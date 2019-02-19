# Copyright (c) 2019, Stefan Grönke
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted providing that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
"""FreeBSD jail sysctl bindings."""
import typing
import ctypes
import itertools

import freebsd_sysctl
import freebsd_sysctl.types

from jail.libc import dll
import jail.types

NULL_BYTES = b"\x00"


class Iovec(ctypes.Structure):
    _fields_ = [
        ("iov_base", ctypes.c_void_p),
        ("iov_size", ctypes.c_size_t)
    ]


class IovecKey:

    def __init__(self, value: typing.Union[str, bytes]) -> None:
        if isinstance(value, bytes) is True:
            self.value = value
        elif isinstance(value, str) is True:
            self.value = value.encode()
        else:
            raise KeyError(
                f"bytes or string expected, but got: {type(value).__name__}"
            )

    def __repr__(self) -> str:
        return self.__str__();
        #return f"<{self.__class__.__name__}: \"{str(self)}\">"

    def __str__(self) -> str:
        return self.value.decode()

    def __bytes__(self) -> bytes:
        return self.value

    def __len__(self) -> int:
        return len(self.value)

    def __hash__(self) -> int:
        return hash(self.value)

    @property
    def iovec(self) -> ctypes.c_void_p:
        return (Iovec(
            ctypes.cast(
                ctypes.c_char_p(bytes(self) + NULL_BYTES),
                ctypes.c_void_p
            ),
            len(self) + len(NULL_BYTES)
        ))


class IovecValue:

    _value: typing.Optional[typing.Union[bytes, int]]

    def __init__(
        self,
        value: typing.Optional[typing.Union[bytes, int, str]]
    ) -> None:
        self.value = value

    @property
    def value(self) -> typing.Optional[typing.Union[bytes, int]]:
        value = self._value
        if isinstance(value, int) or (value is None):
            return value
        return value + (NULL_BYTES * (value[-1:] == NULL_BYTES))

    @property
    def raw_value(self) -> typing.Optional[typing.Union[bytes, int]]:
        return self._value

    @value.setter
    def value(self, value: typing.Optional[typing.Union[bytes, int]]) -> None:
        if value is None:
            self._value = None
        elif isinstance(value, str):
            self._value = value.encode()
        elif isinstance(value, int):
            self._value = int(value)
        elif isinstance(value, bytes):
            self._value = value
        else:
            raise TypeError("IovecValue accepts bytes, int, str or None")

    def __repr__(self) -> str:
        return self.__str__();
        #return f"<{self.__class__.__name__}: \"{str(self)}\">"

    def __len__(self) -> int:
        if self.value is None:
            return 0
        elif isinstance(self.value, int):
            return ctypes.sizeof(ctypes.c_int)
        return len(self.value)

    def __str__(self) -> str:
        if isinstance(self.value, bytes) is True:
            return self.value.decode()
        else:
            return str(self.value)

    @property
    def iovec(self) -> typing.Union[ctypes.POINTER, int]:

        if self.value is None:
            return Iovec(ctypes.c_void_p(), 0)

        elif isinstance(self.value, bytes) is True:
            return Iovec(
                ctypes.cast(
                    ctypes.c_char_p(self.value + NULL_BYTES),
                    ctypes.c_void_p
                ),
                self.__len__() + len(NULL_BYTES)
            )

        elif isinstance(self.value, int) is True:
            if not jail.types.MIN_INT <= self.value <= jail.types.MAX_INT:
                raise OverflowError("Integer parameter out of range")
            return Iovec(
                ctypes.cast(
                    ctypes.POINTER(ctypes.c_int)(ctypes.c_int(self.value)),
                    ctypes.c_void_p
                ),
                self.__len__()
            )

        else:
            # XXX: IP Addrs, JailSys Enums (new, inherit, disabled)
            raise NotImplementedError


class ByteDict(dict):
    """A dict with bytes as keys."""

    def __init__(
        self,
        data: typing.Dict[
            typing.Union[bytes, str],
            IovecValue
        ]={}
    ) -> None:
        super().__init__(data)

    def __setitem__(
        self,
        key: typing.Union[bytes, str],
        value: IovecValue
    ) -> None:
        if isinstance(value, IovecValue) is False:
            raise TypeError("IovecValue expected")

        # XXX: cache sysctls
        sysctl = freebsd_sysctl.Sysctl(self._getkey(key).decode())

        if sysctl.ctl_type == freebsd_sysctl.types.STRING:
            if isinstance(value.value, bytes) is False:
                raise TypeError("IovecValue of bytes expected")

            max_size = int(sysctl.value)
            if len(value.value) > max_size:
                raise ValueError("byte sequence too long")

        super().__setitem__(self.__getkey(key), value)

    def __getitem__(
        self,
        key: typing.Union[bytes, str]
    ) -> IovecValue:
        return super().__getitem__(self.__getkey(key))

    def _getkey(self, key: typing.Union[bytes, str]) -> bytes:
        if isinstance(key, bytes) is False:
            return key
        elif isinstance(key, str) is True:
            return key.encode()
        raise KeyError("string or bytes expected")


class JiovData(dict):
    """Jiov data storage and wrapper."""

    def __init__(
        self,
        data: typing.Dict[
            typing.Union[IovecKey, bytes, str],
            IovecValue
        ]
    ) -> None:
        super().__init__()
        for key, value in data.items():
            self[key] = data[key]

    def __setitem__(
        self,
        key: typing.Union[IovecKey, bytes, str],
        value: typing.Optional[typing.Union[bytes, int, IovecValue]]
    ) -> None:
        super().__setitem__(IovecKey(key), IovecValue(value))

    def __getitem__(
        self,
        key: typing.Union[IovecKey, bytes, str]
    ) -> IovecValue:
        return super().__getitem__(
            (key if isinstance(key, IovecKey) else IovecKey(key))
        )

    def keys(self) -> typing.KeysView[IovecKey]:
        return typing.cast(
            typing.KeysView[IovecKey],
            (self._getkey(x) for x in super().keys())
        )

    def items(self) -> typing.ItemsView[IovecKey, IovecValue]:
        return typing.cast(
            typing.ItemsView[IovecKey, IovecValue],
            ((x, self[x]) for x in self.keys())
        )

    def _getkey(self, key: typing.Union[IovecKey, bytes, str]) -> bytes:
        if isinstance(key, IovecKey) is True:
            return key
        return IovecKey(super()._getkey(key))


class Jiov(JiovData):

    errmsg: ctypes.c_char*256
    
    def __init__(
        self,
        params: typing.Dict[
            typing.Union[str, bytes],
            IovecValue
        ]
    ) -> None:
        self.errmsg = ctypes.create_string_buffer(256)
        super().__init__(params)

    def __len__(self) -> int:
        return (dict.__len__(self) * 2) + 2

    @property
    def pointer(self):
        return ctypes.POINTER(Iovec*len(self))(self.struct)

    @property
    def struct(self) -> typing.Iterator[Iovec]:
        items = []
        for key, value in self.items():
            items.append(key.iovec)
            items.append(value.iovec)

        items.append(
            Iovec(
                ctypes.cast(
                    ctypes.c_char_p(b"errmsg\x00"),
                    ctypes.c_void_p
                ),
                len(b"errmsg\x00")
            )
        )
        
        items.append(
            Iovec(
                ctypes.cast(
                    ctypes.POINTER(ctypes.c_char_p)(self.errmsg),
                    ctypes.c_void_p
                ),
                len(self.errmsg)
            )
        )

        return (Iovec * len(items))(*items)


def get_jid_by_name(name: typing.Union[str, bytes]) -> int:
    if (isinstance(name, str) or isinstance(name, bytes)) is False:
        raise TypeError("bytes required")

    jiov = jail.Jiov(dict(name=name))
    return int(jail.dll.jail_get(jiov.pointer, len(jiov), 0))
