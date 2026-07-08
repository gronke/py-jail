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
import errno
import itertools
import ipaddress
import os

import freebsd_sysctl
import freebsd_sysctl.types

from jail.__version__ import __version__
from jail.libc import dll
import jail.libc
import jail.types

NULL_BYTES = b"\x00"
_JAIL_MAX_AF_IPS: typing.Optional[int] = None


def _jail_max_af_ips() -> int:
    global _JAIL_MAX_AF_IPS
    if _JAIL_MAX_AF_IPS is None:
        _JAIL_MAX_AF_IPS = int(
            freebsd_sysctl.Sysctl("security.jail.jail_max_af_ips").value
        )
    return _JAIL_MAX_AF_IPS


def __getattr__(name: str) -> typing.Any:
    # JAIL_MAX_AF_IPS reads a sysctl, so it resolves on first access to
    # keep the module importable on other platforms
    if name == "JAIL_MAX_AF_IPS":
        return _jail_max_af_ips()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


JAIL_CREATE = 0x01
JAIL_UPDATE = 0x02
JAIL_ATTACH = 0x04
JAIL_DYING = 0x08


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
        self._iovec_buffer: typing.Optional[ctypes.Array] = None

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

    def __eq__(self, other: 'IovecKey') -> bool:
        return self.__hash__() == other.__hash__()

    @property
    def iovec(self) -> Iovec:
        # the kernel dereferences iov_base after this property returns,
        # so the key owns its backing buffer for its whole lifetime
        if self._iovec_buffer is None:
            data = bytes(self) + NULL_BYTES
            self._iovec_buffer = ctypes.create_string_buffer(data, len(data))
        return Iovec(
            ctypes.c_void_p(ctypes.addressof(self._iovec_buffer)),
            len(self._iovec_buffer)
        )


RawIovecValue = typing.Optional[typing.Union[
    bytes,
    int,
    typing.List[ipaddress.IPv4Address],
    typing.List[ipaddress.IPv6Address]
]]
IovevValueInput = typing.Union[RawIovecValue, str]
IovecValueOutput = typing.Union[
    bytes,
    int,
    jail.types.in_addr,
    jail.types.in6_addr
]


class IovecValue:

    _value: RawIovecValue
    _iovec_buffer: typing.Any

    def __init__(
        self,
        value: IovevValueInput
    ) -> None:
        self.value = value

    @property
    def value(self) -> RawIovecValue:
        value = self._value
        if isinstance(value, list):
            if len(value) == 0:
                return None
            elif len(value) > _jail_max_af_ips():
                raise ValueError("Too many IPs (max {JAIL_MAX_AF_IPS}")
            elif isinstance(value[0], ipaddress.IPv4Address):
                list_type = jail.types.in_addr
                value_type = int
            elif isinstance(value[0], ipaddress.IPv6Address):
                list_type = jail.types.in6_addr
                value_type = jail.types.in6_addr_U_from_ip
            else:
                raise TypeError("Expected IP Address")
            output_type = list_type * len(value)
            return output_type(*[list_type(value_type(x)) for x in value])
        elif isinstance(value, int) or (value is None):
            return value
        return value + (NULL_BYTES * (value[-1:] == NULL_BYTES))

    @property
    def raw_value(self) -> RawIovecValue:
        return self._value

    @value.setter
    def value(self, value: RawIovecValue) -> None:
        self._iovec_buffer = None
        if isinstance(value, list):
            self._value = value
        else:
            self._value = self.__convert_value(value)

    @staticmethod
    def __convert_value(value: IovevValueInput) -> RawIovecValue:
        if value is None:
            return None
        elif isinstance(value, str):
            return value.encode()
        elif isinstance(value, int):
            return int(value)
        elif isinstance(value, bytes):
            return value
        else:
            raise TypeError("IovecValue accepts list, bytes, int, str or None")

    def __repr__(self) -> str:
        return self.__str__();
        #return f"<{self.__class__.__name__}: \"{str(self)}\">"

    def __len__(self) -> int:
        value = self.value
        if value is None:
            return 0
        elif isinstance(value, int):
            return ctypes.sizeof(ctypes.c_int)
        return len(value)

    def __str__(self) -> str:
        if isinstance(self.value, bytes) is True:
            return self.value.decode()
        else:
            return str(self.value)

    def __int__(self) -> int:
        if isinstance(self.value, int) is True:
            return int(self.value)
        raise ValueError("cannot convert value to int")

    @property
    def iovec(self) -> Iovec:
        # the kernel dereferences iov_base after this property returns,
        # so the value owns its backing buffer for its whole lifetime
        value = self.value

        if value is None:
            return Iovec(ctypes.c_void_p(), 0)

        if self._iovec_buffer is None:
            if isinstance(value, bytes) is True:
                data = value + NULL_BYTES
                self._iovec_buffer = ctypes.create_string_buffer(
                    data,
                    len(data)
                )
            elif isinstance(value, int) is True:
                if not jail.types.MIN_INT <= value <= jail.types.MAX_INT:
                    raise OverflowError("Integer parameter out of range")
                self._iovec_buffer = ctypes.c_int(value)
            elif isinstance(self._value, list) is True:
                self._iovec_buffer = value
            else:
                # XXX: IP Addrs, JailSys Enums (new, inherit, disabled)
                raise NotImplementedError

        return Iovec(
            ctypes.c_void_p(ctypes.addressof(self._iovec_buffer)),
            ctypes.sizeof(self._iovec_buffer)
        )


class ByteDict(dict):
    """A dict with bytes as keys."""

    cached_sysctls: typing.Dict[str, freebsd_sysctl.Sysctl] = {}

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

        sysctl = self.__get_sysctl(key)

        if sysctl.ctl_type == freebsd_sysctl.types.STRING:
            if isinstance(value.value, bytes) is False:
                raise TypeError("IovecValue of bytes expected")

            max_size = int(sysctl.value)
            if len(value.value) > max_size:
                raise ValueError("byte sequence too long")

        super().__setitem__(self.__getkey(key), value)

    def __get_sysctl(self, key: str) -> freebsd_sysctl.Sysctl:
        _key = self.__getkey(key).decode("UTF-8")
        if _key not in self.cached_sysctls.keys():
            self.cached_sysctls[_key] = freebsd_sysctl.Sysctl(_key)
        return self.cached_sysctls[_key]

    def __getitem__(
        self,
        key: typing.Union[bytes, str]
    ) -> IovecValue:
        return super().__getitem__(self.__getkey(key))

    def __getkey(self, key: typing.Union[bytes, str]) -> bytes:
        if isinstance(key, bytes) is False:
            return key
        elif isinstance(key, str) is True:
            return key.encode("UTF-8")
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
            (self.__getkey(x) for x in super().keys())
        )

    def items(self) -> typing.ItemsView[IovecKey, IovecValue]:
        return typing.cast(
            typing.ItemsView[IovecKey, IovecValue],
            ((x, self[x]) for x in self.keys())
        )

    def __getkey(self, key: typing.Union[IovecKey, bytes, str]) -> bytes:
        if isinstance(key, IovecKey) is True:
            return key
        return IovecKey(super().__getkey(key))


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
        self._errmsg_key = ctypes.create_string_buffer(b"errmsg")
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
                ctypes.c_void_p(ctypes.addressof(self._errmsg_key)),
                len(self._errmsg_key)
            )
        )

        items.append(
            Iovec(
                ctypes.c_void_p(ctypes.addressof(self.errmsg)),
                len(self.errmsg)
            )
        )

        return (Iovec * len(items))(*items)


def _raise_jail_error(jiov: Jiov) -> typing.NoReturn:
    code = ctypes.get_errno()
    errmsg = jiov.errmsg.value.decode("UTF-8", "replace")
    raise OSError(code, errmsg if errmsg else os.strerror(code))


def jail_set(jiov: Jiov, flags: int = JAIL_CREATE) -> int:
    """Create or update a jail and return its jid."""
    jid = jail.libc.jail_set(jiov.pointer, len(jiov), flags)
    if jid < 0:
        _raise_jail_error(jiov)
    return jid


def jail_get(jiov: Jiov, flags: int = 0) -> int:
    """Read the parameters of a jail into the Jiov and return its jid."""
    jid = jail.libc.jail_get(jiov.pointer, len(jiov), flags)
    if jid < 0:
        _raise_jail_error(jiov)
    return jid


def jail_attach(jid: int) -> None:
    """Imprison the current process into the jail."""
    if jail.libc.jail_attach(jid) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


def jail_remove(jid: int) -> None:
    """Remove the jail, killing all processes in it."""
    if jail.libc.jail_remove(jid) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


def get_jid_by_name(name: typing.Union[str, bytes]) -> int:
    if (isinstance(name, str) or isinstance(name, bytes)) is False:
        raise TypeError("bytes required")

    jiov = jail.Jiov(dict(name=name))
    try:
        return jail_get(jiov)
    except OSError as err:
        if err.errno == errno.ENOENT:
            return -1
        raise

def is_jid_dying(jid: int) -> bool:
    jiov = jail.Jiov(dict(jid=jid,dying=0))
    try:
        jail_get(jiov, JAIL_DYING)
    except OSError as err:
        if err.errno == errno.ENOENT:
            return False  # jid does not exist
        raise
    return (int(jiov[IovecKey("dying")]) > 0) is True

