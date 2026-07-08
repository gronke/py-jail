# Copyright (c) 2020, Stefan Grönke
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
"""libc abstraction."""
import ctypes
import typing

try:
    dll = ctypes.CDLL("libc.so.7", use_errno=True)
except OSError:
    import ctypes.util
    dll = ctypes.CDLL(str(ctypes.util.find_library("c")), use_errno=True)

_ARGTYPES = {
    "jail_get": [ctypes.c_void_p, ctypes.c_uint, ctypes.c_int],
    "jail_set": [ctypes.c_void_p, ctypes.c_uint, ctypes.c_int],
    "jail_attach": [ctypes.c_int],
    "jail_remove": [ctypes.c_int]
}
_prototypes: typing.Dict[str, typing.Any] = {}


def _jail_func(name: str) -> typing.Any:
    # the jail(2) family only exists in FreeBSD's libc, so each symbol is
    # resolved on first use to keep the module importable on other platforms
    prototype = _prototypes.get(name)
    if prototype is None:
        prototype = getattr(dll, name)
        prototype.argtypes = _ARGTYPES[name]
        prototype.restype = ctypes.c_int
        _prototypes[name] = prototype
    return prototype


def jail_get(iov: typing.Any, niov: int, flags: int) -> int:
    return int(_jail_func("jail_get")(iov, niov, flags))


def jail_set(iov: typing.Any, niov: int, flags: int) -> int:
    return int(_jail_func("jail_set")(iov, niov, flags))


def jail_attach(jid: int) -> int:
    return int(_jail_func("jail_attach")(jid))


def jail_remove(jid: int) -> int:
    return int(_jail_func("jail_remove")(jid))
