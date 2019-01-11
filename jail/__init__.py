import typing
import ctypes
from jail.libc import dll

in_addr_t = ctypes.c_uint32


class in_addr(ctypes.Structure):
    _fields_ = [('s_addr', in_addr_t)]


class in6_addr_U(ctypes.Union):
    _fields_ = [
        ('__u6_addr8', ctypes.c_uint8 * 16),
        ('__u6_addr16', ctypes.c_uint16 * 8),
        ('__u6_addr32', ctypes.c_uint32 * 4),
    ]


class in6_addr(ctypes.Structure):
    _fields_ = [
        ('__in6_u', in6_addr_U),
    ]


class Iovec(ctypes.Structure):
    _fields_ = [
        ("iov_base", ctypes.c_void_p),
        ("iov_size", ctypes.c_size_t)
    ]


class Jiov:
    
    params: typing.Tuple[typing.Tuple[
        bytes,
        typing.Union[bytes, int, typing.Any]
    ], ...]
    
    def __init__(
        self,
        params: typing.Tuple[typing.Tuple[
            bytes,
            typing.Union[bytes, int, typing.Any]
        ], ...]
    ) -> None:
        self.params = params
        self.errmsg = ctypes.create_string_buffer(256)

    def __len__(self) -> int:
        return len(self.params)*2 + 2

    @property
    def pointer(self):
        return ctypes.POINTER(Iovec*len(self))(self.struct)

    @property
    def struct(self) -> typing.Iterator[Iovec]:
        params = self.params
        items = ()
        for i in range(len(params)):
            
            # key
            base = ctypes.c_char_p(params[i][0])
            items += (Iovec(
                ctypes.cast(base, ctypes.c_void_p),
                len(params[i][0])
            ),)

            # XXX: Check the type of the `security.jail.param.$key`
            # sysctl and verify that the value is of the correct
            # type
            
            # value
            if isinstance(params[i][1], bytes):
                # XXX: Read the `security.jail.param.$key` sysctl, parse it as
                # an integer and check that the value length does not exceed
                # that. Find out if terminating NUL-byte is included?.
                base = ctypes.c_char_p(params[i][1])
                items += (Iovec(
                    ctypes.cast(base, ctypes.c_void_p),
                    len(params[i][1])
                ),)
            elif isinstance(params[i][1], int):
                MAX_INT = 2**(8*ctypes.sizeof(ctypes.c_int)) // 2 - 1
                MIN_INT = - 2**(8*ctypes.sizeof(ctypes.c_int)) // 2
                if not MIN_INT <= params[i][1] <= MAX_INT:
                    raise OverflowError("Integer parameter out of range")

                base = ctypes.POINTER(ctypes.c_int)(ctypes.c_int(params[i][1]))
                items += (Iovec(
                    ctypes.cast(base, ctypes.c_void_p),
                    ctypes.sizeof(ctypes.c_int)
                ),)
            elif params[i][1] is None:
                # XXX: sysctl type is int, even though this is NoneType.
                # Type safety is hard.
                items += (Iovec(ctypes.c_void_p(), 0),)
            else:
                # XXX: IP Addrs, JailSys Enums (new, inherit, disabled)
                raise NotImplemented
        
        items += (
            Iovec(
                ctypes.cast(ctypes.c_char_p(b"errmsg\x00"), ctypes.c_void_p),
                len(b"errmsg\x00")
            ),
            Iovec(
                ctypes.cast(ctypes.POINTER(ctypes.c_char_p)(self.errmsg),
                    ctypes.c_void_p),
                len(self.errmsg)
            ),
        )

        return (Iovec * len(items))(*items)
