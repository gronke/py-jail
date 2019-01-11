import ctypes.util
clib = ctypes.util.find_library("c")
dll = ctypes.CDLL(clib)