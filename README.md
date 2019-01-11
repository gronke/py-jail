py-jail
=======

A native Python wrapper for FreeBSD jails using libc.


```python
>>> import jail
>>> jiov = jail.Jiov(((b"jid\x00", 42), (b"path\x00", b"/rescue/\x00"), (b"persist\x00", None)))
>>> jail.dll.jail_set(jiov.pointer, len(jiov), 1)
42
>>> 

```
