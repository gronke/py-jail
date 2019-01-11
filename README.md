py-jail
=======

A native Python wrapper for FreeBSD jails using libc.

## Usage

### jail_set

```python
>>> import jail
>>> jiov = jail.Jiov(dict(persist=None, jid=23, path="/rescue"))
>>> jail.dll.jail_set(jiov.pointer, len(jiov), 1)
23
```

### jail_remove

```python
>>> import jail
>>> jiov = jail.Jiov(dict(persist=None, jid=23, path="/rescue"))
>>> jail.dll.jail_remove(23)
-1
>>> jail.dll.jail_set(jiov.pointer, len(jiov), 1)
23
>>> jail.dll.jail_set(jiov.pointer, len(jiov), 1)
-1
>>> jiov.errmsg.value
b'jail 23 already exists'
>>> jail.dll.jail_remove(23)
0
>>> jail.dll.jail_set(jiov.pointer, len(jiov), 1)
23
```