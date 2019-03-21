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

## Parameters

### Networking

Non-VNET jails accept `ip.addr` and `ip6.addr` params.
Those can be defined from Python [ipaddress.IPv4Address](https://docs.python.org/3/library/ipaddress.html#ipaddress.IPv4Address) and [ipaddress.IPv6Address](https://docs.python.org/3/library/ipaddress.html#ipaddress.IPv6Address).

```sh
ifconfig bridge create inet 192.168.1.42/24 inet6 add 2001:db8:10C::42/64
```

```python
import ipaddress
import jail

jiov = jail.Jiov({
	"persist": None,
	"jid": 23,
	"path": "/rescue",
	"ip4.addr": ipaddress.IPv4Address("192.168.1.42")
	"ip6.addr": ipaddress.IPv6Address("2001:db8:10C::42")
})

jail.dll.jail_set(jiov.pointer, len(jiov), 1)
```