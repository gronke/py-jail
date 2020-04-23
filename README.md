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

## Development

### Unit Tests

Unit tests may run on FreeBSD or HardenedBSD.

### Static Code Analysis

The project enforces PEP-8 code style and MyPy strong typing via flake8, that is required to pass before merging any changes.
Together with Bandit checks for common security issues the static code analysis can be ran on Linux and BSD code execution.

```
make install-dev
make check
```

### Releases

We try to *manually* keep a [Changelog](CHANGELOG.md), following the style on [changelog.md](https://changelog.md).
New releases are tagged according to [Semver](https://semver.org/), released on [PyPi](https://pypi.org/project/libioc/), and published as [port](https://github.com/bsdci/ports).

To get a port published, we need to [create a Bugzilla Issue in the Ports category](https://bugs.freebsd.org/bugzilla/enter_bug.cgi?component=Individual%20Port%28s%29&product=Ports%20%26%20Packages)
