## 0.11.0 - 2020-04-23

### Added

- [This changelog!](https://github.com/gronke/py-jail/pull/5)
- [Released as Port](), this means it can now be installed vith `pkg`
- [Test automation on Travis and Cirrus CI](https://github.com/gronke/py-jail/pull/4)

### Changed

- update our direct dependency `py-freebsd_sysctl`.
- [speedup loading of C library](https://github.com/gronke/py-jail/pull/3)

### Fixed

- Packaging was broken because we relied on `requirments.txt` but didn't include it in our `MANIFEST.in`
