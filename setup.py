#!/usr/bin/env python
# -*- coding: utf-8 -*-
import typing
import os
import os.path
import sys
from setuptools import find_packages, setup
try:
    from pip._internal.req import parse_requirements
except ModuleNotFoundError:
    from pip.req import parse_requirements

cwd = os.getcwd()

about = {}
with open(os.path.join(cwd, "jail", "__version__.py"), encoding="utf-8") as f:
    VERSION = exec(f.read(), about)

with open(os.path.join(cwd, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

setup(
	name="jail",
	version=about["__version__"],
	description="Native FreeBSD jail bindings with libc.",
	long_description=long_description,
	long_description_content_type="text/markdown",
	url="https://github.com/gronke/py-jail",
	author="Stefan Grönke",
	author_email="stefan@gronke.net",
	python_requires=">=3.6",
	install_requires=[
		"freebsd-sysctl==0.0.7"
	],
	tests_require=["pytest", "pytest-runner", "pytest-benchmark"],
	packages=find_packages(exclude=("tests",))
)
