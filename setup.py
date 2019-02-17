#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import os.path
import sys
from setuptools import find_packages, setup

cwd = os.getcwd()

about = {}
with open(os.path.join(cwd, "jail", "__version__.py")) as f:
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
	setup_requires=["pytest-runner"],
	tests_require=["pytest"],
	packages=find_packages(exclude=("tests",))
)
