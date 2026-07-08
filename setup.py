#!/usr/bin/env python
# -*- coding: utf-8 -*-
from setuptools import setup

about = {}
with open("jail/__version__.py", encoding="utf-8") as f:
    exec(f.read(), about)

setup(version=about["__version__"])
