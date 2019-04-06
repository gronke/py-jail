# Copyright (c) 2019, Stefan Grönke
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted providing that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
import pytest
import ipaddress

import jail


def test_IovecValue_can_be_string():

    iovec_value = jail.IovecValue("string input value 123")
    assert isinstance(iovec_value.raw_value, bytes)
    assert iovec_value.raw_value == b"string input value 123"


def test_IovecValue_can_be_bytes():

    test_value = b"This is a bunch of bytes"
    iovec_value = jail.IovecValue(test_value)
    assert isinstance(iovec_value.raw_value, bytes)
    assert iovec_value.raw_value == test_value


def test_IovecValue_can_be_integer():

    test_value = 23
    iovec_value = jail.IovecValue(test_value)
    assert isinstance(iovec_value.raw_value, int)
    assert iovec_value.raw_value == 23


def test_IovecValue_can_be_list_of_ips():

    test_value = [ipaddress.IPv4Address("192.168.23.10")]
    iovec_value = jail.IovecValue(test_value)
    assert len(iovec_value.raw_value) == 1
    assert isinstance(iovec_value.raw_value[0], ipaddress.IPv4Address)