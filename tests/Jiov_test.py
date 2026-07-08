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
import ctypes
import gc
import os.path
import pytest
import subprocess
import sys

import jail


def test_jiov_length():
    data = dict(persist=None, path="/rescue")
    jiov = jail.Jiov(data)

    print(dict(jiov.items()))

    data_length = len(data)
    assert len(dict(jiov.items())) == data_length
    assert len(list(jiov.keys())) == data_length
    assert len(list(jiov.values())) == data_length

    struct_length = (len(data) + 1) * 2  # (data + errmsg) key/value pairs
    assert len(jiov.struct) == struct_length
    assert len(jiov) == struct_length


def test_jiov_buffers_survive_garbage_collection():
    jiov = jail.Jiov(dict(name="keepalive", jid=23, persist=None))
    pointer = jiov.pointer

    gc.collect()
    # allocations of every small size class, so freed blocks get reused
    churn = [b"\xff" * (1 + i % 64) for i in range(8192)]

    entries = pointer.contents
    assert len(entries) == len(jiov)
    assert ctypes.string_at(entries[0].iov_base, entries[0].iov_size) \
        == b"name\x00"
    assert ctypes.string_at(entries[1].iov_base, entries[1].iov_size) \
        == b"keepalive\x00"
    assert ctypes.string_at(entries[2].iov_base, entries[2].iov_size) \
        == b"jid\x00"
    assert ctypes.c_int.from_address(entries[3].iov_base).value == 23
    assert ctypes.string_at(entries[4].iov_base, entries[4].iov_size) \
        == b"persist\x00"
    assert entries[5].iov_base is None
    assert ctypes.string_at(entries[6].iov_base, entries[6].iov_size) \
        == b"errmsg\x00"
    assert entries[7].iov_size == 256

    assert len(churn) == 8192


def test_jail_flag_constants():
    assert jail.JAIL_CREATE == 0x01
    assert jail.JAIL_UPDATE == 0x02
    assert jail.JAIL_ATTACH == 0x04
    assert jail.JAIL_DYING == 0x08
