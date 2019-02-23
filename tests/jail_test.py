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
import os.path
import pytest
import subprocess
import sys

import jail

jail_command = "/usr/sbin/jail"
jls_command = "/usr/sbin/jls"


def test_jail_create():
    jiov = jail.Jiov(dict(persist=None, path="/rescue"))
    jid = jail.dll.jail_set(jiov.pointer, len(jiov), 1)
    try:
        assert isinstance(jid, int)
        assert jid > 0
    finally:
        subprocess.check_output([jail_command, "-r", str(jid)])

def test_jail_remove():
    jid = 2861
    subprocess.check_output(
        [jail_command, "-c", "persist", f"jid={jid}", "path=/rescue"]
    )
    try:
        jail.dll.jail_remove(jid)
    except:
        subprocess.check_output([jail_command, "-r", str(jid)])
        raise

    with pytest.raises(subprocess.CalledProcessError) as excinfo:
        subprocess.check_output([jls_command, "-j", str(jid)])

def test_jid_lookup():
    name = "test-jid-lookup"
    assert jail.get_jid_by_name(name) == -1
    subprocess.check_output(
        [jail_command, "-c", "persist", f"name={name}", "path=/rescue"]
    )
    jid = jail.get_jid_by_name(name)
    assert isinstance(jid, int)
    assert jid > 0
    subprocess.check_output([jail_command, "-r", name])

