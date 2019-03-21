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
import ipaddress
import ctypes

import jail

jail_command = "/usr/sbin/jail"
jls_command = "/usr/sbin/jls"
jexec_command = "/usr/sbin/jexec"
ifconfig_command = "/sbin/ifconfig"


def test_jail_create() -> None:
    jiov = jail.Jiov(dict(persist=None, path="/rescue"))
    jid = jail.dll.jail_set(jiov.pointer, len(jiov), 1)
    try:
        assert isinstance(jid, int)
        assert jid > 0
    finally:
        subprocess.check_output([jail_command, "-r", str(jid)])

def test_jail_remove() -> None:
    jid = 2861
    subprocess.check_output(
        [jail_command, "-c", "persist", f"jid={jid}", "path=/rescue"]
    )
    try:
        jail.dll.jail_remove(jid)
        while jail.is_jid_dying(jid) is True:
            continue
    except:
        subprocess.check_output([jail_command, "-r", str(jid)])
        raise

    with pytest.raises(subprocess.CalledProcessError) as excinfo:
        subprocess.check_output([jls_command, "-j", str(jid)])

def test_jid_lookup() -> None:
    name = "test-jid-lookup"
    assert jail.get_jid_by_name(name) == -1
    subprocess.check_output(
        [jail_command, "-c", "persist", f"name={name}", "path=/rescue"]
    )
    jid = jail.get_jid_by_name(name)
    assert isinstance(jid, int)
    assert jid > 0
    subprocess.check_output([jail_command, "-r", name])

def test_configure_ipv4_addresses_for_non_vnet_jail(
    ipv4_address: ipaddress.IPv4Address,
    bridge_interface: str
) -> None:
    subprocess.check_output(
        [ifconfig_command, bridge_interface, "inet", str(ipv4_address)]
    )
    jiov = jail.Jiov({
        "persist": None,
        "path": "/rescue",
        "ip4.addr": [ipv4_address]
    })
    jid = jail.dll.jail_set(jiov.pointer, len(jiov), 1)
    try:
        assert isinstance(jid, int)
        assert jid > 0

        assert str(ipv4_address) in subprocess.check_output(
            [jexec_command, str(jid), "/ifconfig", bridge_interface]
        ).decode("UTF-8")
    finally:
        subprocess.check_output([jail_command, "-r", str(jid)])


def test_configure_ipv6_addresses_for_non_vnet_jail(
    ipv6_address: ipaddress.IPv6Address,
    bridge_interface: str
) -> None:
    subprocess.check_output(
        [ifconfig_command, bridge_interface, "inet6", "add", str(ipv6_address)]
    )
    jiov = jail.Jiov({
        "persist": None,
        "path": "/rescue",
        "ip6.addr": [ipv6_address]
    })
    jid = jail.dll.jail_set(jiov.pointer, len(jiov), 1)

    try:
        assert isinstance(jid, int)
        assert jid > 0

        assert str(ipv6_address) in subprocess.check_output(
            [jexec_command, str(jid), "/ifconfig", bridge_interface]
        ).decode("UTF-8")
    finally:
        if jid > 0:
            subprocess.check_output([jail_command, "-r", str(jid)])
