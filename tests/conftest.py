import pytest
import pytest_benchmark

import subprocess
import random
import ipaddress

ifconfig_command = "/sbin/ifconfig"


@pytest.fixture(scope="function")
def ipv4_address() -> ipaddress.IPv4Address:
	return ipaddress.IPv4Address("192.0.2." + str(random.randint(1,254)))


@pytest.fixture(scope="function")
def ipv6_address() -> ipaddress.IPv4Address:
	ipv6_suffix = '{:x}'.format(random.randint(1,0xFFFF))
	return ipaddress.IPv6Address("2001:db8:10c::" + ipv6_suffix)


@pytest.fixture(scope="function")
def bridge_interface(ipv4_address: ipaddress.IPv4Address) -> str:
    bridge = subprocess.check_output(
        [ifconfig_command, "bridge", "create"]
    ).decode("UTF-8").strip()
    yield bridge
    subprocess.check_output(
        [ifconfig_command, bridge, "destroy"]
    )
