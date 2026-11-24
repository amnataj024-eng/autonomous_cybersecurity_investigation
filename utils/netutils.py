"""Small network helpers shared by the agents."""

from __future__ import annotations

import ipaddress

# Python's ``is_private`` also treats the documentation ranges (192.0.2.0/24,
# 198.51.100.0/24, 203.0.113.0/24) as private. Those ranges are used for the SYNTHETIC
# "external" addresses in the demo data, so we use an explicit internal-network list.
INTERNAL_NETWORKS = [
    ipaddress.ip_network(cidr)
    for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16")
]


def is_internal_ip(ip: str) -> bool:
    """True for RFC 1918 / loopback / link-local addresses and for blank or malformed values."""
    try:
        address = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return True  # blank / malformed values are never treated as external
    return any(address in network for network in INTERNAL_NETWORKS)
