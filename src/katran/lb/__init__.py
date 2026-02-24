"""Load balancer logic module."""

from katran.lb.maglev import (
    Endpoint,
    MaglevHashRing,
    compute_ring_changes,
    hash_endpoint_address,
    murmur_hash3_x64_64,
)
from katran.lb.real_manager import RealManager
from katran.lb.vip_manager import VipManager

__all__ = [
    # Consistent hashing
    "MaglevHashRing",
    "Endpoint",
    "hash_endpoint_address",
    "compute_ring_changes",
    "murmur_hash3_x64_64",
    # VIP and backend management
    "VipManager",
    "RealManager",
]
