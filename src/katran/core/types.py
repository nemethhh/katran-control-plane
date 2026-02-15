"""
Core data structures matching Katran BPF map layouts.

These structures must stay synchronized with:
- katran/lib/bpf/balancer_structs.h
- katran/lib/BalancerStructs.h

All structures implement to_bytes() and from_bytes() methods for
serialization/deserialization to/from BPF map format.

Memory Layout Notes:
- IPv4 addresses: 4 bytes (__be32) stored in network byte order
- IPv6 addresses: 16 bytes (4 x __be32) stored in network byte order
- Ports: 2 bytes (__u16) stored in network byte order in BPF maps
- Protocols: 1 byte (__u8)
- Statistics: 8 bytes (__u64) per counter
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Union

from katran.core.constants import (
    Protocol,
    VipFlags,
    RealFlags,
)
from katran.core.exceptions import SerializationError


# Type alias for IP addresses
IpAddress = Union[IPv4Address, IPv6Address]


def _parse_ip_address(addr: str | IpAddress) -> IpAddress:
    """Parse an IP address string or return existing address object."""
    if isinstance(addr, (IPv4Address, IPv6Address)):
        return addr
    return ip_address(addr)


# =============================================================================
# VIP Key Structure (vip_definition)
# =============================================================================

# BPF struct layout for vip_definition:
# struct vip_definition {
#   union {
#     __be32 vip;           // IPv4 (4 bytes)
#     __be32 vipv6[4];      // IPv6 (16 bytes)
#   };
#   __u16 port;             // 2 bytes
#   __u8 proto;             // 1 byte
# };
#
# IPv4 uses first 4 bytes, remaining 12 bytes are padding
# Total size: 20 bytes (16 + 2 + 1 + 1 padding)

VIP_KEY_SIZE = 20  # Fixed size including padding


@dataclass(frozen=True)
class VipKey:
    """
    Key for vip_map - matches BPF struct vip_definition.

    The VIP address can be either IPv4 or IPv6. When serialized:
    - IPv4: Address in first 4 bytes, remaining 12 bytes zeroed
    - IPv6: Full 16 bytes used

    Attributes:
        address: VIP IP address (IPv4 or IPv6)
        port: VIP port number (1-65535)
        protocol: IP protocol (TCP=6, UDP=17)
    """

    address: IpAddress
    port: int
    protocol: Protocol

    def __post_init__(self) -> None:
        """Validate VIP key fields."""
        if not 0 <= self.port <= 65535:
            raise ValueError(f"Port must be 0-65535, got {self.port}")
        if self.protocol not in (Protocol.TCP, Protocol.UDP):
            raise ValueError(f"Protocol must be TCP or UDP, got {self.protocol}")

    @property
    def is_ipv6(self) -> bool:
        """Check if this VIP uses IPv6."""
        return isinstance(self.address, IPv6Address)

    def to_bytes(self) -> bytes:
        """
        Serialize to BPF map key format.

        Format: [16 bytes address][2 bytes port][1 byte proto][1 byte padding]
        Total: 20 bytes

        IPv4 addresses are stored in the first 4 bytes with 12 bytes of zero padding.
        """
        try:
            # Address (16 bytes)
            if isinstance(self.address, IPv6Address):
                addr_bytes = self.address.packed
            else:
                # IPv4: pad to 16 bytes (address in first 4 bytes)
                addr_bytes = self.address.packed + b"\x00" * 12

            # Port (2 bytes, network byte order — the BPF program copies the
            # raw port from the TCP/UDP header without byte-swap conversion)
            port_bytes = struct.pack("!H", self.port)

            # Protocol (1 byte) + padding (1 byte)
            proto_bytes = struct.pack("BB", self.protocol.value, 0)

            return addr_bytes + port_bytes + proto_bytes

        except Exception as e:
            raise SerializationError("VipKey", "serialize", str(e)) from e

    @classmethod
    def from_bytes(cls, data: bytes) -> VipKey:
        """
        Deserialize from BPF map key format.

        Args:
            data: 20 bytes of serialized VipKey

        Returns:
            VipKey instance
        """
        if len(data) != VIP_KEY_SIZE:
            raise SerializationError(
                "VipKey", "deserialize", f"Expected {VIP_KEY_SIZE} bytes, got {len(data)}"
            )

        try:
            # Check if IPv6 (non-zero bytes after first 4)
            is_ipv6 = any(data[4:16])

            if is_ipv6:
                address = IPv6Address(data[:16])
            else:
                address = IPv4Address(data[:4])

            # Port (2 bytes, network byte order)
            port = struct.unpack("!H", data[16:18])[0]

            # Protocol (1 byte)
            proto = Protocol(data[18])

            return cls(address=address, port=port, protocol=proto)

        except Exception as e:
            raise SerializationError("VipKey", "deserialize", str(e)) from e

    def __str__(self) -> str:
        """Human-readable VIP key representation."""
        return f"{self.address}:{self.port}/{self.protocol.name.lower()}"


# =============================================================================
# VIP Metadata Structure (vip_meta)
# =============================================================================

# BPF struct layout for vip_meta:
# struct vip_meta {
#   __u32 flags;     // 4 bytes
#   __u32 vip_num;   // 4 bytes
# };
# Total size: 8 bytes

VIP_META_SIZE = 8


@dataclass
class VipMeta:
    """
    Value for vip_map - matches BPF struct vip_meta.

    Attributes:
        flags: VIP behavior flags
        vip_num: VIP index number (used to index CH rings and stats)
    """

    flags: VipFlags
    vip_num: int

    def to_bytes(self) -> bytes:
        """Serialize to BPF map value format (8 bytes)."""
        try:
            return struct.pack("<II", self.flags, self.vip_num)
        except Exception as e:
            raise SerializationError("VipMeta", "serialize", str(e)) from e

    @classmethod
    def from_bytes(cls, data: bytes) -> VipMeta:
        """Deserialize from BPF map value format."""
        if len(data) != VIP_META_SIZE:
            raise SerializationError(
                "VipMeta", "deserialize", f"Expected {VIP_META_SIZE} bytes, got {len(data)}"
            )

        try:
            flags_val, vip_num = struct.unpack("<II", data)
            return cls(flags=VipFlags(flags_val), vip_num=vip_num)
        except Exception as e:
            raise SerializationError("VipMeta", "deserialize", str(e)) from e


# =============================================================================
# Real Definition Structure (real_definition)
# =============================================================================

# BPF struct layout for real_definition:
# struct real_definition {
#   union {
#     __be32 dst;           // IPv4 (4 bytes)
#     __be32 dstv6[4];      // IPv6 (16 bytes)
#   };
#   __u8 flags;             // 1 byte
# };
# Total size: 20 bytes (16 + 1 + 3 padding)

REAL_DEFINITION_SIZE = 20


@dataclass
class RealDefinition:
    """
    Backend server definition - matches BPF struct real_definition.

    This is the value stored in the reals array map.

    Attributes:
        address: Backend server IP address
        flags: Backend flags (IPV6, LOCAL_REAL)
    """

    address: IpAddress
    flags: RealFlags = RealFlags.NONE

    def __post_init__(self) -> None:
        """Set IPv6 flag automatically based on address type."""
        if isinstance(self.address, IPv6Address):
            # Ensure IPV6 flag is set
            object.__setattr__(self, "flags", self.flags | RealFlags.IPV6)

    @property
    def is_ipv6(self) -> bool:
        """Check if this backend uses IPv6."""
        return isinstance(self.address, IPv6Address)

    def to_bytes(self) -> bytes:
        """Serialize to BPF map value format (20 bytes)."""
        try:
            # Address (16 bytes)
            if isinstance(self.address, IPv6Address):
                addr_bytes = self.address.packed
            else:
                # IPv4: pad to 16 bytes
                addr_bytes = self.address.packed + b"\x00" * 12

            # Flags (1 byte) + padding (3 bytes)
            flags_bytes = struct.pack("BBBB", self.flags, 0, 0, 0)

            return addr_bytes + flags_bytes

        except Exception as e:
            raise SerializationError("RealDefinition", "serialize", str(e)) from e

    @classmethod
    def from_bytes(cls, data: bytes) -> RealDefinition:
        """Deserialize from BPF map value format."""
        if len(data) != REAL_DEFINITION_SIZE:
            raise SerializationError(
                "RealDefinition",
                "deserialize",
                f"Expected {REAL_DEFINITION_SIZE} bytes, got {len(data)}",
            )

        try:
            flags = RealFlags(data[16])

            if flags & RealFlags.IPV6:
                address = IPv6Address(data[:16])
            else:
                address = IPv4Address(data[:4])

            return cls(address=address, flags=flags)

        except Exception as e:
            raise SerializationError("RealDefinition", "deserialize", str(e)) from e


# =============================================================================
# Flow Key Structure (flow_key)
# =============================================================================

# BPF struct layout for flow_key:
# struct flow_key {
#   union {
#     __be32 src;           // IPv4 source (4 bytes)
#     __be32 srcv6[4];      // IPv6 source (16 bytes)
#   };
#   union {
#     __be32 dst;           // IPv4 dest (4 bytes)
#     __be32 dstv6[4];      // IPv6 dest (16 bytes)
#   };
#   union {
#     __u32 ports;          // Combined ports (4 bytes)
#     __u16 port16[2];      // src_port[0], dst_port[1]
#   };
#   __u8 proto;             // 1 byte
# };
# Total size: 40 bytes (16 + 16 + 4 + 1 + 3 padding)

FLOW_KEY_SIZE = 40


@dataclass(frozen=True)
class FlowKey:
    """
    5-tuple flow key - matches BPF struct flow_key.

    Used as key in LRU maps to cache backend selection decisions.

    Attributes:
        src_addr: Source IP address
        dst_addr: Destination IP address
        src_port: Source port
        dst_port: Destination port
        protocol: IP protocol (TCP=6, UDP=17)
    """

    src_addr: IpAddress
    dst_addr: IpAddress
    src_port: int
    dst_port: int
    protocol: Protocol

    @property
    def is_ipv6(self) -> bool:
        """Check if this flow uses IPv6 addresses."""
        return isinstance(self.src_addr, IPv6Address)

    def to_bytes(self) -> bytes:
        """Serialize to BPF map key format (40 bytes)."""
        try:
            # Source address (16 bytes)
            if isinstance(self.src_addr, IPv6Address):
                src_bytes = self.src_addr.packed
            else:
                src_bytes = self.src_addr.packed + b"\x00" * 12

            # Destination address (16 bytes)
            if isinstance(self.dst_addr, IPv6Address):
                dst_bytes = self.dst_addr.packed
            else:
                dst_bytes = self.dst_addr.packed + b"\x00" * 12

            # Ports (4 bytes) - stored as two u16 in network byte order
            # (BPF copies raw port bytes from packet headers without conversion)
            ports_bytes = struct.pack("!HH", self.src_port, self.dst_port)

            # Protocol (1 byte) + padding (3 bytes)
            proto_bytes = struct.pack("BBBB", self.protocol.value, 0, 0, 0)

            return src_bytes + dst_bytes + ports_bytes + proto_bytes

        except Exception as e:
            raise SerializationError("FlowKey", "serialize", str(e)) from e

    @classmethod
    def from_bytes(cls, data: bytes) -> FlowKey:
        """Deserialize from BPF map key format."""
        if len(data) != FLOW_KEY_SIZE:
            raise SerializationError(
                "FlowKey", "deserialize", f"Expected {FLOW_KEY_SIZE} bytes, got {len(data)}"
            )

        try:
            # Check if IPv6 (non-zero bytes in extended area)
            is_ipv6 = any(data[4:16]) or any(data[20:32])

            if is_ipv6:
                src_addr = IPv6Address(data[:16])
                dst_addr = IPv6Address(data[16:32])
            else:
                src_addr = IPv4Address(data[:4])
                dst_addr = IPv4Address(data[16:20])

            src_port, dst_port = struct.unpack("!HH", data[32:36])
            proto = Protocol(data[36])

            return cls(
                src_addr=src_addr,
                dst_addr=dst_addr,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
            )

        except Exception as e:
            raise SerializationError("FlowKey", "deserialize", str(e)) from e


# =============================================================================
# LRU Cache Value Structure (real_pos_lru)
# =============================================================================

# BPF struct layout for real_pos_lru:
# struct real_pos_lru {
#   __u32 pos;    // Real index (4 bytes)
#   __u64 atime;  // Access time in nanoseconds (8 bytes)
# };
# Total size: 16 bytes (4 + 4 padding + 8)

REAL_POS_LRU_SIZE = 16


@dataclass
class RealPosLru:
    """
    LRU cache value - matches BPF struct real_pos_lru.

    Stores the selected backend index and access time for cached flows.

    Attributes:
        pos: Backend index in reals array
        atime: Access time in nanoseconds (for UDP timeout)
    """

    pos: int
    atime: int = 0

    def to_bytes(self) -> bytes:
        """Serialize to BPF map value format (16 bytes)."""
        try:
            # pos (4 bytes) + padding (4 bytes) + atime (8 bytes)
            return struct.pack("<IIQ", self.pos, 0, self.atime)
        except Exception as e:
            raise SerializationError("RealPosLru", "serialize", str(e)) from e

    @classmethod
    def from_bytes(cls, data: bytes) -> RealPosLru:
        """Deserialize from BPF map value format."""
        if len(data) != REAL_POS_LRU_SIZE:
            raise SerializationError(
                "RealPosLru",
                "deserialize",
                f"Expected {REAL_POS_LRU_SIZE} bytes, got {len(data)}",
            )

        try:
            pos, _, atime = struct.unpack("<IIQ", data)
            return cls(pos=pos, atime=atime)
        except Exception as e:
            raise SerializationError("RealPosLru", "deserialize", str(e)) from e


# =============================================================================
# Control Array Value Structure (ctl_value)
# =============================================================================

# BPF struct layout for ctl_value:
# struct ctl_value {
#   union {
#     __u64 value;      // Generic 64-bit value
#     __u32 ifindex;    // Interface index
#     __u8 mac[6];      // MAC address
#   };
# };
# Total size: 8 bytes

CTL_VALUE_SIZE = 8


@dataclass
class CtlValue:
    """
    Control array value - matches BPF struct ctl_value.

    Can hold a 64-bit value, 32-bit interface index, or 6-byte MAC address.
    Used in ctl_array for global configuration.

    Attributes:
        value: Raw 8-byte value
    """

    value: bytes

    def __post_init__(self) -> None:
        """Validate and pad value to 8 bytes."""
        if len(self.value) > CTL_VALUE_SIZE:
            raise ValueError(f"Value too large: {len(self.value)} > {CTL_VALUE_SIZE}")
        # Pad to 8 bytes
        if len(self.value) < CTL_VALUE_SIZE:
            object.__setattr__(
                self, "value", self.value + b"\x00" * (CTL_VALUE_SIZE - len(self.value))
            )

    @classmethod
    def from_mac(cls, mac: str | bytes) -> CtlValue:
        """Create CtlValue from MAC address."""
        if isinstance(mac, str):
            # Parse MAC string like "aa:bb:cc:dd:ee:ff"
            mac_bytes = bytes.fromhex(mac.replace(":", "").replace("-", ""))
        else:
            mac_bytes = mac

        if len(mac_bytes) != 6:
            raise ValueError(f"Invalid MAC address length: {len(mac_bytes)}")

        return cls(value=mac_bytes)

    @classmethod
    def from_ifindex(cls, ifindex: int) -> CtlValue:
        """Create CtlValue from interface index."""
        return cls(value=struct.pack("<I", ifindex))

    @classmethod
    def from_u64(cls, value: int) -> CtlValue:
        """Create CtlValue from 64-bit integer."""
        return cls(value=struct.pack("<Q", value))

    def as_mac(self) -> str:
        """Return value as MAC address string."""
        return ":".join(f"{b:02x}" for b in self.value[:6])

    def as_ifindex(self) -> int:
        """Return value as interface index."""
        return struct.unpack("<I", self.value[:4])[0]

    def as_u64(self) -> int:
        """Return value as 64-bit integer."""
        return struct.unpack("<Q", self.value)[0]

    def to_bytes(self) -> bytes:
        """Serialize to BPF map value format (8 bytes)."""
        return self.value

    @classmethod
    def from_bytes(cls, data: bytes) -> CtlValue:
        """Deserialize from BPF map value format."""
        if len(data) != CTL_VALUE_SIZE:
            raise SerializationError(
                "CtlValue", "deserialize", f"Expected {CTL_VALUE_SIZE} bytes, got {len(data)}"
            )
        return cls(value=data)


# =============================================================================
# Statistics Structure (lb_stats)
# =============================================================================

# BPF struct layout for lb_stats:
# struct lb_stats {
#   __u64 v1;   // First counter (typically packets)
#   __u64 v2;   // Second counter (typically bytes)
# };
# Total size: 16 bytes

LB_STATS_SIZE = 16


@dataclass
class LbStats:
    """
    Statistics counters - matches BPF struct lb_stats.

    Used in stats map and reals_stats for tracking packets and bytes.

    Attributes:
        v1: First counter (typically packets)
        v2: Second counter (typically bytes)
    """

    v1: int = 0
    v2: int = 0

    @property
    def packets(self) -> int:
        """Alias for v1 (typically packet count)."""
        return self.v1

    @property
    def bytes(self) -> int:
        """Alias for v2 (typically byte count)."""
        return self.v2

    def __add__(self, other: LbStats) -> LbStats:
        """Add two LbStats together (for aggregating per-CPU values)."""
        return LbStats(v1=self.v1 + other.v1, v2=self.v2 + other.v2)

    def to_bytes(self) -> bytes:
        """Serialize to BPF map value format (16 bytes)."""
        try:
            return struct.pack("<QQ", self.v1, self.v2)
        except Exception as e:
            raise SerializationError("LbStats", "serialize", str(e)) from e

    @classmethod
    def from_bytes(cls, data: bytes) -> LbStats:
        """Deserialize from BPF map value format."""
        if len(data) != LB_STATS_SIZE:
            raise SerializationError(
                "LbStats", "deserialize", f"Expected {LB_STATS_SIZE} bytes, got {len(data)}"
            )

        try:
            v1, v2 = struct.unpack("<QQ", data)
            return cls(v1=v1, v2=v2)
        except Exception as e:
            raise SerializationError("LbStats", "deserialize", str(e)) from e

    @classmethod
    def aggregate(cls, stats_list: list[LbStats]) -> LbStats:
        """Aggregate a list of stats (e.g., from all CPUs)."""
        if not stats_list:
            return cls()
        result = cls()
        for stats in stats_list:
            result = result + stats
        return result


# =============================================================================
# High-Level Control Plane Types
# =============================================================================


@dataclass
class Real:
    """
    Full backend server representation for control plane.

    This is a higher-level representation used by the control plane
    to manage backends, including weight and state information not
    stored in BPF maps.

    Attributes:
        address: Backend server IP address
        weight: Backend weight for load balancing (0 = drained)
        index: Index in the reals array map (-1 if not allocated)
        flags: Backend flags
    """

    address: IpAddress
    weight: int = 100
    index: int = -1
    flags: RealFlags = RealFlags.NONE

    def __post_init__(self) -> None:
        """Parse address if string."""
        if isinstance(self.address, str):
            object.__setattr__(self, "address", _parse_ip_address(self.address))

    @property
    def is_allocated(self) -> bool:
        """Check if backend has an allocated index."""
        return self.index >= 0

    @property
    def is_drained(self) -> bool:
        """Check if backend is drained (weight = 0)."""
        return self.weight == 0

    def to_real_definition(self) -> RealDefinition:
        """Convert to BPF RealDefinition for map storage."""
        return RealDefinition(address=self.address, flags=self.flags)


@dataclass
class Vip:
    """
    Full VIP representation for control plane.

    This is a higher-level representation used by the control plane
    to manage VIPs, including associated backends.

    Attributes:
        key: VIP identifier (address, port, protocol)
        flags: VIP behavior flags
        vip_num: VIP index number (-1 if not allocated)
        reals: List of backend servers for this VIP
    """

    key: VipKey
    flags: VipFlags = VipFlags.NONE
    vip_num: int = -1
    reals: list[Real] = field(default_factory=list)

    @classmethod
    def create(
        cls,
        address: str | IpAddress,
        port: int,
        protocol: Protocol | str,
        flags: VipFlags = VipFlags.NONE,
    ) -> Vip:
        """
        Create a new VIP with the given parameters.

        Args:
            address: VIP IP address (string or address object)
            port: VIP port number
            protocol: IP protocol (TCP, UDP, or string)
            flags: VIP behavior flags
        """
        if isinstance(address, str):
            address = _parse_ip_address(address)

        if isinstance(protocol, str):
            protocol = Protocol[protocol.upper()]

        key = VipKey(address=address, port=port, protocol=protocol)
        return cls(key=key, flags=flags)

    @property
    def address(self) -> IpAddress:
        """VIP address."""
        return self.key.address

    @property
    def port(self) -> int:
        """VIP port."""
        return self.key.port

    @property
    def protocol(self) -> Protocol:
        """VIP protocol."""
        return self.key.protocol

    @property
    def is_allocated(self) -> bool:
        """Check if VIP has an allocated vip_num."""
        return self.vip_num >= 0

    @property
    def active_reals(self) -> list[Real]:
        """Get list of non-drained backends."""
        return [r for r in self.reals if r.weight > 0]

    def to_vip_meta(self) -> VipMeta:
        """Convert to BPF VipMeta for map storage."""
        return VipMeta(flags=self.flags, vip_num=self.vip_num)

    def __str__(self) -> str:
        """Human-readable VIP representation."""
        return str(self.key)
