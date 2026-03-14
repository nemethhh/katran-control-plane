"""
Control array map wrapper for BPF ctl_array.

The ctl_array stores global configuration data such as the default
router MAC address and interface index.

BPF Map Definition:
    Type: BPF_MAP_TYPE_ARRAY
    Key: __u32 (index, 4 bytes)
    Value: struct ctl_value (8 bytes)
    Max Entries: CTL_MAP_SIZE (16)
"""

from __future__ import annotations

import struct

from katran.bpf.map_manager import BpfMap
from katran.core.constants import CtlArrayIndex
from katran.core.types import CTL_VALUE_SIZE, CtlValue


class CtlArray(BpfMap[int, CtlValue]):
    """
    Wrapper for ctl_array BPF array map.

    Stores global configuration like MAC addresses and interface indices.

    Example:
        >>> with CtlArray("/sys/fs/bpf/katran") as ctl:
        ...     # Set router MAC address
        ...     ctl.set_mac("aa:bb:cc:dd:ee:ff")
        ...     # Get current MAC
        ...     mac = ctl.get_mac()
        ...     print(f"Router MAC: {mac}")
    """

    MAP_NAME = "ctl_array"

    def __init__(
        self,
        pin_base_path: str,
        map_name: str | None = None,
    ) -> None:
        """
        Initialize control array wrapper.

        Args:
            pin_base_path: Base path where maps are pinned
            map_name: Map name (defaults to "ctl_array")
        """
        super().__init__(pin_base_path, map_name)

    # -------------------------------------------------------------------------
    # Serialization methods
    # -------------------------------------------------------------------------

    @property
    def _key_size(self) -> int:
        return 4  # __u32

    @property
    def _value_size(self) -> int:
        return CTL_VALUE_SIZE

    def _serialize_key(self, key: int) -> bytes:
        return struct.pack("<I", key)

    def _deserialize_key(self, data: bytes) -> int:
        return int(struct.unpack("<I", data)[0])

    def _serialize_value(self, value: CtlValue) -> bytes:
        return value.to_bytes()

    def _deserialize_value(self, data: bytes) -> CtlValue:
        return CtlValue.from_bytes(data)

    # -------------------------------------------------------------------------
    # MAC address operations
    # -------------------------------------------------------------------------

    def set_mac(self, mac: str | bytes, index: int = CtlArrayIndex.MAC_ADDRESS_POS) -> None:
        """
        Set MAC address at specified index.

        Args:
            mac: MAC address (string like "aa:bb:cc:dd:ee:ff" or 6 bytes)
            index: Array index (default: MAC_ADDRESS_POS)
        """
        ctl_value = CtlValue.from_mac(mac)
        self.set(index, ctl_value)

    def get_mac(self, index: int = CtlArrayIndex.MAC_ADDRESS_POS) -> str | None:
        """
        Get MAC address at specified index.

        Args:
            index: Array index (default: MAC_ADDRESS_POS)

        Returns:
            MAC address string or None if not set
        """
        value = self.get(index)
        if value is None:
            return None
        return value.as_mac()

    def get_mac_bytes(self, index: int = CtlArrayIndex.MAC_ADDRESS_POS) -> bytes | None:
        """
        Get MAC address as raw bytes.

        Args:
            index: Array index

        Returns:
            6 bytes of MAC address or None
        """
        value = self.get(index)
        if value is None:
            return None
        return value.value[:6]

    # -------------------------------------------------------------------------
    # Interface index operations
    # -------------------------------------------------------------------------

    def set_ifindex(self, ifindex: int, index: int = CtlArrayIndex.IFINDEX_POS) -> None:
        """
        Set interface index.

        Args:
            ifindex: Interface index
            index: Array index (default: IFINDEX_POS)
        """
        ctl_value = CtlValue.from_ifindex(ifindex)
        self.set(index, ctl_value)

    def get_ifindex(self, index: int = CtlArrayIndex.IFINDEX_POS) -> int | None:
        """
        Get interface index.

        Args:
            index: Array index (default: IFINDEX_POS)

        Returns:
            Interface index or None if not set
        """
        value = self.get(index)
        if value is None:
            return None
        return value.as_ifindex()

    # -------------------------------------------------------------------------
    # Generic value operations
    # -------------------------------------------------------------------------

    def set_u64(self, value: int, index: int) -> None:
        """
        Set a 64-bit value.

        Args:
            value: 64-bit integer value
            index: Array index
        """
        ctl_value = CtlValue.from_u64(value)
        self.set(index, ctl_value)

    def get_u64(self, index: int) -> int | None:
        """
        Get a 64-bit value.

        Args:
            index: Array index

        Returns:
            64-bit integer or None
        """
        value = self.get(index)
        if value is None:
            return None
        return value.as_u64()

    # -------------------------------------------------------------------------
    # Convenience methods
    # -------------------------------------------------------------------------

    def configure_gateway(self, mac: str, ifindex: int) -> None:
        """
        Configure default gateway MAC and interface.

        Args:
            mac: Gateway MAC address
            ifindex: Gateway interface index
        """
        self.set_mac(mac)
        self.set_ifindex(ifindex)

    def get_configuration(self) -> dict[str, object]:
        """
        Get all control configuration.

        Returns:
            Dictionary with configuration values
        """
        return {
            "mac_address": self.get_mac(),
            "ifindex": self.get_ifindex(),
        }
