"""
Custom exceptions for Katran control plane.

Exception hierarchy:
    KatranError (base)
    ├── BpfMapError
    │   ├── MapNotFoundError
    │   ├── MapOperationError
    │   └── SerializationError
    ├── VipError
    │   ├── VipExistsError
    │   └── VipNotFoundError
    ├── RealError
    │   ├── RealExistsError
    │   └── RealNotFoundError
    ├── ResourceExhaustedError
    └── ConfigurationError
"""


class KatranError(Exception):
    """Base exception for all Katran control plane errors."""

    pass


# =============================================================================
# BPF Map Errors
# =============================================================================


class BpfMapError(KatranError):
    """Base exception for BPF map operations."""

    pass


class MapNotFoundError(BpfMapError):
    """Raised when a BPF map cannot be found at the expected path."""

    def __init__(self, map_name: str, map_path: str) -> None:
        self.map_name = map_name
        self.map_path = map_path
        super().__init__(f"BPF map '{map_name}' not found at path: {map_path}")


class MapOperationError(BpfMapError):
    """Raised when a BPF map operation fails."""

    def __init__(
        self,
        operation: str,
        map_name: str,
        error_code: int | None = None,
        message: str | None = None,
    ) -> None:
        self.operation = operation
        self.map_name = map_name
        self.error_code = error_code

        if message:
            msg = f"BPF map operation '{operation}' failed on '{map_name}': {message}"
        elif error_code:
            msg = f"BPF map operation '{operation}' failed on '{map_name}' with errno {error_code}"
        else:
            msg = f"BPF map operation '{operation}' failed on '{map_name}'"

        super().__init__(msg)


class SerializationError(BpfMapError):
    """Raised when serialization/deserialization of BPF data fails."""

    def __init__(self, type_name: str, direction: str, message: str) -> None:
        self.type_name = type_name
        self.direction = direction  # "serialize" or "deserialize"
        super().__init__(f"Failed to {direction} {type_name}: {message}")


# =============================================================================
# VIP Errors
# =============================================================================


class VipError(KatranError):
    """Base exception for VIP operations."""

    pass


class VipExistsError(VipError):
    """Raised when attempting to create a VIP that already exists."""

    def __init__(self, address: str, port: int, protocol: str) -> None:
        self.address = address
        self.port = port
        self.protocol = protocol
        super().__init__(f"VIP already exists: {address}:{port}/{protocol}")


class VipNotFoundError(VipError):
    """Raised when a VIP cannot be found."""

    def __init__(self, address: str, port: int, protocol: str) -> None:
        self.address = address
        self.port = port
        self.protocol = protocol
        super().__init__(f"VIP not found: {address}:{port}/{protocol}")


# =============================================================================
# Real (Backend) Errors
# =============================================================================


class RealError(KatranError):
    """Base exception for backend (real) operations."""

    pass


class RealExistsError(RealError):
    """Raised when attempting to add a backend that already exists."""

    def __init__(self, address: str, vip_key: str | None = None) -> None:
        self.address = address
        self.vip_key = vip_key
        if vip_key:
            msg = f"Backend {address} already exists for VIP {vip_key}"
        else:
            msg = f"Backend {address} already exists"
        super().__init__(msg)


class RealNotFoundError(RealError):
    """Raised when a backend cannot be found."""

    def __init__(self, address: str, vip_key: str | None = None) -> None:
        self.address = address
        self.vip_key = vip_key
        if vip_key:
            msg = f"Backend {address} not found for VIP {vip_key}"
        else:
            msg = f"Backend {address} not found"
        super().__init__(msg)


# =============================================================================
# Resource Errors
# =============================================================================


class ResourceExhaustedError(KatranError):
    """Raised when a resource limit is reached."""

    def __init__(self, resource_type: str, limit: int) -> None:
        self.resource_type = resource_type
        self.limit = limit
        super().__init__(f"Resource exhausted: {resource_type} (limit: {limit})")


# =============================================================================
# Configuration Errors
# =============================================================================


class ConfigurationError(KatranError):
    """Raised when there's a configuration problem."""

    def __init__(self, message: str, field: str | None = None) -> None:
        self.field = field
        if field:
            super().__init__(f"Configuration error for '{field}': {message}")
        else:
            super().__init__(f"Configuration error: {message}")


# =============================================================================
# BPF Program Errors
# =============================================================================


class BpfLoadError(KatranError):
    """Raised when loading a BPF program fails."""

    def __init__(self, program_path: str, message: str) -> None:
        self.program_path = program_path
        super().__init__(f"Failed to load BPF program '{program_path}': {message}")


class BpfAttachError(KatranError):
    """Raised when attaching a BPF program fails."""

    def __init__(self, interface: str, program_type: str, message: str) -> None:
        self.interface = interface
        self.program_type = program_type
        super().__init__(
            f"Failed to attach {program_type} program to '{interface}': {message}"
        )
