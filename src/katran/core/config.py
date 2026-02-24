"""
Configuration management for Katran control plane.

Supports both flat (legacy) and nested YAML configuration formats.
Uses Pydantic v2 for validation.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, field_validator, model_validator

from katran.core.constants import DEFAULT_LRU_SIZE, MAX_REALS, MAX_VIPS, RING_SIZE
from katran.core.exceptions import ConfigurationError

# Known primes used for ring sizes (subset for fast validation)
_SMALL_PRIMES = {2, 3, 5, 7, 11, 13}


def _is_prime(n: int) -> bool:
    """Check if a number is prime."""
    if n < 2:
        return False
    if n in _SMALL_PRIMES:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True


_MAC_RE = re.compile(r"^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$")
_VALID_XDP_MODES = {"native", "generic", "offload", "skb"}
_VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
_VALID_LOG_FORMATS = {"json", "console"}


class InterfaceConfig(BaseModel):
    """Network interface configuration."""

    name: str = "eth0"
    xdp_mode: str = "native"
    default_gateway_mac: str = "aa:bb:cc:dd:ee:ff"

    @field_validator("xdp_mode")
    @classmethod
    def validate_xdp_mode(cls, v: str) -> str:
        v = v.lower()
        if v not in _VALID_XDP_MODES:
            raise ValueError(f"xdp_mode must be one of {_VALID_XDP_MODES}, got '{v}'")
        return v

    @field_validator("default_gateway_mac")
    @classmethod
    def validate_mac(cls, v: str) -> str:
        if not _MAC_RE.match(v):
            raise ValueError(f"Invalid MAC address format: '{v}'")
        return v.lower()


class BpfConfig(BaseModel):
    """BPF program paths."""

    xdp_program: str = "/usr/share/katran/balancer.o"
    hc_program: str = "/usr/share/katran/healthchecking_ipip.o"
    pin_path: str = "/sys/fs/bpf/katran"


class MapConfig(BaseModel):
    """BPF map size limits."""

    max_vips: int = MAX_VIPS
    max_reals: int = MAX_REALS
    lru_size: int = DEFAULT_LRU_SIZE
    ring_size: int = RING_SIZE

    @field_validator("ring_size")
    @classmethod
    def validate_ring_size_prime(cls, v: int) -> int:
        if not _is_prime(v):
            raise ValueError(f"ring_size must be prime, got {v}")
        return v


class ApiConfig(BaseModel):
    """API port configuration."""

    grpc_port: int = 50051
    rest_port: int = 8080
    prometheus_port: int = 9100


class LogConfig(BaseModel):
    """Logging configuration."""

    level: str = "INFO"
    format: str = "json"

    @field_validator("level")
    @classmethod
    def validate_level(cls, v: str) -> str:
        v = v.upper()
        if v not in _VALID_LOG_LEVELS:
            raise ValueError(f"log level must be one of {_VALID_LOG_LEVELS}, got '{v}'")
        return v

    @field_validator("format")
    @classmethod
    def validate_format(cls, v: str) -> str:
        v = v.lower()
        if v not in _VALID_LOG_FORMATS:
            raise ValueError(f"log format must be one of {_VALID_LOG_FORMATS}, got '{v}'")
        return v


# Keys that only appear in flat format
_FLAT_KEYS = {
    "interface",
    "xdp_mode",
    "default_gateway_mac",
    "xdp_program",
    "hc_program",
    "pin_path",
    "max_vips",
    "max_reals",
    "lru_size",
    "ring_size",
    "grpc_port",
    "rest_port",
    "prometheus_port",
    "log_level",
    "log_format",
}


def _is_flat_config(data: dict[str, Any]) -> bool:
    """Detect whether config dict uses flat format.

    Flat format has top-level scalar keys like ``interface: "eth0"``.
    Nested format has ``interface: {name: "eth0", ...}``.
    We check if any unambiguous flat-only key is present, or if known
    keys have scalar (non-dict) values.
    """
    # Keys that only exist in flat format (never a nested group name)
    unambiguous_flat = {
        "xdp_mode",
        "default_gateway_mac",
        "xdp_program",
        "hc_program",
        "pin_path",
        "max_vips",
        "max_reals",
        "lru_size",
        "ring_size",
        "grpc_port",
        "rest_port",
        "prometheus_port",
        "log_level",
        "log_format",
    }
    if set(data.keys()) & unambiguous_flat:
        return True
    # "interface" exists in both formats: str in flat, dict in nested
    if "interface" in data and isinstance(data["interface"], str):
        return True
    return False


def _normalize_flat_config(data: dict[str, Any]) -> dict[str, Any]:
    """Convert flat YAML keys to nested structure."""
    return {
        "interface": {
            "name": data.get("interface", "eth0"),
            "xdp_mode": data.get("xdp_mode", "native"),
            "default_gateway_mac": data.get("default_gateway_mac", "aa:bb:cc:dd:ee:ff"),
        },
        "bpf": {
            "xdp_program": data.get("xdp_program", "/usr/share/katran/balancer.o"),
            "hc_program": data.get("hc_program", "/usr/share/katran/healthchecking_ipip.o"),
            "pin_path": data.get("pin_path", "/sys/fs/bpf/katran"),
        },
        "maps": {
            "max_vips": data.get("max_vips", MAX_VIPS),
            "max_reals": data.get("max_reals", MAX_REALS),
            "lru_size": data.get("lru_size", DEFAULT_LRU_SIZE),
            "ring_size": data.get("ring_size", RING_SIZE),
        },
        "api": {
            "grpc_port": data.get("grpc_port", 50051),
            "rest_port": data.get("rest_port", 8080),
            "prometheus_port": data.get("prometheus_port", 9100),
        },
        "logging": {
            "level": data.get("log_level", "INFO"),
            "format": data.get("log_format", "json"),
        },
    }


class KatranConfig(BaseModel):
    """Top-level Katran configuration."""

    interface: InterfaceConfig = InterfaceConfig()
    bpf: BpfConfig = BpfConfig()
    maps: MapConfig = MapConfig()
    api: ApiConfig = ApiConfig()
    logging: LogConfig = LogConfig()

    @model_validator(mode="before")
    @classmethod
    def normalize_flat(cls, data: Any) -> Any:
        if isinstance(data, dict) and _is_flat_config(data):
            return _normalize_flat_config(data)
        return data

    @classmethod
    def from_yaml(cls, path: str | Path) -> KatranConfig:
        """Load configuration from a YAML file."""
        path = Path(path)
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
        except FileNotFoundError:
            raise ConfigurationError(f"Config file not found: {path}")
        except yaml.YAMLError as e:
            raise ConfigurationError(f"Invalid YAML: {e}")

        if data is None:
            data = {}

        try:
            return cls.model_validate(data)
        except Exception as e:
            raise ConfigurationError(str(e))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> KatranConfig:
        """Load configuration from a dictionary."""
        try:
            return cls.model_validate(data)
        except Exception as e:
            raise ConfigurationError(str(e))

    def validate_paths(self) -> list[str]:
        """
        Validate that configured paths exist on disk.

        Returns list of error messages (empty if all paths valid).
        """
        errors: list[str] = []
        if not Path(self.bpf.xdp_program).exists():
            errors.append(f"XDP program not found: {self.bpf.xdp_program}")
        if not Path(self.bpf.hc_program).exists():
            errors.append(f"HC program not found: {self.bpf.hc_program}")
        if not Path(self.bpf.pin_path).exists():
            errors.append(f"Pin path not found: {self.bpf.pin_path}")
        return errors
