"""Tests for Katran configuration management."""


import pytest

from katran.core.config import KatranConfig, _is_prime
from katran.core.exceptions import ConfigurationError

# ---------------------------------------------------------------------------
# Flat format (existing katran.yaml)
# ---------------------------------------------------------------------------


class TestFlatConfig:
    """Tests for loading flat-format YAML config."""

    def test_load_existing_flat_yaml(self):
        """Load the actual config/katran.yaml and verify all fields parse."""
        cfg = KatranConfig.from_yaml("config/katran.yaml")
        assert cfg.interface.name == "eth0"
        assert cfg.interface.xdp_mode == "native"
        assert cfg.interface.default_gateway_mac == "aa:bb:cc:dd:ee:ff"
        assert cfg.bpf.xdp_program == "/usr/share/katran/balancer.o"
        assert cfg.bpf.hc_program == "/usr/share/katran/healthchecking_ipip.o"
        assert cfg.bpf.pin_path == "/sys/fs/bpf/katran"
        assert cfg.maps.max_vips == 512
        assert cfg.maps.max_reals == 4096
        assert cfg.maps.lru_size == 1000000
        assert cfg.maps.ring_size == 65537
        assert cfg.api.grpc_port == 50051
        assert cfg.api.rest_port == 8080
        assert cfg.api.prometheus_port == 9100
        assert cfg.logging.level == "INFO"
        assert cfg.logging.format == "json"

    def test_flat_format_autodetection(self):
        data = {
            "interface": "lo",
            "xdp_mode": "generic",
            "pin_path": "/tmp/bpf",
            "max_vips": 64,
            "ring_size": 13,
            "log_level": "DEBUG",
        }
        cfg = KatranConfig.from_dict(data)
        assert cfg.interface.name == "lo"
        assert cfg.interface.xdp_mode == "generic"
        assert cfg.bpf.pin_path == "/tmp/bpf"
        assert cfg.maps.max_vips == 64
        assert cfg.maps.ring_size == 13
        assert cfg.logging.level == "DEBUG"


# ---------------------------------------------------------------------------
# Nested format
# ---------------------------------------------------------------------------


class TestNestedConfig:
    """Tests for loading nested-format config."""

    def test_nested_dict(self):
        data = {
            "interface": {
                "name": "lo",
                "xdp_mode": "skb",
                "default_gateway_mac": "11:22:33:44:55:66",
            },
            "bpf": {"pin_path": "/tmp/bpf"},
            "maps": {"max_vips": 128, "ring_size": 65537},
            "logging": {"level": "WARNING", "format": "console"},
        }
        cfg = KatranConfig.from_dict(data)
        assert cfg.interface.name == "lo"
        assert cfg.interface.xdp_mode == "skb"
        assert cfg.interface.default_gateway_mac == "11:22:33:44:55:66"
        assert cfg.maps.max_vips == 128
        assert cfg.logging.level == "WARNING"
        assert cfg.logging.format == "console"

    def test_defaults_when_empty(self):
        cfg = KatranConfig.from_dict({})
        assert cfg.interface.name == "eth0"
        assert cfg.maps.ring_size == 65537
        assert cfg.logging.level == "INFO"


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


class TestValidation:
    """Tests for config validation rules."""

    def test_valid_mac_formats(self):
        for mac in ("aa:bb:cc:dd:ee:ff", "AA:BB:CC:DD:EE:FF", "01-23-45-67-89-ab"):
            data = {"interface": {"default_gateway_mac": mac}}
            cfg = KatranConfig.from_dict(data)
            assert cfg.interface.default_gateway_mac == mac.lower().replace("-", "-")

    def test_invalid_mac(self):
        with pytest.raises(ConfigurationError):
            KatranConfig.from_dict({"interface": {"default_gateway_mac": "not-a-mac"}})

    def test_xdp_mode_valid(self):
        for mode in ("native", "generic", "offload", "skb"):
            cfg = KatranConfig.from_dict({"interface": {"xdp_mode": mode}})
            assert cfg.interface.xdp_mode == mode

    def test_xdp_mode_invalid(self):
        with pytest.raises(ConfigurationError):
            KatranConfig.from_dict({"interface": {"xdp_mode": "turbo"}})

    def test_ring_size_must_be_prime(self):
        with pytest.raises(ConfigurationError):
            KatranConfig.from_dict({"maps": {"ring_size": 100}})

    def test_ring_size_prime_ok(self):
        cfg = KatranConfig.from_dict({"maps": {"ring_size": 65537}})
        assert cfg.maps.ring_size == 65537

    def test_log_level_valid(self):
        for level in ("DEBUG", "info", "Warning", "ERROR", "CRITICAL"):
            cfg = KatranConfig.from_dict({"logging": {"level": level}})
            assert cfg.logging.level == level.upper()

    def test_log_level_invalid(self):
        with pytest.raises(ConfigurationError):
            KatranConfig.from_dict({"logging": {"level": "TRACE"}})

    def test_log_format_valid(self):
        for fmt in ("json", "console", "JSON", "Console"):
            cfg = KatranConfig.from_dict({"logging": {"format": fmt}})
            assert cfg.logging.format == fmt.lower()

    def test_log_format_invalid(self):
        with pytest.raises(ConfigurationError):
            KatranConfig.from_dict({"logging": {"format": "syslog"}})

    def test_missing_config_file(self):
        with pytest.raises(ConfigurationError, match="not found"):
            KatranConfig.from_yaml("/nonexistent/katran.yaml")


# ---------------------------------------------------------------------------
# Primality helper
# ---------------------------------------------------------------------------


class TestIsPrime:
    def test_known_primes(self):
        for p in (2, 3, 5, 7, 11, 13, 65537):
            assert _is_prime(p), f"{p} should be prime"

    def test_known_composites(self):
        for c in (0, 1, 4, 6, 8, 9, 100, 65536):
            assert not _is_prime(c), f"{c} should not be prime"
