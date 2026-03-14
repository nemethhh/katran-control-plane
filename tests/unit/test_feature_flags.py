"""Tests for feature flags, new constants, and new exceptions."""

from katran.core.constants import (
    HC_CTRL_MAP_SIZE,
    MAX_DECAP_DST,
    MAX_LPM_SRC,
    MAX_QUIC_REALS,
    V4_SRC_INDEX,
    V6_SRC_INDEX,
    KatranFeature,
    ModifyAction,
    StatsCounterIndex,
)


class TestKatranFeature:
    def test_flag_values(self):
        assert KatranFeature.SRC_ROUTING == 1
        assert KatranFeature.INLINE_DECAP == 2
        assert KatranFeature.DIRECT_HEALTHCHECKING == 16

    def test_combine_flags(self):
        features = KatranFeature.SRC_ROUTING | KatranFeature.INLINE_DECAP
        assert KatranFeature.SRC_ROUTING in features
        assert KatranFeature.DIRECT_HEALTHCHECKING not in features

    def test_from_int(self):
        features = KatranFeature(5)
        assert KatranFeature.SRC_ROUTING in features


class TestModifyAction:
    def test_values(self):
        assert ModifyAction.ADD.value == "add"
        assert ModifyAction.DEL.value == "del"


class TestNewConstants:
    def test_encap_fail_cntr(self):
        assert StatsCounterIndex.ENCAP_FAIL_CNTR == 7

    def test_hc_constants(self):
        assert HC_CTRL_MAP_SIZE == 4
        assert V4_SRC_INDEX == 0
        assert V6_SRC_INDEX == 1

    def test_map_size_defaults(self):
        assert MAX_LPM_SRC == 3_000_000
        assert MAX_DECAP_DST == 6
        assert MAX_QUIC_REALS == 0x00FFFFFE


from katran.core.exceptions import (
    DecapError,
    FeatureNotEnabledError,
    HealthCheckError,
    KatranError,
    QuicMappingError,
    SrcRoutingError,
)


class TestNewExceptions:
    def test_feature_not_enabled(self):
        err = FeatureNotEnabledError("SRC_ROUTING")
        assert "SRC_ROUTING" in str(err)
        assert isinstance(err, KatranError)

    def test_health_check_error(self):
        err = HealthCheckError("HC map full")
        assert isinstance(err, KatranError)

    def test_src_routing_error(self):
        err = SrcRoutingError("invalid CIDR")
        assert isinstance(err, KatranError)

    def test_quic_mapping_error(self):
        err = QuicMappingError("ID out of range")
        assert isinstance(err, KatranError)

    def test_decap_error(self):
        err = DecapError("max destinations reached")
        assert isinstance(err, KatranError)
