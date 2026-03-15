"""E2E tests for feature flags API endpoint."""


class TestFeatureFlags:
    """Verify GET /api/v1/features returns configured features."""

    def test_list_features_all_enabled(self, api_client):
        resp = api_client.get("/api/v1/features")
        assert resp.status_code == 200
        data = resp.json()
        enabled = data["enabled"]
        assert "SRC_ROUTING" in enabled
        assert "INLINE_DECAP" in enabled
        assert "DIRECT_HEALTHCHECKING" in enabled

    def test_features_response_structure(self, api_client):
        resp = api_client.get("/api/v1/features")
        assert resp.status_code == 200
        data = resp.json()
        assert "flags" in data
        assert "enabled" in data
        assert isinstance(data["flags"], int)
        assert isinstance(data["enabled"], list)

    def test_features_flags_bitmask(self, api_client):
        resp = api_client.get("/api/v1/features")
        assert resp.status_code == 200
        data = resp.json()
        assert data["flags"] != 0
        # SRC_ROUTING=1, INLINE_DECAP=2, DIRECT_HEALTHCHECKING=16
        assert data["flags"] & 1  # SRC_ROUTING
        assert data["flags"] & 2  # INLINE_DECAP
        assert data["flags"] & 16  # DIRECT_HEALTHCHECKING
