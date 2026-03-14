"""Tests for new REST API endpoints (source routing, decap, QUIC, HC, stats, LRU, etc.)."""

from unittest.mock import MagicMock, PropertyMock

import httpx
import pytest

from katran.api.rest.app import create_app
from katran.core.types import (
    HealthCheckProgStats,
    LbStats,
    LruAnalysis,
    LruEntries,
    PurgeResponse,
    QuicPacketStats,
    QuicReal,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

VIP_PARAMS = {"address": "10.0.0.1", "port": 80, "protocol": "tcp"}


@pytest.fixture
def mock_service():
    svc = MagicMock()
    type(svc).is_running = PropertyMock(return_value=True)
    type(svc).is_healthy = PropertyMock(return_value=True)
    svc.has_feature = MagicMock(return_value=True)
    svc.vip_manager = MagicMock()
    svc.real_manager = MagicMock()
    svc.config = MagicMock()
    svc.config.features = 0
    return svc


@pytest.fixture
def app(mock_service):
    return create_app(mock_service)


@pytest.fixture
async def client(app):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


# ---------------------------------------------------------------------------
# Source routing
# ---------------------------------------------------------------------------


class TestSrcRoutingEndpoints:
    @pytest.mark.asyncio
    async def test_add_src_routing(self, client, mock_service):
        mock_service.add_src_routing_rules.return_value = 0
        resp = await client.post(
            "/api/v1/src-routing/add",
            json={"srcs": ["10.0.0.0/24"], "dst": "192.168.1.1"},
        )
        assert resp.status_code == 200
        assert resp.json() == {"failures": 0}
        mock_service.add_src_routing_rules.assert_called_once_with(
            srcs=["10.0.0.0/24"], dst="192.168.1.1"
        )

    @pytest.mark.asyncio
    async def test_get_src_routing(self, client, mock_service):
        mock_service.get_src_routing_rules.return_value = {"10.0.0.0/24": "192.168.1.1"}
        resp = await client.get("/api/v1/src-routing")
        assert resp.status_code == 200
        assert resp.json() == {"10.0.0.0/24": "192.168.1.1"}

    @pytest.mark.asyncio
    async def test_remove_src_routing(self, client, mock_service):
        mock_service.del_src_routing_rules.return_value = True
        resp = await client.post(
            "/api/v1/src-routing/remove",
            json={"srcs": ["10.0.0.0/24"], "dst": "192.168.1.1"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "removed"

    @pytest.mark.asyncio
    async def test_clear_src_routing(self, client, mock_service):
        resp = await client.post("/api/v1/src-routing/clear")
        assert resp.status_code == 200
        assert resp.json()["status"] == "cleared"
        mock_service.clear_src_routing_rules.assert_called_once()


# ---------------------------------------------------------------------------
# Decap
# ---------------------------------------------------------------------------


class TestDecapEndpoints:
    @pytest.mark.asyncio
    async def test_add_decap_dst(self, client, mock_service):
        resp = await client.post("/api/v1/decap/dst/add", json={"address": "10.0.0.1"})
        assert resp.status_code == 200
        assert resp.json()["status"] == "added"
        mock_service.add_decap_dst.assert_called_once_with(dst="10.0.0.1")

    @pytest.mark.asyncio
    async def test_remove_decap_dst(self, client, mock_service):
        resp = await client.post("/api/v1/decap/dst/remove", json={"address": "10.0.0.1"})
        assert resp.status_code == 200
        assert resp.json()["status"] == "removed"

    @pytest.mark.asyncio
    async def test_get_decap_dsts(self, client, mock_service):
        mock_service.get_decap_dsts.return_value = ["10.0.0.1", "10.0.0.2"]
        resp = await client.get("/api/v1/decap/dst")
        assert resp.status_code == 200
        assert resp.json() == ["10.0.0.1", "10.0.0.2"]


# ---------------------------------------------------------------------------
# QUIC
# ---------------------------------------------------------------------------


class TestQuicEndpoints:
    @pytest.mark.asyncio
    async def test_add_quic_mapping(self, client, mock_service):
        mock_service.modify_quic_mapping.return_value = 0
        resp = await client.post(
            "/api/v1/quic/mapping",
            json={"action": "add", "mappings": [{"address": "10.0.0.1", "id": 1}]},
        )
        assert resp.status_code == 200
        assert resp.json() == {"failures": 0}

    @pytest.mark.asyncio
    async def test_get_quic_mapping(self, client, mock_service):
        mock_service.get_quic_mapping.return_value = [
            QuicReal(address="10.0.0.1", id=1),
        ]
        resp = await client.get("/api/v1/quic/mapping")
        assert resp.status_code == 200
        assert resp.json() == [{"address": "10.0.0.1", "id": 1}]

    @pytest.mark.asyncio
    async def test_invalidate_quic(self, client, mock_service):
        resp = await client.post(
            "/api/v1/quic/invalidate", json={"server_ids": [1, 2, 3]}
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "invalidated"
        mock_service.invalidate_quic_server_ids.assert_called_once_with(
            server_ids=[1, 2, 3]
        )

    @pytest.mark.asyncio
    async def test_revalidate_quic(self, client, mock_service):
        resp = await client.post(
            "/api/v1/quic/revalidate",
            json={"mappings": [{"address": "10.0.0.1", "id": 1}]},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "revalidated"


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------


class TestHcEndpoints:
    @pytest.mark.asyncio
    async def test_add_hc_dst(self, client, mock_service):
        resp = await client.post(
            "/api/v1/hc/dst/add", json={"somark": 1000, "dst": "10.0.0.1"}
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "added"
        mock_service.add_hc_dst.assert_called_once_with(somark=1000, dst="10.0.0.1")

    @pytest.mark.asyncio
    async def test_remove_hc_dst(self, client, mock_service):
        resp = await client.post("/api/v1/hc/dst/remove", json={"somark": 1000})
        assert resp.status_code == 200
        assert resp.json()["status"] == "removed"
        mock_service.del_hc_dst.assert_called_once_with(somark=1000)

    @pytest.mark.asyncio
    async def test_get_hc_dsts(self, client, mock_service):
        mock_service.get_hc_dsts.return_value = {1000: "10.0.0.1"}
        resp = await client.get("/api/v1/hc/dst")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_add_hc_key(self, client, mock_service):
        mock_service.add_hc_key.return_value = 5
        resp = await client.post(
            "/api/v1/hc/key/add",
            json={"address": "10.0.0.1", "port": 80, "protocol": "tcp"},
        )
        assert resp.status_code == 200
        assert resp.json() == {"index": 5}

    @pytest.mark.asyncio
    async def test_remove_hc_key(self, client, mock_service):
        resp = await client.post(
            "/api/v1/hc/key/remove",
            json={"address": "10.0.0.1", "port": 80, "protocol": "tcp"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "removed"

    @pytest.mark.asyncio
    async def test_get_hc_keys(self, client, mock_service):
        mock_service.get_hc_keys.return_value = {}
        resp = await client.get("/api/v1/hc/keys")
        assert resp.status_code == 200
        assert resp.json() == []

    @pytest.mark.asyncio
    async def test_set_hc_src_ip(self, client, mock_service):
        resp = await client.post("/api/v1/hc/src-ip", json={"address": "10.0.0.1"})
        assert resp.status_code == 200
        assert resp.json()["status"] == "set"

    @pytest.mark.asyncio
    async def test_set_hc_src_mac(self, client, mock_service):
        resp = await client.post(
            "/api/v1/hc/src-mac", json={"mac": "aa:bb:cc:dd:ee:ff"}
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "set"

    @pytest.mark.asyncio
    async def test_set_hc_dst_mac(self, client, mock_service):
        resp = await client.post(
            "/api/v1/hc/dst-mac", json={"mac": "aa:bb:cc:dd:ee:ff"}
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "set"

    @pytest.mark.asyncio
    async def test_set_hc_interface(self, client, mock_service):
        resp = await client.post("/api/v1/hc/interface", json={"ifindex": 2})
        assert resp.status_code == 200
        assert resp.json()["status"] == "set"

    @pytest.mark.asyncio
    async def test_get_hc_stats(self, client, mock_service):
        mock_service.get_hc_stats.return_value = HealthCheckProgStats(
            packets_processed=100,
            packets_dropped=5,
            packets_skipped=3,
            packets_too_big=1,
            packets_dst_matched=91,
        )
        resp = await client.get("/api/v1/hc/stats")
        assert resp.status_code == 200
        body = resp.json()
        assert body["packets_processed"] == 100
        assert body["packets_dropped"] == 5

    @pytest.mark.asyncio
    async def test_get_hc_stats_key(self, client, mock_service):
        mock_service.get_packets_for_hc_key.return_value = 42
        resp = await client.get(
            "/api/v1/hc/stats/key",
            params={"address": "10.0.0.1", "port": 80, "protocol": "tcp"},
        )
        assert resp.status_code == 200
        assert resp.json() == {"packets": 42}


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


class TestStatsEndpoints:
    @pytest.mark.asyncio
    async def test_get_vip_stats(self, client, mock_service):
        vip_mock = MagicMock()
        vip_mock.vip_num = 3
        mock_service.vip_manager.get_vip.return_value = vip_mock
        mock_service.get_vip_stats.return_value = LbStats(v1=100, v2=5000)
        resp = await client.get("/api/v1/stats/vip", params=VIP_PARAMS)
        assert resp.status_code == 200
        assert resp.json() == {"packets": 100, "bytes": 5000}

    @pytest.mark.asyncio
    async def test_get_real_stats(self, client, mock_service):
        mock_service.get_real_stats.return_value = LbStats(v1=50, v2=2000)
        resp = await client.get("/api/v1/stats/real", params={"index": 1})
        assert resp.status_code == 200
        assert resp.json() == {"packets": 50, "bytes": 2000}

    @pytest.mark.asyncio
    async def test_get_global_stats(self, client, mock_service):
        mock_service.get_all_global_stats.return_value = {
            "lru": {"v1": 0, "v2": 0},
        }
        resp = await client.get("/api/v1/stats/global")
        assert resp.status_code == 200
        assert "lru" in resp.json()

    @pytest.mark.asyncio
    async def test_get_quic_stats(self, client, mock_service):
        mock_service.get_quic_packet_stats.return_value = QuicPacketStats(
            ch_routed=50, cid_routed=30
        )
        resp = await client.get("/api/v1/stats/quic")
        assert resp.status_code == 200
        body = resp.json()
        assert body["ch_routed"] == 50
        assert body["cid_routed"] == 30

    @pytest.mark.asyncio
    async def test_get_hc_program_stats(self, client, mock_service):
        mock_service.get_hc_program_stats.return_value = HealthCheckProgStats(
            packets_processed=42
        )
        resp = await client.get("/api/v1/stats/hc")
        assert resp.status_code == 200
        assert resp.json()["packets_processed"] == 42

    @pytest.mark.asyncio
    async def test_get_per_cpu_stats(self, client, mock_service):
        mock_service.get_per_core_packets_stats.return_value = [100, 200, 150]
        resp = await client.get("/api/v1/stats/per-cpu")
        assert resp.status_code == 200
        assert resp.json() == [100, 200, 150]


# ---------------------------------------------------------------------------
# Features
# ---------------------------------------------------------------------------


class TestFeaturesEndpoint:
    @pytest.mark.asyncio
    async def test_get_features(self, client, mock_service):
        mock_service.config.features = 3
        resp = await client.get("/api/v1/features")
        assert resp.status_code == 200
        body = resp.json()
        assert "flags" in body
        assert "enabled" in body
        assert body["flags"] == 3


# ---------------------------------------------------------------------------
# Encap
# ---------------------------------------------------------------------------


class TestEncapEndpoints:
    @pytest.mark.asyncio
    async def test_set_encap_src_ip(self, client, mock_service):
        resp = await client.post("/api/v1/encap/src-ip", json={"address": "10.0.0.1"})
        assert resp.status_code == 200
        assert resp.json()["status"] == "set"
        mock_service.set_src_ip_for_encap.assert_called_once_with(address="10.0.0.1")


# ---------------------------------------------------------------------------
# LRU
# ---------------------------------------------------------------------------


class TestLruEndpoints:
    @pytest.mark.asyncio
    async def test_lru_search(self, client, mock_service):
        mock_service.lru_search.return_value = LruEntries(entries=[], error="")
        resp = await client.post(
            "/api/v1/lru/search",
            json={"vip": VIP_PARAMS, "src_ip": "10.1.0.1", "src_port": 12345},
        )
        assert resp.status_code == 200
        assert resp.json() == {"entries": 0, "error": ""}

    @pytest.mark.asyncio
    async def test_lru_list(self, client, mock_service):
        mock_service.lru_list.return_value = LruEntries(entries=[], error="")
        resp = await client.post(
            "/api/v1/lru/list",
            json={"vip": VIP_PARAMS, "limit": 50},
        )
        assert resp.status_code == 200
        assert resp.json()["entries"] == 0

    @pytest.mark.asyncio
    async def test_lru_delete(self, client, mock_service):
        mock_service.lru_delete.return_value = ["lru_map_0"]
        resp = await client.post(
            "/api/v1/lru/delete",
            json={"vip": VIP_PARAMS, "src_ip": "10.1.0.1", "src_port": 12345},
        )
        assert resp.status_code == 200
        assert resp.json() == {"deleted": ["lru_map_0"]}

    @pytest.mark.asyncio
    async def test_lru_purge_vip(self, client, mock_service):
        mock_service.lru_purge_vip.return_value = PurgeResponse(deleted_count=5)
        resp = await client.post(
            "/api/v1/lru/purge-vip",
            json={"vip": VIP_PARAMS},
        )
        assert resp.status_code == 200
        assert resp.json() == {"deleted_count": 5}

    @pytest.mark.asyncio
    async def test_lru_purge_real(self, client, mock_service):
        mock_service.lru_purge_vip_for_real.return_value = PurgeResponse(deleted_count=3)
        resp = await client.post(
            "/api/v1/lru/purge-real",
            json={"vip": VIP_PARAMS, "real_index": 1},
        )
        assert resp.status_code == 200
        assert resp.json() == {"deleted_count": 3}

    @pytest.mark.asyncio
    async def test_lru_analyze(self, client, mock_service):
        mock_service.lru_analyze.return_value = LruAnalysis(
            total_entries=10, per_vip={}
        )
        resp = await client.get("/api/v1/lru/analyze")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total_entries"] == 10
        assert body["per_vip"] == {}


# ---------------------------------------------------------------------------
# Down reals
# ---------------------------------------------------------------------------


class TestDownRealsEndpoints:
    @pytest.mark.asyncio
    async def test_add_down_real(self, client, mock_service):
        resp = await client.post(
            "/api/v1/down-reals/add",
            json={"vip": VIP_PARAMS, "real_index": 1},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "added"

    @pytest.mark.asyncio
    async def test_remove_down_real(self, client, mock_service):
        resp = await client.post(
            "/api/v1/down-reals/remove",
            json={"vip": VIP_PARAMS, "real_index": 1},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "removed"

    @pytest.mark.asyncio
    async def test_remove_down_reals_vip(self, client, mock_service):
        resp = await client.post("/api/v1/down-reals/remove-vip", json=VIP_PARAMS)
        assert resp.status_code == 200
        assert resp.json()["status"] == "removed"

    @pytest.mark.asyncio
    async def test_check_down_real(self, client, mock_service):
        mock_service.check_down_real.return_value = True
        resp = await client.post(
            "/api/v1/down-reals/check",
            json={"vip": VIP_PARAMS, "real_index": 1},
        )
        assert resp.status_code == 200
        assert resp.json() == {"is_down": True}

    @pytest.mark.asyncio
    async def test_check_down_real_false(self, client, mock_service):
        mock_service.check_down_real.return_value = False
        resp = await client.post(
            "/api/v1/down-reals/check",
            json={"vip": VIP_PARAMS, "real_index": 2},
        )
        assert resp.status_code == 200
        assert resp.json() == {"is_down": False}
