"""Tests for the REST API."""

from unittest.mock import MagicMock, PropertyMock
from ipaddress import IPv4Address

import pytest
import httpx

from katran.api.rest import create_app
from katran.core.constants import Protocol, VipFlags
from katran.core.exceptions import (
    RealExistsError,
    VipExistsError,
)
from katran.core.types import Real, Vip, VipKey


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_vip(address="10.0.0.1", port=80, proto=Protocol.TCP, vip_num=0, reals=None):
    vip = Vip.create(address=address, port=port, protocol=proto)
    vip.vip_num = vip_num
    if reals:
        vip.reals = reals
    return vip


def _make_real(address="10.0.0.100", weight=100, index=1):
    return Real(address=IPv4Address(address), weight=weight, index=index)


VIP_PARAMS = {"address": "10.0.0.1", "port": 80, "protocol": "tcp"}


@pytest.fixture
def mock_service():
    svc = MagicMock()
    type(svc).is_running = PropertyMock(return_value=True)
    svc.vip_manager = MagicMock()
    svc.real_manager = MagicMock()
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
# Health
# ---------------------------------------------------------------------------

class TestHealth:
    @pytest.mark.asyncio
    async def test_healthy(self, client):
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"

    @pytest.mark.asyncio
    async def test_unhealthy(self):
        svc = MagicMock()
        type(svc).is_running = PropertyMock(return_value=False)
        app = create_app(svc)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.get("/health")
            assert resp.status_code == 503

    @pytest.mark.asyncio
    async def test_no_service(self):
        app = create_app(None)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.get("/health")
            assert resp.status_code == 503


# ---------------------------------------------------------------------------
# VIP endpoints
# ---------------------------------------------------------------------------

class TestVipEndpoints:
    @pytest.mark.asyncio
    async def test_add_vip(self, client, mock_service):
        vip = _make_vip()
        mock_service.vip_manager.add_vip.return_value = vip

        resp = await client.post("/api/v1/vips", json={
            "address": "10.0.0.1", "port": 80, "protocol": "tcp"
        })
        assert resp.status_code == 201
        body = resp.json()
        assert body["address"] == "10.0.0.1"
        assert body["port"] == 80
        assert body["protocol"] == "tcp"

    @pytest.mark.asyncio
    async def test_add_vip_duplicate(self, client, mock_service):
        mock_service.vip_manager.add_vip.side_effect = VipExistsError("10.0.0.1", 80, "tcp")
        resp = await client.post("/api/v1/vips", json={
            "address": "10.0.0.1", "port": 80, "protocol": "tcp"
        })
        assert resp.status_code == 409

    @pytest.mark.asyncio
    async def test_list_vips(self, client, mock_service):
        mock_service.vip_manager.list_vips.return_value = [_make_vip(), _make_vip("10.0.0.2", 443)]
        resp = await client.get("/api/v1/vips")
        assert resp.status_code == 200
        assert len(resp.json()) == 2

    @pytest.mark.asyncio
    async def test_get_vip(self, client, mock_service):
        vip = _make_vip()
        mock_service.vip_manager.get_vip.return_value = vip
        resp = await client.get("/api/v1/vips", params=VIP_PARAMS)
        assert resp.status_code == 200
        assert resp.json()["address"] == "10.0.0.1"

    @pytest.mark.asyncio
    async def test_get_vip_not_found(self, client, mock_service):
        mock_service.vip_manager.get_vip.return_value = None
        resp = await client.get("/api/v1/vips", params={
            "address": "10.0.0.99", "port": 80, "protocol": "tcp"
        })
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_get_vip_partial_params_400(self, client, mock_service):
        resp = await client.get("/api/v1/vips", params={"address": "10.0.0.1"})
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_remove_vip(self, client, mock_service):
        mock_service.vip_manager.remove_vip.return_value = True
        resp = await client.post("/api/v1/vips/remove", json=VIP_PARAMS)
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_remove_vip_not_found(self, client, mock_service):
        mock_service.vip_manager.remove_vip.return_value = False
        resp = await client.post("/api/v1/vips/remove", json=VIP_PARAMS)
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_invalid_protocol(self, client, mock_service):
        resp = await client.post("/api/v1/vips", json={
            "address": "10.0.0.1", "port": 80, "protocol": "icmp"
        })
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Backend endpoints
# ---------------------------------------------------------------------------

class TestBackendEndpoints:
    @pytest.mark.asyncio
    async def test_add_backend(self, client, mock_service):
        vip = _make_vip()
        mock_service.vip_manager.get_vip.return_value = vip
        real = _make_real()
        mock_service.real_manager.add_real.return_value = real

        resp = await client.post("/api/v1/backends/add", json={
            "vip": VIP_PARAMS, "address": "10.0.0.100", "weight": 100,
        })
        assert resp.status_code == 201
        assert resp.json()["address"] == "10.0.0.100"

    @pytest.mark.asyncio
    async def test_add_backend_duplicate(self, client, mock_service):
        mock_service.vip_manager.get_vip.return_value = _make_vip()
        mock_service.real_manager.add_real.side_effect = RealExistsError("10.0.0.100")
        resp = await client.post("/api/v1/backends/add", json={
            "vip": VIP_PARAMS, "address": "10.0.0.100",
        })
        assert resp.status_code == 409

    @pytest.mark.asyncio
    async def test_add_backend_vip_not_found(self, client, mock_service):
        mock_service.vip_manager.get_vip.return_value = None
        resp = await client.post("/api/v1/backends/add", json={
            "vip": {"address": "10.0.0.99", "port": 80, "protocol": "tcp"},
            "address": "10.0.0.100",
        })
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_remove_backend(self, client, mock_service):
        mock_service.vip_manager.get_vip.return_value = _make_vip()
        mock_service.real_manager.remove_real.return_value = True
        resp = await client.post("/api/v1/backends/remove", json={
            "vip": VIP_PARAMS, "address": "10.0.0.100",
        })
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_remove_backend_not_found(self, client, mock_service):
        mock_service.vip_manager.get_vip.return_value = _make_vip()
        mock_service.real_manager.remove_real.return_value = False
        resp = await client.post("/api/v1/backends/remove", json={
            "vip": VIP_PARAMS, "address": "10.0.0.100",
        })
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_drain_backend(self, client, mock_service):
        mock_service.vip_manager.get_vip.return_value = _make_vip()
        mock_service.real_manager.drain_real.return_value = True
        resp = await client.post("/api/v1/backends/drain", json={
            "vip": VIP_PARAMS, "address": "10.0.0.100",
        })
        assert resp.status_code == 200
        assert resp.json()["status"] == "drained"

    @pytest.mark.asyncio
    async def test_drain_backend_not_found(self, client, mock_service):
        mock_service.vip_manager.get_vip.return_value = _make_vip()
        mock_service.real_manager.drain_real.return_value = False
        resp = await client.post("/api/v1/backends/drain", json={
            "vip": VIP_PARAMS, "address": "10.0.0.100",
        })
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Service unavailable
# ---------------------------------------------------------------------------

class TestServiceUnavailable:
    @pytest.mark.asyncio
    async def test_503_when_service_down(self):
        svc = MagicMock()
        type(svc).is_running = PropertyMock(return_value=False)
        app = create_app(svc)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.get("/api/v1/vips")
            assert resp.status_code == 503
