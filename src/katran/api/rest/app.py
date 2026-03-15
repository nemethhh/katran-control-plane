"""
FastAPI application factory for Katran control plane REST API.

Production-ready HTTP API using only GET/POST methods. IPs are passed in request
bodies or query params (never in URL path segments), making the API safe for IPv6
addresses with colons.
"""

from __future__ import annotations

import dataclasses
from ipaddress import ip_address
from typing import Any, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, generate_latest
from pydantic import BaseModel, Field

from katran.core.constants import KatranFeature, ModifyAction, Protocol
from katran.core.exceptions import (
    DecapError,
    FeatureNotEnabledError,
    HealthCheckError,
    KatranError,
    QuicMappingError,
    RealExistsError,
    ResourceExhaustedError,
    SrcRoutingError,
    VipExistsError,
)
from katran.core.logging import get_logger
from katran.core.types import QuicReal, VipKey
from katran.stats.collector import KatranMetricsCollector

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Request / Response Models
# ---------------------------------------------------------------------------


class VipId(BaseModel):
    address: str
    port: int = Field(ge=0, le=65535)
    protocol: str  # "tcp" or "udp"


class AddVipRequest(VipId):
    flags: int = 0


class BackendId(BaseModel):
    vip: VipId
    address: str


class AddBackendRequest(BackendId):
    weight: int = 100


class StatusResponse(BaseModel):
    status: str


class RealResponse(BaseModel):
    address: str
    weight: int
    index: int


class VipResponse(BaseModel):
    address: str
    port: int
    protocol: str
    flags: int
    vip_num: int
    backends: list[RealResponse]


class ErrorResponse(BaseModel):
    detail: str


class SrcRoutingRequest(BaseModel):
    srcs: list[str]
    dst: str


class AddressRequest(BaseModel):
    address: str


class HcDstRequest(BaseModel):
    somark: int
    dst: str


class HcKeyRequest(BaseModel):
    address: str
    port: int
    protocol: str


class HcMacRequest(BaseModel):
    mac: str


class HcInterfaceRequest(BaseModel):
    ifindex: int


class QuicRealModel(BaseModel):
    address: str
    id: int


class QuicMappingRequest(BaseModel):
    action: str
    mappings: list[QuicRealModel]


class QuicInvalidateRequest(BaseModel):
    server_ids: list[int]


class QuicRevalidateRequest(BaseModel):
    mappings: list[QuicRealModel]


class DownRealRequest(BaseModel):
    vip: VipId
    real_index: int


class SomarkRequest(BaseModel):
    somark: int


class LruSearchRequest(BaseModel):
    vip: VipId
    src_ip: str
    src_port: int


class LruListRequest(BaseModel):
    vip: VipId
    limit: int = 100


class LruPurgeRealRequest(BaseModel):
    vip: VipId
    real_index: int


class LruDeleteRequest(BaseModel):
    vip: VipId
    src_ip: str
    src_port: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_protocol(proto_str: str) -> Protocol:
    """Parse protocol string to Protocol enum."""
    try:
        return Protocol[proto_str.upper()]
    except KeyError:
        raise HTTPException(status_code=400, detail=f"Invalid protocol: {proto_str}") from None


def _vip_to_response(vip: Any) -> VipResponse:
    return VipResponse(
        address=str(vip.key.address),
        port=vip.key.port,
        protocol=vip.key.protocol.name.lower(),
        flags=int(vip.flags),
        vip_num=vip.vip_num,
        backends=[
            RealResponse(address=str(r.address), weight=r.weight, index=r.index) for r in vip.reals
        ],
    )


def _lookup_vip(svc: Any, address: str, port: int, protocol: Protocol) -> Any:
    """Get a VIP or raise 404."""
    vip = svc.vip_manager.get_vip(address=address, port=port, protocol=protocol)
    if vip is None:
        raise HTTPException(
            status_code=404,
            detail=f"VIP not found: {address}:{port}/{protocol.name.lower()}",
        )
    return vip


def _make_vip_key(vip_id: VipId) -> VipKey:
    """Convert a VipId request model into a VipKey."""
    return VipKey(
        address=ip_address(vip_id.address),
        port=vip_id.port,
        protocol=_parse_protocol(vip_id.protocol),
    )


# ---------------------------------------------------------------------------
# Dependency
# ---------------------------------------------------------------------------


def get_service(request: Request) -> Any:
    """FastAPI dependency that returns the KatranService or raises 503."""
    service = request.app.state.service
    if service is None or not service.is_running:
        raise HTTPException(status_code=503, detail="Service unavailable")
    return service


# ---------------------------------------------------------------------------
# Global exception handler
# ---------------------------------------------------------------------------

_KATRAN_ERROR_STATUS: dict[type, int] = {
    VipExistsError: 409,
    RealExistsError: 409,
    ResourceExhaustedError: 507,
    FeatureNotEnabledError: 400,
    HealthCheckError: 400,
    SrcRoutingError: 400,
    QuicMappingError: 400,
    DecapError: 400,
}


def _katran_error_handler(request: Request, exc: Exception) -> JSONResponse:
    for err_cls, status in _KATRAN_ERROR_STATUS.items():
        if isinstance(exc, err_cls):
            return JSONResponse(status_code=status, content={"detail": str(exc)})
    return JSONResponse(status_code=500, content={"detail": str(exc)})


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def create_app(service: Any = None) -> FastAPI:
    """Create the FastAPI application."""
    app = FastAPI(title="Katran Control Plane", version="0.1.0")
    app.state.service = service
    app.add_exception_handler(KatranError, _katran_error_handler)

    # Prometheus metrics endpoint — uses a direct FastAPI route instead of
    # make_asgi_app() sub-application.  The ASGI sub-app approach bypasses
    # FastAPI's exception handling; an unhandled error during BPF map reads
    # can crash the Uvicorn event loop and kill the container.
    if service is not None:
        try:
            registry = CollectorRegistry()
            registry.register(KatranMetricsCollector(service))

            def _metrics_handler() -> Response:
                try:
                    output = generate_latest(registry)
                    return Response(content=output, media_type=CONTENT_TYPE_LATEST)
                except Exception:
                    log.error("Failed to generate metrics", exc_info=True)
                    return Response(
                        content=b"# katran_up 0\n",
                        media_type=CONTENT_TYPE_LATEST,
                        status_code=500,
                    )

            app.add_api_route("/metrics", _metrics_handler, methods=["GET"])
            app.add_api_route("/metrics/", _metrics_handler, methods=["GET"])
            log.info("Registered Prometheus metrics endpoint at /metrics")
        except Exception:
            log.error("Failed to register metrics endpoint", exc_info=True)

    # --- Health -----------------------------------------------------------

    @app.get("/health")
    def health() -> dict[str, str]:
        svc = app.state.service
        if svc is None or not svc.is_running:
            raise HTTPException(status_code=503, detail="Service not running")
        return {"status": "healthy"}

    # --- VIP endpoints ----------------------------------------------------

    @app.post("/api/v1/vips", status_code=201, response_model=VipResponse)
    def add_vip(req: AddVipRequest, svc: Any = Depends(get_service)) -> VipResponse:
        proto = _parse_protocol(req.protocol)
        vip = svc.vip_manager.add_vip(
            address=req.address,
            port=req.port,
            protocol=proto,
            flags=req.flags,
        )
        log.info("Added VIP %s:%d/%s", req.address, req.port, req.protocol)
        return _vip_to_response(vip)

    @app.get("/api/v1/vips")
    def get_vips(
        address: Optional[str] = Query(None),
        port: Optional[int] = Query(None),
        protocol: Optional[str] = Query(None),
        svc: Any = Depends(get_service),
    ) -> Any:
        params = [address, port, protocol]
        provided = sum(p is not None for p in params)

        if provided == 0:
            # List all VIPs
            return [_vip_to_response(v) for v in svc.vip_manager.list_vips()]

        if provided != 3:
            raise HTTPException(
                status_code=400,
                detail="Provide all of address, port, protocol — or none",
            )

        # Single VIP lookup — all three are non-None at this point
        proto = _parse_protocol(protocol or "")
        vip = svc.vip_manager.get_vip(address=address, port=port, protocol=proto)
        if vip is None:
            raise HTTPException(
                status_code=404,
                detail=f"VIP not found: {address}:{port}/{protocol}",
            )
        return _vip_to_response(vip)

    @app.post("/api/v1/vips/remove")
    def remove_vip(req: VipId, svc: Any = Depends(get_service)) -> dict[str, str]:
        proto = _parse_protocol(req.protocol)
        removed = svc.vip_manager.remove_vip(
            address=req.address,
            port=req.port,
            protocol=proto,
        )
        if not removed:
            raise HTTPException(
                status_code=404,
                detail=f"VIP not found: {req.address}:{req.port}/{req.protocol}",
            )
        log.info("Removed VIP %s:%d/%s", req.address, req.port, req.protocol)
        return {"status": "removed"}

    # --- Backend endpoints ------------------------------------------------

    @app.post("/api/v1/backends/add", status_code=201, response_model=RealResponse)
    def add_backend(req: AddBackendRequest, svc: Any = Depends(get_service)) -> RealResponse:
        proto = _parse_protocol(req.vip.protocol)
        vip = _lookup_vip(svc, req.vip.address, req.vip.port, proto)
        real = svc.real_manager.add_real(vip, address=req.address, weight=req.weight)
        log.info(
            "Added backend %s to VIP %s:%d/%s",
            req.address,
            req.vip.address,
            req.vip.port,
            req.vip.protocol,
        )
        return RealResponse(address=str(real.address), weight=real.weight, index=real.index)

    @app.post("/api/v1/backends/remove")
    def remove_backend(req: BackendId, svc: Any = Depends(get_service)) -> dict[str, str]:
        proto = _parse_protocol(req.vip.protocol)
        vip = _lookup_vip(svc, req.vip.address, req.vip.port, proto)
        removed = svc.real_manager.remove_real(vip, address=req.address)
        if not removed:
            raise HTTPException(status_code=404, detail=f"Backend {req.address} not found")
        log.info(
            "Removed backend %s from VIP %s:%d/%s",
            req.address,
            req.vip.address,
            req.vip.port,
            req.vip.protocol,
        )
        return {"status": "removed"}

    @app.post("/api/v1/backends/drain")
    def drain_backend(req: BackendId, svc: Any = Depends(get_service)) -> dict[str, str]:
        proto = _parse_protocol(req.vip.protocol)
        vip = _lookup_vip(svc, req.vip.address, req.vip.port, proto)
        drained = svc.real_manager.drain_real(vip, address=req.address)
        if not drained:
            raise HTTPException(status_code=404, detail=f"Backend {req.address} not found")
        log.info(
            "Drained backend %s from VIP %s:%d/%s",
            req.address,
            req.vip.address,
            req.vip.port,
            req.vip.protocol,
        )
        return {"status": "drained"}

    # --- Source routing endpoints ------------------------------------------

    @app.post("/api/v1/src-routing/add")
    def add_src_routing(
        req: SrcRoutingRequest, svc: Any = Depends(get_service)
    ) -> dict[str, int]:
        failures = svc.add_src_routing_rules(srcs=req.srcs, dst=req.dst)
        return {"failures": failures}

    @app.get("/api/v1/src-routing")
    def get_src_routing(svc: Any = Depends(get_service)) -> dict[str, str]:
        return svc.get_src_routing_rules()

    @app.post("/api/v1/src-routing/remove")
    def remove_src_routing(
        req: SrcRoutingRequest, svc: Any = Depends(get_service)
    ) -> dict[str, str]:
        svc.del_src_routing_rules(srcs=req.srcs)
        return {"status": "removed"}

    @app.post("/api/v1/src-routing/clear")
    def clear_src_routing(svc: Any = Depends(get_service)) -> dict[str, str]:
        svc.clear_src_routing_rules()
        return {"status": "cleared"}

    # --- Decap endpoints --------------------------------------------------

    @app.post("/api/v1/decap/dst/add")
    def add_decap_dst(
        req: AddressRequest, svc: Any = Depends(get_service)
    ) -> dict[str, str]:
        svc.add_decap_dst(dst=req.address)
        return {"status": "added"}

    @app.post("/api/v1/decap/dst/remove")
    def remove_decap_dst(
        req: AddressRequest, svc: Any = Depends(get_service)
    ) -> dict[str, str]:
        svc.del_decap_dst(dst=req.address)
        return {"status": "removed"}

    @app.get("/api/v1/decap/dst")
    def get_decap_dsts(svc: Any = Depends(get_service)) -> list[str]:
        return svc.get_decap_dsts()

    # --- QUIC endpoints ---------------------------------------------------

    @app.post("/api/v1/quic/mapping")
    def modify_quic_mapping(
        req: QuicMappingRequest, svc: Any = Depends(get_service)
    ) -> dict[str, int]:
        action = ModifyAction(req.action)
        quic_reals = [QuicReal(address=m.address, id=m.id) for m in req.mappings]
        failures = svc.modify_quic_mapping(action=action, quic_reals=quic_reals)
        return {"failures": failures}

    @app.get("/api/v1/quic/mapping")
    def get_quic_mapping(svc: Any = Depends(get_service)) -> list[dict[str, Any]]:
        mapping = svc.get_quic_mapping()
        return [{"address": qr.address, "id": qr.id} for qr in mapping]

    @app.post("/api/v1/quic/invalidate")
    def invalidate_quic(
        req: QuicInvalidateRequest, svc: Any = Depends(get_service)
    ) -> dict[str, str]:
        svc.invalidate_quic_server_ids(server_ids=req.server_ids)
        return {"status": "invalidated"}

    @app.post("/api/v1/quic/revalidate")
    def revalidate_quic(
        req: QuicRevalidateRequest, svc: Any = Depends(get_service)
    ) -> dict[str, str]:
        quic_reals = [QuicReal(address=m.address, id=m.id) for m in req.mappings]
        svc.revalidate_quic_server_ids(quic_reals=quic_reals)
        return {"status": "revalidated"}

    # --- Health check endpoints -------------------------------------------

    @app.post("/api/v1/hc/dst/add")
    def add_hc_dst(
        req: HcDstRequest, svc: Any = Depends(get_service)
    ) -> dict[str, str]:
        svc.add_hc_dst(somark=req.somark, dst=req.dst)
        return {"status": "added"}

    @app.post("/api/v1/hc/dst/remove")
    def remove_hc_dst(
        req: SomarkRequest, svc: Any = Depends(get_service)
    ) -> dict[str, str]:
        svc.del_hc_dst(somark=req.somark)
        return {"status": "removed"}

    @app.get("/api/v1/hc/dst")
    def get_hc_dsts(svc: Any = Depends(get_service)) -> dict[int, str]:
        return svc.get_hc_dsts()

    @app.post("/api/v1/hc/key/add")
    def add_hc_key(
        req: HcKeyRequest, svc: Any = Depends(get_service)
    ) -> dict[str, int]:
        key = VipKey(
            address=ip_address(req.address),
            port=req.port,
            protocol=_parse_protocol(req.protocol),
        )
        index = svc.add_hc_key(key=key)
        return {"index": index}

    @app.post("/api/v1/hc/key/remove")
    def remove_hc_key(
        req: HcKeyRequest, svc: Any = Depends(get_service)
    ) -> dict[str, str]:
        key = VipKey(
            address=ip_address(req.address),
            port=req.port,
            protocol=_parse_protocol(req.protocol),
        )
        svc.del_hc_key(key=key)
        return {"status": "removed"}

    @app.get("/api/v1/hc/keys")
    def get_hc_keys(svc: Any = Depends(get_service)) -> list[dict[str, Any]]:
        keys = svc.get_hc_keys()
        return [
            {
                "address": str(k.address),
                "port": k.port,
                "protocol": k.protocol.name.lower(),
                "index": idx,
            }
            for k, idx in keys.items()
        ]

    @app.post("/api/v1/hc/src-ip")
    def set_hc_src_ip(
        req: AddressRequest, svc: Any = Depends(get_service)
    ) -> dict[str, str]:
        svc.set_hc_src_ip(address=req.address)
        return {"status": "set"}

    @app.post("/api/v1/hc/src-mac")
    def set_hc_src_mac(
        req: HcMacRequest, svc: Any = Depends(get_service)
    ) -> dict[str, str]:
        svc.set_hc_src_mac(mac=req.mac)
        return {"status": "set"}

    @app.post("/api/v1/hc/dst-mac")
    def set_hc_dst_mac(
        req: HcMacRequest, svc: Any = Depends(get_service)
    ) -> dict[str, str]:
        svc.set_hc_dst_mac(mac=req.mac)
        return {"status": "set"}

    @app.post("/api/v1/hc/interface")
    def set_hc_interface(
        req: HcInterfaceRequest, svc: Any = Depends(get_service)
    ) -> dict[str, str]:
        svc.set_hc_interface(ifindex=req.ifindex)
        return {"status": "set"}

    @app.get("/api/v1/hc/stats")
    def get_hc_stats(svc: Any = Depends(get_service)) -> dict[str, int]:
        stats = svc.get_hc_stats()
        return dataclasses.asdict(stats)

    @app.get("/api/v1/hc/stats/key")
    def get_hc_stats_key(
        address: str = Query(...),
        port: int = Query(...),
        protocol: str = Query(...),
        svc: Any = Depends(get_service),
    ) -> dict[str, int]:
        key = VipKey(
            address=ip_address(address),
            port=port,
            protocol=_parse_protocol(protocol),
        )
        packets = svc.get_packets_for_hc_key(key=key)
        return {"packets": packets}

    # --- Stats endpoints --------------------------------------------------

    @app.get("/api/v1/stats/vip")
    def get_vip_stats(
        address: str = Query(...),
        port: int = Query(...),
        protocol: str = Query(...),
        svc: Any = Depends(get_service),
    ) -> dict[str, int]:
        proto = _parse_protocol(protocol)
        vip = _lookup_vip(svc, address, port, proto)
        stats = svc.get_vip_stats(vip_num=vip.vip_num)
        return {"packets": stats.v1, "bytes": stats.v2}

    @app.get("/api/v1/stats/real")
    def get_real_stats(
        index: int = Query(...),
        svc: Any = Depends(get_service),
    ) -> dict[str, int]:
        stats = svc.get_real_stats(real_index=index)
        return {"packets": stats.v1, "bytes": stats.v2}

    @app.get("/api/v1/stats/global")
    def get_global_stats(svc: Any = Depends(get_service)) -> dict[str, Any]:
        return svc.get_all_global_stats()

    @app.get("/api/v1/stats/quic")
    def get_quic_stats(svc: Any = Depends(get_service)) -> dict[str, int]:
        stats = svc.get_quic_packet_stats()
        return dataclasses.asdict(stats)

    @app.get("/api/v1/stats/hc")
    def get_hc_program_stats(svc: Any = Depends(get_service)) -> dict[str, int]:
        stats = svc.get_hc_program_stats()
        return dataclasses.asdict(stats)

    @app.get("/api/v1/stats/per-cpu")
    def get_per_cpu_stats(svc: Any = Depends(get_service)) -> list[int]:
        return svc.get_per_core_packets_stats()

    # --- Features endpoint ------------------------------------------------

    @app.get("/api/v1/features")
    def get_features(svc: Any = Depends(get_service)) -> dict[str, Any]:
        flags = svc.config.features
        enabled = [f.name for f in KatranFeature if svc.has_feature(f)]
        return {"flags": flags, "enabled": enabled}

    # --- Encap endpoints --------------------------------------------------

    @app.post("/api/v1/encap/src-ip")
    def set_encap_src_ip(
        req: AddressRequest, svc: Any = Depends(get_service)
    ) -> dict[str, str]:
        svc.set_src_ip_for_encap(address=req.address)
        return {"status": "set"}

    # --- LRU endpoints ----------------------------------------------------

    @app.post("/api/v1/lru/search")
    def lru_search(
        req: LruSearchRequest, svc: Any = Depends(get_service)
    ) -> dict[str, Any]:
        vip_key = _make_vip_key(req.vip)
        result = svc.lru_search(vip_key=vip_key, src_ip=req.src_ip, src_port=req.src_port)
        return {"entries": len(result.entries), "error": result.error}

    @app.post("/api/v1/lru/list")
    def lru_list(
        req: LruListRequest, svc: Any = Depends(get_service)
    ) -> dict[str, Any]:
        vip_key = _make_vip_key(req.vip)
        result = svc.lru_list(vip_key=vip_key, limit=req.limit)
        return {"entries": len(result.entries), "error": result.error}

    @app.post("/api/v1/lru/delete")
    def lru_delete(
        req: LruDeleteRequest, svc: Any = Depends(get_service)
    ) -> dict[str, list[str]]:
        vip_key = _make_vip_key(req.vip)
        deleted = svc.lru_delete(vip_key=vip_key, src_ip=req.src_ip, src_port=req.src_port)
        return {"deleted": deleted}

    @app.post("/api/v1/lru/purge-vip")
    def lru_purge_vip(
        req: LruListRequest, svc: Any = Depends(get_service)
    ) -> dict[str, int]:
        vip_key = _make_vip_key(req.vip)
        result = svc.lru_purge_vip(vip_key=vip_key)
        return {"deleted_count": result.deleted_count}

    @app.post("/api/v1/lru/purge-real")
    def lru_purge_real(
        req: LruPurgeRealRequest, svc: Any = Depends(get_service)
    ) -> dict[str, int]:
        vip_key = _make_vip_key(req.vip)
        result = svc.lru_purge_vip_for_real(vip_key=vip_key, real_index=req.real_index)
        return {"deleted_count": result.deleted_count}

    @app.get("/api/v1/lru/analyze")
    def lru_analyze(svc: Any = Depends(get_service)) -> dict[str, Any]:
        result = svc.lru_analyze()
        return {
            "total_entries": result.total_entries,
            "per_vip": {k: dataclasses.asdict(v) for k, v in result.per_vip.items()},
        }

    # --- Debug endpoints --------------------------------------------------

    @app.post("/debug/trigger-probe")
    async def trigger_probe(body: dict) -> dict[str, Any]:
        """Send a SO_MARK-tagged UDP packet to trigger TC-BPF HC probe rewriting.

        Only useful in E2E test environments where TC-BPF HC program is loaded.
        """
        import socket as _socket

        somark = int(body["somark"])
        dst_addr = str(body["dst"])
        dst_port = int(body.get("port", 9999))

        family = _socket.AF_INET6 if ":" in dst_addr else _socket.AF_INET
        sock = _socket.socket(family, _socket.SOCK_DGRAM)
        try:
            sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_MARK, somark)
            sock.sendto(b"hc-probe", (dst_addr, dst_port))
        finally:
            sock.close()

        return {"status": "sent", "somark": somark, "dst": dst_addr}

    # --- Down reals endpoints ---------------------------------------------

    @app.post("/api/v1/down-reals/add")
    def add_down_real(
        req: DownRealRequest, svc: Any = Depends(get_service)
    ) -> dict[str, str]:
        vip_key = _make_vip_key(req.vip)
        svc.add_down_real(vip_key=vip_key, real_index=req.real_index)
        return {"status": "added"}

    @app.post("/api/v1/down-reals/remove")
    def remove_down_real(
        req: DownRealRequest, svc: Any = Depends(get_service)
    ) -> dict[str, str]:
        vip_key = _make_vip_key(req.vip)
        svc.remove_down_real(vip_key=vip_key, real_index=req.real_index)
        return {"status": "removed"}

    @app.post("/api/v1/down-reals/remove-vip")
    def remove_down_reals_vip(
        req: VipId, svc: Any = Depends(get_service)
    ) -> dict[str, str]:
        vip_key = _make_vip_key(req)
        svc.remove_down_reals_vip(vip_key=vip_key)
        return {"status": "removed"}

    @app.post("/api/v1/down-reals/check")
    def check_down_real(
        req: DownRealRequest, svc: Any = Depends(get_service)
    ) -> dict[str, bool]:
        vip_key = _make_vip_key(req.vip)
        is_down = svc.check_down_real(vip_key=vip_key, real_index=req.real_index)
        return {"is_down": is_down}

    return app
