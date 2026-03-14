"""
FastAPI application factory for Katran control plane REST API.

Production-ready HTTP API using only GET/POST methods. IPs are passed in request
bodies or query params (never in URL path segments), making the API safe for IPv6
addresses with colons.
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, generate_latest
from pydantic import BaseModel, Field

from katran.core.constants import Protocol
from katran.core.exceptions import (
    KatranError,
    RealExistsError,
    ResourceExhaustedError,
    VipExistsError,
)
from katran.core.logging import get_logger
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


def _lookup_vip(svc, address: str, port: int, protocol: Protocol):
    """Get a VIP or raise 404."""
    vip = svc.vip_manager.get_vip(address=address, port=port, protocol=protocol)
    if vip is None:
        raise HTTPException(
            status_code=404,
            detail=f"VIP not found: {address}:{port}/{protocol.name.lower()}",
        )
    return vip


# ---------------------------------------------------------------------------
# Dependency
# ---------------------------------------------------------------------------


def get_service(request: Request):
    """FastAPI dependency that returns the KatranService or raises 503."""
    service = request.app.state.service
    if service is None or not service.is_running:
        raise HTTPException(status_code=503, detail="Service unavailable")
    return service


# ---------------------------------------------------------------------------
# Global exception handler
# ---------------------------------------------------------------------------

_KATRAN_ERROR_STATUS = {
    VipExistsError: 409,
    RealExistsError: 409,
    ResourceExhaustedError: 507,
}


def _katran_error_handler(request: Request, exc: KatranError) -> JSONResponse:
    for err_cls, status in _KATRAN_ERROR_STATUS.items():
        if isinstance(exc, err_cls):
            return JSONResponse(status_code=status, content={"detail": str(exc)})
    return JSONResponse(status_code=500, content={"detail": str(exc)})


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def create_app(service=None) -> FastAPI:
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

            def _metrics_handler():
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
    def health():
        svc = app.state.service
        if svc is None or not svc.is_running:
            raise HTTPException(status_code=503, detail="Service not running")
        return {"status": "healthy"}

    # --- VIP endpoints ----------------------------------------------------

    @app.post("/api/v1/vips", status_code=201, response_model=VipResponse)
    def add_vip(req: AddVipRequest, svc=Depends(get_service)):
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
        svc=Depends(get_service),
    ):
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

        # Single VIP lookup
        proto = _parse_protocol(protocol)
        vip = svc.vip_manager.get_vip(address=address, port=port, protocol=proto)
        if vip is None:
            raise HTTPException(
                status_code=404,
                detail=f"VIP not found: {address}:{port}/{protocol}",
            )
        return _vip_to_response(vip)

    @app.post("/api/v1/vips/remove")
    def remove_vip(req: VipId, svc=Depends(get_service)):
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
    def add_backend(req: AddBackendRequest, svc=Depends(get_service)):
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
    def remove_backend(req: BackendId, svc=Depends(get_service)):
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
    def drain_backend(req: BackendId, svc=Depends(get_service)):
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

    return app
