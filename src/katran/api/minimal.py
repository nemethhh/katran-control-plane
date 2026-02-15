"""
Minimal FastAPI HTTP API for Katran control plane E2E testing.

Provides VIP and backend CRUD endpoints backed by VipManager/RealManager.
"""

from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel

from katran.core.constants import Protocol
from katran.core.exceptions import (
    RealExistsError,
    VipExistsError,
)


# ---------------------------------------------------------------------------
# Request / Response Models
# ---------------------------------------------------------------------------

class AddVipRequest(BaseModel):
    address: str
    port: int
    protocol: str
    flags: int = 0


class AddRealRequest(BaseModel):
    address: str
    weight: int = 100


class DrainRequest(BaseModel):
    pass


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
        raise HTTPException(status_code=400, detail=f"Invalid protocol: {proto_str}")


def _vip_to_response(vip: Any) -> VipResponse:
    return VipResponse(
        address=str(vip.key.address),
        port=vip.key.port,
        protocol=vip.key.protocol.name.lower(),
        flags=int(vip.flags),
        vip_num=vip.vip_num,
        backends=[
            RealResponse(address=str(r.address), weight=r.weight, index=r.index)
            for r in vip.reals
        ],
    )


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
# App factory
# ---------------------------------------------------------------------------

def create_app(service=None) -> FastAPI:
    """Create the FastAPI application."""
    app = FastAPI(title="Katran Control Plane", version="0.1.0")
    app.state.service = service

    # --- Health -----------------------------------------------------------

    @app.get("/health")
    def health():
        svc = app.state.service
        if svc is None or not svc.is_running:
            raise HTTPException(status_code=503, detail="Service not running")
        return {"status": "healthy"}

    # --- VIP CRUD ---------------------------------------------------------

    @app.post("/api/v1/vips", status_code=201, response_model=VipResponse)
    def add_vip(req: AddVipRequest, svc=Depends(get_service)):
        proto = _parse_protocol(req.protocol)
        try:
            vip = svc.vip_manager.add_vip(
                address=req.address,
                port=req.port,
                protocol=proto,
                flags=req.flags,
            )
        except VipExistsError as e:
            raise HTTPException(status_code=409, detail=str(e))
        return _vip_to_response(vip)

    @app.get("/api/v1/vips", response_model=list[VipResponse])
    def list_vips(svc=Depends(get_service)):
        return [_vip_to_response(v) for v in svc.vip_manager.list_vips()]

    @app.get("/api/v1/vips/{addr}/{port}/{proto}", response_model=VipResponse)
    def get_vip(addr: str, port: int, proto: str, svc=Depends(get_service)):
        protocol = _parse_protocol(proto)
        vip = svc.vip_manager.get_vip(address=addr, port=port, protocol=protocol)
        if vip is None:
            raise HTTPException(status_code=404, detail=f"VIP not found: {addr}:{port}/{proto}")
        return _vip_to_response(vip)

    @app.delete("/api/v1/vips/{addr}/{port}/{proto}", status_code=200)
    def remove_vip(addr: str, port: int, proto: str, svc=Depends(get_service)):
        protocol = _parse_protocol(proto)
        removed = svc.vip_manager.remove_vip(address=addr, port=port, protocol=protocol)
        if not removed:
            raise HTTPException(status_code=404, detail=f"VIP not found: {addr}:{port}/{proto}")
        return {"status": "removed"}

    # --- Backend CRUD -----------------------------------------------------

    @app.post(
        "/api/v1/vips/{addr}/{port}/{proto}/backends",
        status_code=201,
        response_model=RealResponse,
    )
    def add_backend(
        addr: str,
        port: int,
        proto: str,
        req: AddRealRequest,
        svc=Depends(get_service),
    ):
        protocol = _parse_protocol(proto)
        vip = svc.vip_manager.get_vip(address=addr, port=port, protocol=protocol)
        if vip is None:
            raise HTTPException(
                status_code=404, detail=f"VIP not found: {addr}:{port}/{proto}"
            )
        try:
            real = svc.real_manager.add_real(vip, address=req.address, weight=req.weight)
        except RealExistsError as e:
            raise HTTPException(status_code=409, detail=str(e))
        return RealResponse(address=str(real.address), weight=real.weight, index=real.index)

    @app.delete(
        "/api/v1/vips/{addr}/{port}/{proto}/backends/{backend_addr}",
        status_code=200,
    )
    def remove_backend(
        addr: str,
        port: int,
        proto: str,
        backend_addr: str,
        svc=Depends(get_service),
    ):
        protocol = _parse_protocol(proto)
        vip = svc.vip_manager.get_vip(address=addr, port=port, protocol=protocol)
        if vip is None:
            raise HTTPException(
                status_code=404, detail=f"VIP not found: {addr}:{port}/{proto}"
            )
        removed = svc.real_manager.remove_real(vip, address=backend_addr)
        if not removed:
            raise HTTPException(status_code=404, detail=f"Backend {backend_addr} not found")
        return {"status": "removed"}

    @app.put(
        "/api/v1/vips/{addr}/{port}/{proto}/backends/{backend_addr}/drain",
        status_code=200,
    )
    def drain_backend(
        addr: str,
        port: int,
        proto: str,
        backend_addr: str,
        svc=Depends(get_service),
    ):
        protocol = _parse_protocol(proto)
        vip = svc.vip_manager.get_vip(address=addr, port=port, protocol=protocol)
        if vip is None:
            raise HTTPException(
                status_code=404, detail=f"VIP not found: {addr}:{port}/{proto}"
            )
        drained = svc.real_manager.drain_real(vip, address=backend_addr)
        if not drained:
            raise HTTPException(status_code=404, detail=f"Backend {backend_addr} not found")
        return {"status": "drained"}

    return app
