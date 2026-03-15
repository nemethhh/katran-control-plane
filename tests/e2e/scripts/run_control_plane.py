#!/usr/bin/env python3
"""Start the Katran control plane API server for E2E tests."""

import os

import uvicorn

from katran.api.rest import create_app
from katran.core.config import KatranConfig
from katran.service import KatranService


def main() -> None:
    pin_path = os.environ.get("KATRAN_PIN_PATH", "/sys/fs/bpf/katran")
    host = os.environ.get("KATRAN_API_HOST", "0.0.0.0")
    port = int(os.environ.get("KATRAN_API_PORT", "8080"))

    features_str = os.environ.get("KATRAN_FEATURES", "")
    feature_list = [f.strip() for f in features_str.split(",") if f.strip()]
    tunnel_based_hc = os.environ.get("KATRAN_TUNNEL_BASED_HC", "true").lower() == "true"

    config = KatranConfig.from_dict(
        {
            "bpf": {"pin_path": pin_path},
            "maps": {
                "max_vips": int(os.environ.get("KATRAN_MAX_VIPS", "512")),
                "max_reals": int(os.environ.get("KATRAN_MAX_REALS", "4096")),
                "ring_size": int(os.environ.get("KATRAN_RING_SIZE", "65537")),
                "lru_size": int(os.environ.get("KATRAN_LRU_SIZE", "1000")),
            },
            "features": feature_list,
            "tunnel_based_hc": tunnel_based_hc,
        }
    )

    service = KatranService(config)
    print(f"Starting Katran service (pin_path={pin_path})...", flush=True)
    service.start()
    print(f"Features enabled: {feature_list or '(none)'}", flush=True)
    print("Katran service started successfully", flush=True)

    app = create_app(service)

    print(f"Starting API server on {host}:{port}", flush=True)
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
