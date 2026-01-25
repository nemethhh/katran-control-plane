"""
Integration tests for Katran control plane with actual BPF programs.

These tests require:
- Root/CAP_BPF privileges
- BPF filesystem mounted at /sys/fs/bpf
- xdp-loader from xdp-tools package
- Katran BPF programs (.o files)

Run with Docker:
    docker-compose -f docker-compose.test.yml up --build integration-tests

Or manually with sudo:
    sudo pytest tests/integration/ -v
"""
