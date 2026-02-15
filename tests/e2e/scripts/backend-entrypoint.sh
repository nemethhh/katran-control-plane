#!/bin/bash
#
# Backend entrypoint for E2E tests.
#
# 1. Load IPIP kernel module
# 2. Configure tunl0 with VIP address for decapsulation
# 3. Disable rp_filter (required for DSR)
# 4. Start HTTP server identifying this backend
#
set -e

BACKEND_NAME="${BACKEND_NAME:-backend}"
BACKEND_ADDR="${BACKEND_ADDR:-10.200.0.20}"
VIP_ADDR="${VIP_ADDR:-10.200.0.10}"
HTTP_PORT="${HTTP_PORT:-80}"

echo "=== Backend Entrypoint: $BACKEND_NAME ==="
echo "  Backend addr: $BACKEND_ADDR"
echo "  VIP addr:     $VIP_ADDR"
echo "  HTTP port:    $HTTP_PORT"

# Load IPIP module
modprobe ipip 2>/dev/null || true

# Bring up tunnel interface
ip link set tunl0 up 2>/dev/null || true

# Add VIP address to tunl0 so kernel accepts decapsulated packets
# (inner dst = VIP_ADDR, which must be a local address)
ip addr add "${VIP_ADDR}/32" dev tunl0 2>/dev/null || true

# Disable reverse path filtering (otherwise kernel drops IPIP packets
# because the source doesn't match the expected interface)
sysctl -w net.ipv4.conf.all.rp_filter=0 > /dev/null 2>&1
sysctl -w net.ipv4.conf.default.rp_filter=0 > /dev/null 2>&1
sysctl -w net.ipv4.conf.tunl0.rp_filter=0 > /dev/null 2>&1
sysctl -w net.ipv4.conf.eth0.rp_filter=0 > /dev/null 2>&1

# Prevent ARP flux: don't respond to ARP for VIP address on eth0.
# Without this, the backend steals ARP entries from the LB since
# the VIP is on tunl0 but Linux answers ARP on all interfaces by default.
sysctl -w net.ipv4.conf.all.arp_ignore=1 > /dev/null 2>&1
sysctl -w net.ipv4.conf.all.arp_announce=2 > /dev/null 2>&1

echo "  tunl0 addresses: $(ip addr show tunl0 | grep inet | awk '{print $2}')"
echo ""
echo "=== Starting HTTP server on port $HTTP_PORT ==="
exec python3 /app/scripts/backend-server.py
