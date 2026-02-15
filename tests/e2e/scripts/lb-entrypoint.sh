#!/bin/bash
#
# Load balancer entrypoint for E2E tests.
#
# 1. Load XDP program onto eth0
# 2. Pin BPF maps to /sys/fs/bpf/katran/
# 3. Write gateway MAC to ctl_array[0]
# 4. Start the control plane API server
#
set -e

BPF_PROGRAM="${KATRAN_BPF_PATH:-/app/katran-bpfs}/balancer.bpf.o"
PIN_PATH="${KATRAN_PIN_PATH:-/sys/fs/bpf/katran}"
INTERFACE="${KATRAN_INTERFACE:-eth0}"

echo "=== Katran LB Entrypoint ==="
echo "  BPF program: $BPF_PROGRAM"
echo "  Pin path:    $PIN_PATH"
echo "  Interface:   $INTERFACE"

# Ensure bpf filesystem is mounted
if ! mountpoint -q /sys/fs/bpf 2>/dev/null; then
    echo "Mounting bpffs..."
    mkdir -p /sys/fs/bpf
    mount -t bpf bpf /sys/fs/bpf
fi

# Disable reverse path filtering (needed for IPIP return traffic)
sysctl -w net.ipv4.conf.all.rp_filter=0 2>/dev/null || true
sysctl -w net.ipv4.conf.default.rp_filter=0 2>/dev/null || true
sysctl -w net.ipv4.conf.eth0.rp_filter=0 2>/dev/null || true

# Enable IPv6 forwarding
sysctl -w net.ipv6.conf.all.forwarding=1 2>/dev/null || true
sysctl -w net.ipv6.conf.eth0.forwarding=1 2>/dev/null || true

# Clean up any previous state
xdp-loader unload "$INTERFACE" --all 2>/dev/null || true
rm -rf "$PIN_PATH" 2>/dev/null || true
mkdir -p "$PIN_PATH"

# Load XDP program in SKB mode (Docker veth doesn't support native)
echo "Loading XDP program..."
xdp-loader load -m skb "$INTERFACE" "$BPF_PROGRAM"
sleep 2

# Pin BPF maps to filesystem.
# IMPORTANT: There may be stale maps from previous XDP loads on the shared
# host bpffs.  We must pin the maps owned by the CURRENT XDP program, not
# just the first match by name.  Get the program's map_ids and cross-reference.
echo "Pinning BPF maps..."

PROG_ID=$(bpftool prog list | grep "name balancer_ingress" | tail -1 | cut -d: -f1)
if [ -n "$PROG_ID" ]; then
    # Extract map_ids from the program (comma-separated list)
    PROG_MAP_IDS=$(bpftool prog show id "$PROG_ID" | grep map_ids | sed 's/.*map_ids //' | tr ',' ' ')
    echo "  XDP program $PROG_ID uses maps: $PROG_MAP_IDS"

    for map_name in vip_map reals ch_rings stats ctl_array fallback_cache; do
        # Find the map ID that belongs to this program
        map_id=""
        for candidate in $(bpftool map list | grep -w "name $map_name" | cut -d: -f1); do
            for prog_mid in $PROG_MAP_IDS; do
                if [ "$candidate" = "$prog_mid" ]; then
                    map_id="$candidate"
                    break 2
                fi
            done
        done

        if [ -n "$map_id" ]; then
            bpftool map pin id "$map_id" "${PIN_PATH}/${map_name}" 2>/dev/null || true
            echo "  Pinned: $map_name (id=$map_id)"
        else
            echo "  Skip:   $map_name (not found in program's maps)"
        fi
    done
else
    echo "  WARNING: balancer_ingress program not found, falling back to name match"
    for map_name in vip_map reals ch_rings stats ctl_array fallback_cache; do
        map_id=$(bpftool map list | grep -w "name $map_name" | tail -1 | cut -d: -f1)
        if [ -n "$map_id" ]; then
            bpftool map pin id "$map_id" "${PIN_PATH}/${map_name}" 2>/dev/null || true
            echo "  Pinned: $map_name (id=$map_id)"
        fi
    done
fi

echo "Pinned maps: $(ls "$PIN_PATH" | tr '\n' ' ')"

# Discover and write gateway MAC to ctl_array[0]
# The XDP program reads ctl_array[0] to get the destination MAC for XDP_TX
echo "Discovering gateway MAC..."

# Wait for ARP to populate
GW_IP=$(ip route | awk '/default/{print $3}')
if [ -z "$GW_IP" ]; then
    # No default route — use the subnet gateway (Docker bridge)
    GW_IP="10.200.0.1"
fi

# Ping the gateway to populate ARP cache
ping -c 2 -W 1 "$GW_IP" > /dev/null 2>&1 || true
sleep 1

GW_MAC=$(ip neigh show "$GW_IP" 2>/dev/null | awk '{print $5}' | head -1)
if [ -z "$GW_MAC" ] || [ "$GW_MAC" = "FAILED" ]; then
    # Fallback: try the interface's neighbor
    GW_MAC=$(ip neigh show dev "$INTERFACE" 2>/dev/null | head -1 | awk '{print $5}')
fi

if [ -n "$GW_MAC" ] && [ "$GW_MAC" != "FAILED" ]; then
    echo "  Gateway: $GW_IP -> $GW_MAC"

    # Convert MAC to bytes for bpftool: aa:bb:cc:dd:ee:ff -> 0xaa 0xbb ...
    MAC_BYTES=$(echo "$GW_MAC" | tr ':' ' ' | awk '{for(i=1;i<=NF;i++) printf "0x%s ", $i}')

    # ctl_array key=0 (4 bytes LE), value is mac_addr struct (6 bytes mac)
    CTL_MAP_PATH="${PIN_PATH}/ctl_array"
    if [ -f "$CTL_MAP_PATH" ]; then
        # key=0 (u32 LE) = 0x00 0x00 0x00 0x00
        # value = 6 bytes MAC
        bpftool map update pinned "$CTL_MAP_PATH" \
            key 0x00 0x00 0x00 0x00 \
            value $MAC_BYTES 0x00 0x00 2>/dev/null || \
        echo "  Warning: Could not write gateway MAC to ctl_array"
    else
        echo "  Warning: ctl_array not pinned, skipping MAC write"
    fi
else
    echo "  Warning: Could not discover gateway MAC (ARP not populated)"
fi

echo ""
echo "=== Starting control plane API ==="
exec python3 /app/tests/e2e/scripts/run_control_plane.py
