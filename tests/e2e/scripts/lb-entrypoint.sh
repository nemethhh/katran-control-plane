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

# Add extra VIP addresses to the interface so XDP sees traffic to these IPs
for vip in ${EXTRA_VIP_ADDRS:-}; do
    ip addr add "${vip}/32" dev "$INTERFACE" 2>/dev/null || true
done
for vip6 in ${EXTRA_VIP_ADDRS6:-}; do
    ip -6 addr add "${vip6}/128" dev "$INTERFACE" nodad 2>/dev/null || true
done

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
#
# BPF kernel map names are truncated to 15 chars (BPF_OBJ_NAME_LEN=16).
# We iterate program map IDs and match by kernel name, then pin with the
# Python-expected name (which may differ from the BPF variable name).
echo "Pinning BPF maps..."

# pin_prog_maps <prog_map_ids> <kernel_name:pin_name> ...
# Iterates the program's map IDs and pins maps whose kernel name matches.
pin_prog_maps() {
    local prog_ids="$1"; shift
    local all_maps
    all_maps=$(bpftool map list 2>/dev/null)

    for spec in "$@"; do
        local kname="${spec%%:*}"
        local pname="${spec##*:}"
        local map_id=""

        for candidate in $(echo "$all_maps" | grep -w "name $kname" | cut -d: -f1); do
            for mid in $prog_ids; do
                if [ "$candidate" = "$mid" ]; then
                    map_id="$candidate"
                    break 2
                fi
            done
        done

        if [ -n "$map_id" ]; then
            bpftool map pin id "$map_id" "${PIN_PATH}/${pname}" 2>/dev/null || true
            echo "  Pinned: $pname (id=$map_id)"
        fi
    done
}

PROG_ID=$(bpftool prog list | grep "name balancer_ingress" | tail -1 | cut -d: -f1)
if [ -n "$PROG_ID" ]; then
    # Extract map_ids from the program (comma-separated list)
    PROG_MAP_IDS=$(bpftool prog show id "$PROG_ID" | grep map_ids | sed 's/.*map_ids //' | tr ',' ' ')
    echo "  XDP program $PROG_ID uses maps: $PROG_MAP_IDS"

    # Core maps (names ≤15 chars, no truncation)
    pin_prog_maps "$PROG_MAP_IDS" \
        vip_map:vip_map reals:reals ch_rings:ch_rings stats:stats \
        ctl_array:ctl_array fallback_cache:fallback_cache

    # Verify required core maps
    for map in vip_map reals ch_rings stats ctl_array; do
        if [ ! -f "$PIN_PATH/$map" ]; then
            echo "  FATAL: Required map $map not pinned"
            exit 1
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

# --- Load HC TC-BPF program on egress ---
HC_PROGRAM="${KATRAN_BPF_PATH:-/app/katran-bpfs}/healthchecking.bpf.o"
if [ -f "$HC_PROGRAM" ]; then
    echo ""
    echo "=== Loading HC TC-BPF program ==="
    tc qdisc add dev "$INTERFACE" clsact 2>/dev/null || true
    if tc filter add dev "$INTERFACE" egress bpf direct-action obj "$HC_PROGRAM" sec tc 2>/dev/null; then
        echo "  HC program loaded on $INTERFACE egress"

        # Pin HC maps from TC program
        sleep 1
        HC_PROG_ID=$(tc filter show dev "$INTERFACE" egress | grep -oP 'id \K[0-9]+' | head -1)
        if [ -n "$HC_PROG_ID" ]; then
            HC_MAP_IDS=$(bpftool prog show id "$HC_PROG_ID" 2>/dev/null | grep map_ids | sed 's/.*map_ids //' | tr ',' ' ')
            echo "  HC program $HC_PROG_ID uses maps: $HC_MAP_IDS"

            # HC map names — hc_pckt_srcs_map (17 chars) truncated to hc_pckt_srcs_ma
            pin_prog_maps "$HC_MAP_IDS" \
                hc_key_map:hc_key_map \
                hc_reals_map:hc_reals_map \
                hc_ctrl_map:hc_ctrl_map \
                hc_pckt_srcs_ma:hc_pckt_srcs_map \
                hc_pckt_macs:hc_pckt_macs \
                hc_stats_map:hc_stats_map \
                per_hckey_stats:per_hckey_stats

            # Report missing HC maps
            for hc_map in hc_key_map hc_reals_map hc_ctrl_map hc_pckt_srcs_map \
                          hc_pckt_macs hc_stats_map per_hckey_stats; do
                if [ ! -f "$PIN_PATH/$hc_map" ]; then
                    echo "  Skip HC:   $hc_map (not found)"
                fi
            done
        else
            echo "  Warning: Could not find HC program ID for map pinning"
        fi
    else
        echo "  Warning: HC program failed to load (may not be available)"
    fi
else
    echo "  HC program not found at $HC_PROGRAM, skipping"
fi

# --- Pin additional XDP feature maps ---
echo ""
echo "=== Pinning XDP feature maps ==="
if [ -n "$PROG_ID" ]; then
    # Map names with kernel-truncated form where needed (>15 chars).
    # Format: kernel_name:pin_name
    pin_prog_maps "$PROG_MAP_IDS" \
        lpm_src_v4:lpm_src_v4 \
        lpm_src_v6:lpm_src_v6 \
        decap_dst:decap_dst \
        server_id_map:server_id_map \
        reals_stats:reals_stats \
        lru_miss_stats:lru_miss_stats \
        quic_stats_map:quic_stats_map \
        decap_vip_stats:decap_vip_stats \
        server_id_stats:server_id_stats \
        vip_to_down_rea:vip_to_down_reals
fi

echo "All pinned maps: $(ls "$PIN_PATH" 2>/dev/null | tr '\n' ' ')"

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
