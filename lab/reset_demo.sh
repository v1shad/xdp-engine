#!/bin/bash
set -u

MANUAL=0
KEEP_DB=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --manual) MANUAL=1; shift ;;
        --keep-db) KEEP_DB=1; shift ;;
        *) echo "Unknown option $1"; exit 1 ;;
    esac
done

if ! ip netns list | grep -q "^attacker\b" || ! ip link show veth-host >/dev/null 2>&1; then
    echo "ERROR: Namespace 'attacker' or interface 'veth-host' missing."
    exit 1
fi

echo "[*] Stopping service and clearing BPF maps..."
pkill -x engine 2>/dev/null || true
sleep 1
../engine cleanup veth-host 2>/dev/null || true
rm -rf /sys/fs/bpf/xdp_engine
ip link set dev veth-host xdp off 2>/dev/null || true

echo "[*] Clearing logs and reports..."
chown root:root /tmp/fake_auth.log /tmp/fake_access.log 2>/dev/null || true
: > /tmp/fake_auth.log
: > /tmp/fake_access.log
rm -f report.md

if [ "$KEEP_DB" -eq 0 ]; then
    if [ -f "../engine.db" ]; then
        TS=$(date +%s)
        mv ../engine.db "../engine.db.backup.$TS"
        echo "[*] Backed up DB to engine.db.backup.$TS"
    fi
    # Need to touch it so permissions are right for restorecon
    touch ../engine.db
    chmod 666 ../engine.db
    restorecon -v ../engine.db >/dev/null 2>&1 || true
fi

echo "[*] Recreating lab network..."
./teardown_lab.sh >/dev/null 2>&1 || true
./setup_lab.sh >/dev/null 2>&1

echo "[*] Adding secondary IPs to attacker namespace..."
for IP in "10.10.0.3/24" "10.10.0.4/24" "10.10.0.5/24"; do
    ip netns exec attacker ip addr add "$IP" dev veth-atk 2>/dev/null || true
done

echo "[*] Verifying network baseline..."
if ! ip netns exec attacker ping -c 1 -W 1 10.10.0.1 >/dev/null 2>&1; then
    echo "FAIL: Baseline ping from attacker to 10.10.0.1 failed!"
    exit 1
fi

if [ "$MANUAL" -eq 1 ]; then
    echo "[*] Manual mode requested. Start the engine with:"
    echo "    sudo ../engine veth-host ../xdp_prog.bpf.o /tmp/fake_auth.log"
else
    echo "[*] Starting xdp-engine service..."
    (cd .. && ./engine veth-host >/dev/null 2>&1 &)
    sleep 2
    
    echo "[*] Waiting for engine-cli to respond..."
    READY=0
    for _ in {1..10}; do
        if ../engine-cli stats >/dev/null 2>&1; then
            READY=1
            break
        fi
        sleep 1
    done
    
    if [ "$READY" -eq 0 ]; then
        echo "FAIL: engine-cli did not respond after 10 seconds."
        exit 1
    fi
fi

echo "========================================="
echo "READY"
echo "Dashboard: http://127.0.0.1:5000/?demo=1"
echo "========================================="
