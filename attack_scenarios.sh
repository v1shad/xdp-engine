#!/bin/bash
set -u

# Check for required environment
if ! ip netns list | grep -q "^attacker\b"; then
    echo "ERROR: Namespace 'attacker' does not exist."
    exit 1
fi
if ! ip link show veth-host >/dev/null 2>&1; then
    echo "ERROR: Interface 'veth-host' does not exist."
    exit 1
fi

TARGET="10.10.0.1"
PAUSE=5
STAGE_OPT=0

# Add secondary IPs (idempotent)
for IP in "10.10.0.3/24" "10.10.0.4/24" "10.10.0.5/24"; do
    if ! ip netns exec attacker ip addr show veth-atk | grep -q "${IP%/*}"; then
        ip netns exec attacker ip addr add "$IP" dev veth-atk
    fi
done

function cleanup() {
    echo "Cleaning up..."
    pkill -P $$ -x hping3 2>/dev/null || true
    exit 1
}
trap cleanup SIGINT SIGTERM

function print_list() {
    echo "Available Stages:"
    echo "  1 - 10.10.0.2: Port scan + SSH brute force -> Expected: SCAN_THEN_BRUTE alert"
    echo "  2 - 10.10.0.3: SSH brute force only -> Expected: SSH_BRUTE_FORCE alert"
    echo "  3 - 10.10.0.4: Bounded SYN flood -> Expected: RATE_LIMIT drops, no block"
    echo "  4 - 10.10.0.5: Malicious HTTP logs -> Expected: http_* events"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --list)
            print_list
            exit 0
            ;;
        --pause)
            PAUSE="$2"
            shift 2
            ;;
        --stage)
            STAGE_OPT="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--list] [--stage N] [--pause N]"
            exit 1
            ;;
    esac
done

function run_stage1() {
    echo "=========================================================="
    echo "STAGE 1: 10.10.0.2 - Port Scan followed by SSH Brute Force"
    echo "=========================================================="
    sleep "$PAUSE"
    echo "[*] Running port scan from 10.10.0.2..."
    ip netns exec attacker hping3 -a 10.10.0.2 -S --scan 1-40 "$TARGET" >/dev/null 2>&1 &
    HPING_PID=$!
    sleep 3
    kill $HPING_PID 2>/dev/null || true
    wait $HPING_PID 2>/dev/null || true
    
    echo "[*] Writing 6 SSH failures for 10.10.0.2..."
    for _ in {1..6}; do
        echo "Failed password for root from 10.10.0.2 port 22 ssh2" >> /tmp/fake_auth.log
        sleep 0.2
    done
    
    echo "[*] Checking engine-cli list..."
    ./engine-cli list | grep "10.10.0.2" || echo "10.10.0.2 not found in blocklist"
}

function run_stage2() {
    echo "=========================================================="
    echo "STAGE 2: 10.10.0.3 - SSH Brute Force Only                 "
    echo "=========================================================="
    sleep "$PAUSE"
    echo "[*] Writing 6 SSH failures for 10.10.0.3..."
    for _ in {1..6}; do
        echo "Failed password for admin from 10.10.0.3 port 22 ssh2" >> /tmp/fake_auth.log
        sleep 0.2
    done
    
    echo "[*] Checking engine-cli list..."
    ./engine-cli list | grep "10.10.0.3" || echo "10.10.0.3 not found in blocklist"
}

function run_stage3() {
    echo "=========================================================="
    echo "STAGE 3: 10.10.0.4 - Bounded SYN Flood                    "
    echo "=========================================================="
    sleep "$PAUSE"
    echo "[*] Running SYN flood from 10.10.0.4..."
    ip netns exec attacker hping3 -a 10.10.0.4 -S -p 22 --faster -c 3000 "$TARGET" >/dev/null 2>&1
    
    echo "[*] Checking engine-cli list..."
    ./engine-cli list | grep "10.10.0.4" || echo "10.10.0.4 not found in blocklist (Expected behavior)"
}

function run_stage4() {
    echo "=========================================================="
    echo "STAGE 4: 10.10.0.5 - Malicious HTTP Payloads              "
    echo "=========================================================="
    sleep "$PAUSE"
    echo "[*] Writing malicious access log entries for 10.10.0.5..."
    echo '10.10.0.5 - - [04/Oct/2026:12:00:00 +0000] "GET /../../../etc/passwd HTTP/1.1" 200' >> /tmp/fake_access.log
    sleep 0.5
    echo '10.10.0.5 - - [04/Oct/2026:12:00:01 +0000] "GET /login?user=admin%27%20OR%201=1-- HTTP/1.1" 200' >> /tmp/fake_access.log
    sleep 0.5
    echo '10.10.0.5 - - [04/Oct/2026:12:00:02 +0000] "GET / HTTP/1.1" 200 "-" "sqlmap/1.5.8"' >> /tmp/fake_access.log
    
    echo "[*] Checking engine-cli list..."
    ./engine-cli list | grep "10.10.0.5" || echo "10.10.0.5 not found in blocklist"
}

if [[ "$STAGE_OPT" -eq 1 || "$STAGE_OPT" -eq 0 ]]; then run_stage1; fi
if [[ "$STAGE_OPT" -eq 2 || "$STAGE_OPT" -eq 0 ]]; then run_stage2; fi
if [[ "$STAGE_OPT" -eq 3 || "$STAGE_OPT" -eq 0 ]]; then run_stage3; fi
if [[ "$STAGE_OPT" -eq 4 || "$STAGE_OPT" -eq 0 ]]; then run_stage4; fi

echo "All specified stages complete."
