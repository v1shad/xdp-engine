#!/bin/bash
set -u

if ! ip netns list | grep -q "^attacker\b" || ! ip link show veth-host >/dev/null 2>&1; then
    echo "ERROR: Namespace 'attacker' or interface 'veth-host' missing."
    exit 1
fi

TARGET="10.10.0.1"
AUTH_LOG="/tmp/fake_auth.log"
ACCESS_LOG="/tmp/fake_access.log"

# Find PID
ENGINE_PID=$(pgrep -f "/opt/xdp-engine/engine" || pgrep -f "./engine")
if [ -z "$ENGINE_PID" ]; then
    echo "ERROR: Engine is not running."
    exit 1
fi
ENGINE_PID=$(echo "$ENGINE_PID" | head -n 1)

START_MEM=$(awk '/VmRSS/ {print $2}' "/proc/$ENGINE_PID/status" 2>/dev/null || echo 0)

echo ">>> Phase 1: Injecting Hostile Data into Logs"

head -c 100 /dev/urandom >> "$AUTH_LOG"; echo >> "$AUTH_LOG"

head -c 10000 /dev/zero | tr '\0' 'A' >> "$AUTH_LOG"; echo >> "$AUTH_LOG"
head -c 100000 /dev/zero | tr '\0' 'B' >> "$AUTH_LOG"; echo >> "$AUTH_LOG"

printf "Failed password for \x00root from 10.10.0.2\n" >> "$AUTH_LOG"
printf "Failed password for \xff\xfe\xfd from 10.10.0.2\n" >> "$AUTH_LOG"

echo "Failed password for \$(id) from 10.10.0.2" >> "$AUTH_LOG"
echo "Failed password for \`id\` from 10.10.0.2" >> "$AUTH_LOG"
echo "Failed password for root from 10.10.0.2 ; touch /tmp/pwned" >> "$AUTH_LOG"
echo "Failed password for root from 10.10.0.2 | nc" >> "$AUTH_LOG"
echo "Failed password for %n%n%s%s from 10.10.0.2" >> "$AUTH_LOG"
echo "Failed password for ' OR 1=1 -- from 10.10.0.2" >> "$AUTH_LOG"

for IP in 999.1.1.1 1.2.3 01.02.03.04 1.1.1.1.1 0.0.0.0 255.255.255.255 127.0.0.1 10.10.0.1; do
    echo "Failed password for root from $IP port 22 ssh2" >> "$AUTH_LOG"
done

printf "Failed password for root from 10.10.0.2" >> "$AUTH_LOG"
sleep 0.5
echo "" >> "$AUTH_LOG"

echo ">>> Injecting 20,000 valid-looking lines..."
# Write lines that look like valid SSH but are successful, so they don't trigger blocks
awk 'BEGIN { for(i=0; i<20000; i++) print "Accepted password for root from 10.20.30.40 port 22 ssh2" }' >> "$AUTH_LOG"
sleep 2

echo ">>> Phase 2: Testing Log Rotation"
> "$AUTH_LOG"
echo "Truncated $AUTH_LOG. Sending brute-force from 10.10.0.6..."
for i in {1..6}; do
    echo "Failed password for root from 10.10.0.6 port 22 ssh2" >> "$AUTH_LOG"
    sleep 0.2
done
sleep 1

HAS_10_10_0_6=$(./engine-cli list | grep "10.10.0.6" || true)
if [ -z "$HAS_10_10_0_6" ]; then
    echo "NOTICE: The engine DID NOT block 10.10.0.6 after log rotation. (Inotify needs modification to handle truncation)."
else
    echo "NOTICE: The engine blocked 10.10.0.6 successfully after log rotation."
fi

echo ">>> Phase 3: Final Checks"

# a) Engine still running
if kill -0 "$ENGINE_PID" 2>/dev/null; then
    echo "[PASS] Engine is still running."
else
    echo "[FAIL] Engine crashed!"
fi

# b) engine-cli list contains only expected IPs
# Should be empty or contain only 10.10.0.6
LIST_OUTPUT=$(./engine-cli list | grep -v "10.10.0.6" | grep -v "Currently blocked IPs" | grep -v "Total:" | grep -P "\d+\.\d+\.\d+\.\d+" || true)
if [ -z "$LIST_OUTPUT" ]; then
    echo "[PASS] No hostile IPs caused a wrong block."
else
    echo "[FAIL] Unexpected IPs were blocked: $LIST_OUTPUT"
fi

# c) 127.0.0.1 and 10.10.0.1 never blocked
if ./engine-cli list | grep -qE "127\.0\.0\.1|10\.10\.0\.1"; then
    echo "[FAIL] 127.0.0.1 or 10.10.0.1 was blocked!"
else
    echo "[PASS] 127.0.0.1 and 10.10.0.1 were never blocked."
fi

# d) Shell injection check
if [ -f "/tmp/pwned" ]; then
    echo "[FAIL] /tmp/pwned exists! Shell injection succeeded."
    rm -f "/tmp/pwned"
else
    echo "[PASS] Shell metacharacters did not execute."
fi

# e) SQLite integrity
if sqlite3 /opt/xdp-engine/engine.db "PRAGMA integrity_check;" | grep -q "ok"; then
    echo "[PASS] SQLite DB integrity check: ok"
else
    echo "[FAIL] SQLite DB corruption detected!"
fi

# f) Memory check
END_MEM=$(awk '/VmRSS/ {print $2}' "/proc/$ENGINE_PID/status" 2>/dev/null || echo 0)
DIFF=$((END_MEM - START_MEM))
if [ "$DIFF" -le 51200 ]; then
    echo "[PASS] Engine memory is stable (grew by $((DIFF / 1024)) MB, limit is 50 MB)."
else
    echo "[FAIL] Engine memory leak detected! Grew by $((DIFF / 1024)) MB."
fi
