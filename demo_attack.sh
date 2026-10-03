#!/bin/bash
# demo_attack.sh
# Usage: ./demo_attack.sh [IP_ADDRESS]

IP=${1:-10.10.0.2}
LOG_FILE="/tmp/fake_auth.log"

echo "[*] Simulating SSH brute force from $IP..."

for i in {1..6}; do
    echo "Failed password for root from $IP port 22 ssh2" >> "$LOG_FILE"
    echo " -> Wrote failure $i"
    sleep 0.2
done

echo "[*] Attack simulation complete."
