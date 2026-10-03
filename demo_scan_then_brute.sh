#!/bin/bash
TARGET="10.10.0.1"

echo "Running nmap port scan against $TARGET..."
sudo ip netns exec attacker nmap -p 1-20 $TARGET

echo "Waiting a few seconds..."
sleep 3

echo "Simulating 6 SSH failures from 10.10.0.2..."
for i in {1..6}; do
    echo "Failed password for root from 10.10.0.2 port 22 ssh2" >> /tmp/fake_auth.log
    sleep 0.5
done
echo "Sequence completed."
