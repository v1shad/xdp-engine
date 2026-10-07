#!/bin/bash
set -e

echo "Building..."
make clean && make

echo "Installing to /opt/xdp-engine..."
mkdir -p /opt/xdp-engine
cp engine /opt/xdp-engine/
cp engine-cli /opt/xdp-engine/
cp xdp_prog.bpf.o /opt/xdp-engine/
cp rules.yaml /opt/xdp-engine/
cp playbooks.yaml /opt/xdp-engine/

echo "Installing systemd service..."
cp xdp-engine.service /etc/systemd/system/
systemctl daemon-reload

echo "Done. Edit /etc/systemd/system/xdp-engine.service if you want to change flags (like --enforce)."
echo "Start with: systemctl start xdp-engine"
