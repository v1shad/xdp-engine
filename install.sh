#!/bin/bash
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

echo "Creating directories..."
mkdir -p /opt/xdp-engine

echo "Copying files..."
cp engine engine-cli xdp_prog.bpf.o rules.yaml playbooks.yaml /opt/xdp-engine/
cp xdp-engine.service /etc/systemd/system/
cp xdp-engine.conf /etc/

echo "Setting permissions..."
chmod 755 /opt/xdp-engine/engine /opt/xdp-engine/engine-cli
chmod 644 /etc/systemd/system/xdp-engine.service
chmod 644 /etc/xdp-engine.conf

# Initialize an empty DB if not present so restorecon works on it
if [ ! -f /opt/xdp-engine/engine.db ]; then
    touch /opt/xdp-engine/engine.db
fi
chmod 666 /opt/xdp-engine/engine.db

# SELinux requires binaries running as systemd services to have the correct context (bin_t or similar).
# restorecon resets the file contexts to the system default, allowing systemd to transition to the right domain.
echo "Running restorecon for SELinux..."
restorecon -Rv /opt/xdp-engine/

systemctl daemon-reload
echo "Install complete!"
