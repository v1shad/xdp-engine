#!/bin/bash
# We do not use 'set -e' here so the script continues even if an interface is already deleted

# Delete the "veth-host" interface on the host side (this automatically deletes the "veth-atk" peer)
ip link del veth-host 2>/dev/null || true

# Delete the "attacker" network namespace
ip netns del attacker 2>/dev/null || true
