#!/bin/bash
# Exit immediately if a command exits with a non-zero status
set -e

# Create a new network namespace named "attacker"
ip netns add attacker

# Create a virtual ethernet (veth) pair with ends "veth-host" and "veth-atk"
ip link add veth-host type veth peer name veth-atk

# Move the "veth-atk" interface into the "attacker" network namespace
ip link set veth-atk netns attacker

# Assign the IP address 10.10.0.1/24 to the "veth-host" interface on the host
ip addr add 10.10.0.1/24 dev veth-host

# Bring the "veth-host" interface up so it can process traffic
ip link set veth-host up

# Assign the IP address 10.10.0.2/24 to the "veth-atk" interface inside the namespace
ip -n attacker addr add 10.10.0.2/24 dev veth-atk

# Bring the "veth-atk" interface up inside the namespace
ip -n attacker link set veth-atk up

# Bring the loopback interface up inside the "attacker" namespace (good practice)
ip -n attacker link set lo up
