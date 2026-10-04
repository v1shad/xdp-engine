[![Build & Test](https://github.com/v1shad/xdp-engine/actions/workflows/build.yml/badge.svg)](https://github.com/v1shad/xdp-engine/actions/workflows/build.yml)

# Tier 3 Automated Intrusion Mitigation Engine

## What the Project Is
This project is an automated intrusion mitigation engine built using eBPF/XDP (kernel space) and C++20 (user space). 
The XDP program runs directly at the network interface driver level, filtering incoming packets before they even reach the standard Linux networking stack. It inspects the source IPv4 address of incoming packets and drops them if they are found in an eBPF hash map (`blocked_ips`). 
The C++ user-space engine uses `libbpf` to load this XDP program and attach it to a network interface. Concurrently, it tails an SSH log file (e.g., `/var/log/secure` or a dummy test file). If an IP accumulates 5 "Failed password" attempts within a 60-second sliding window, the C++ engine dynamically inserts that IP into the `blocked_ips` map, immediately blocking the attacker at line rate.

## Build Steps
Ensure all prerequisites (clang, llvm, libbpf-devel, gcc-c++, make, etc.) are installed.
1. Open a terminal in the project directory.
2. Build the project using `make`:
   ```bash
   make
   ```
   This will compile `xdp_prog.bpf.c` into the eBPF object file (`xdp_prog.bpf.o`) and build the C++ daemon (`engine`).

## Run Steps
We use a virtual lab environment consisting of a network namespace (`attacker`) and a veth pair to safely test the engine without locking ourselves out of our host.

1. **Setup the lab environment:**
   ```bash
   sudo ./setup_lab.sh
   ```
2. **Create a dummy log file to tail:**
   ```bash
   touch /tmp/dummy_auth.log
   ```
3. **Run the engine on the host side of the veth pair:**
   ```bash
   sudo ./engine veth-host xdp_prog.bpf.o /tmp/dummy_auth.log
   ```
4. **Teardown (when completely finished testing):**
   Type `quit` in the engine console (or press `Ctrl-C`), then clean up the network interfaces:
   ```bash
   sudo ./teardown_lab.sh
   ```

## Test Plan

### 1. Manual Block Test
1. In the running engine console, type: `block 10.10.0.2`
2. Open a second terminal and ping the host from the attacker namespace:
   ```bash
   sudo ip netns exec attacker ping 10.10.0.1
   ```
3. The ping will fail (packets are dropped by XDP).
4. In the engine console, type `unblock 10.10.0.2`. The ping in the second terminal should now begin receiving replies.
5. In the engine console, type `stats` to view the updated packet pass/drop counters.

### 2. Automated Brute-Force Test (Fake Log Lines)
1. Type `unblock 10.10.0.2` in the engine console to ensure it's unblocked.
2. Start a continuous ping in the second terminal:
   ```bash
   sudo ip netns exec attacker ping 10.10.0.1
   ```
3. Open a third terminal and simulate 5 failed SSH logins from the attacker IP by writing to the dummy log:
   ```bash
   for i in {1..5}; do echo "Failed password for invalid user root from 10.10.0.2 port 22 ssh2" >> /tmp/dummy_auth.log; done
   ```
4. Look at the engine console. It should print a message stating that it blocked `10.10.0.2`. 
5. The continuous ping in the second terminal will suddenly stop receiving replies.

### 3. Flood Test with hping3
1. With `10.10.0.2` blocked by the engine, launch a SYN flood from the attacker namespace:
   ```bash
   sudo ip netns exec attacker hping3 -S -p 80 --flood 10.10.0.1
   ```
2. Wait a few seconds, then type `stats` in the engine console. You will see the "packets dropped" counter rising dramatically, demonstrating that XDP is absorbing the flood efficiently.
3. Press `Ctrl-C` in the `hping3` terminal to stop the flood.

### 4. Verification with bpftool and tcpdump
*   **tcpdump verification:** Because XDP drops packets before they reach the OS stack, they are invisible to standard packet captures.
    ```bash
    sudo tcpdump -i veth-host -n
    ```
    While `10.10.0.2` is blocked, pinging from the attacker will produce no output in this tcpdump trace.
*   **bpftool verification:** You can query the kernel directly to prove the C++ engine inserted the IP into the map.
    ```bash
    sudo bpftool map dump name blocked_ips
    ```
    This will dump the raw hexadecimal keys (IPs) and values (hit counts) currently stored in the map.

### 5. How to demo
To demonstrate the full dashboard and engine pipeline to your professor:
1. Open terminal 1 and start the Flask dashboard:
   ```bash
   python3 dashboard/app.py
   ```
2. Open your web browser and navigate to `http://127.0.0.1:5000`. You should see the empty dashboard.
3. Open terminal 2 and start the engine with the dummy log file:
   ```bash
   sudo ./engine veth-host xdp_prog.bpf.o /tmp/fake_auth.log
   ```
4. Open terminal 3 and run the demo script to simulate an attack:
   ```bash
   ./demo_attack.sh 10.10.0.2
   ```
5. Watch the dashboard! The events will rise, then an alert will be generated, the IP will appear in the Top Attackers chart and Recent Alerts table, the Active Blocks will increase, and the Drops chart will spike if you run a ping or hping flood.

## Demo and Red Team

To run a live demonstration of the XDP Intrusion Engine:

1. **Reset the Lab**
   Run the reset script to tear down and recreate the network namespaces, clear the BPF maps, rotate the logs, and back up the SQLite database:
   ```bash
   sudo ./reset_demo.sh
   ```

2. **Open the Dashboard**
   Launch the web dashboard in presentation mode:
   ```bash
   http://127.0.0.1:5000/?demo=1
   ```

3. **Run the Attack Scenarios**
   Run the automated red team script to simulate various attacks:
   ```bash
   sudo ./attack_scenarios.sh
   ```
   
   **What to point out during the demo:**
   - **Stage 1 (10.10.0.2)**: A port scan followed by SSH brute force. Watch the dashboard's Live Feed to see the `port_scan` event upgrade into a `SCAN_THEN_BRUTE` critical alert.
   - **Stage 2 (10.10.0.3)**: A pure SSH brute force attack. Point out the `SSH_BRUTE_FORCE` alert appearing in the feed.
   - **Stage 3 (10.10.0.4)**: A volumetric SYN flood. Point out the Health Strip showing XDP actively dropping packets (`RATE_LIMIT`), but note that the IP is intentionally *not* added to the permanent blocklist (to prevent spoofing lockouts).
   - **Stage 4 (10.10.0.5)**: Malicious HTTP payloads (Path Traversal, SQLi). Watch the Live Feed for the `http_sql_injection` and `http_path_traversal` alerts triggered by the C++ regex engine.
