# XDP-Engine: Live Network Defense

An enterprise-grade, eBPF-powered firewall and SOAR engine. 
Detect from anywhere, enforce at kernel speed, respond with guardrails, record everything.

![Build Status](https://github.com/v1shad/xdp-engine/actions/workflows/build.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

## Features
- **Kernel eBPF (XDP):** Drops up to 2,000,000+ packets/sec natively in hardware before they reach the OS.
- **Enterprise Scaling:** Hardware map preallocates tracking capacity for **1,000,000 unique IPs**.
- **Detection (SIEM):** Real-time Log Tailer for Nginx/Apache and SSH. Parses SQL Injection and Path Traversal.
- **Response (SOAR):** YAML-based Playbooks orchestrate instant blocks, IP enrichment, and dynamic escalations.
- **Advanced Correlation:** Tracks complex state machines (e.g. `SCAN_THEN_BRUTE` killshot sequences).
- **Observability:** Live asynchronous Python Dashboard tracking hardware graphs and threat alerts.
- **Safety Guardrails:** Hardcoded auto-allowlisting for loopback and default gateways to prevent self-lockout.

## Testing the Defenses (Attacker Simulation)

To safely verify the firewall, you can launch these simulated attacks.
*Note: Replace `<MY_IP>` with the IP of the machine running the Engine.*

### 1. Web Exploits (SQL Injection & Path Traversal)
Fires a malicious HTTP payload that the engine parses from Nginx logs.
*   **Linux / Mac / WSL:** `curl -m 5 "http://<MY_IP>/?id=1%27%20OR%201=1--"`
*   **Windows (PowerShell):** `curl.exe -m 5 "http://<MY_IP>/../../etc/passwd" --path-as-is`

### 2. SSH Brute Force
Triggers the stateful sliding-window rule (>5 failed logins in 60s).
*   **Linux / Mac / WSL:** `hydra -l fakeuser -p invalid <MY_IP> ssh` (or fail 5 interactive logins)
*   **Windows (PowerShell):** Manually attempt `ssh fakeuser@<MY_IP>` and fail the password 5 times.

### 3. Network Reconnaissance (eBPF Port Scans)
The kernel natively tracks unique destination ports in a hash map. Scanning >10 ports triggers the event.
*   **Linux / Mac / WSL (Nmap):** `nmap -Pn -sS -p 1-20 <MY_IP>`
*   **Windows (PowerShell):** `1..15 | ForEach-Object { $s = New-Object Net.Sockets.TcpClient; $null = $s.ConnectAsync("<MY_IP>", $_) }`

### 4. Advanced Correlation: The "Killshot" Sequence
Demonstrates the `SCAN_THEN_BRUTE` sequence rule. 
1. Run the **Port Scan** command above.
2. Within 5 minutes, run a single **SSH Brute Force** failure.
3. The engine correlates both attacks and issues an escalated 24-hour ban.

### 5. SYN Floods & Volumetric DDoS
Tests the Kernel's native capacity to incinerate millions of packets per second.

*   **1 Million Packets/Sec (Single Attacker):**
    Requires WSL or Linux. Run this in two parallel terminals to push >1M PPS:
    `sudo hping3 -S -p 80 --flood <MY_IP>`
*   **1 Million IP Botnet Simulation (IP Spoofing):**
    Uses `--rand-source` to spoof a completely random source IP for every packet. The eBPF kernel tracks all 1,000,000 IPs simultaneously. (Because each random IP only sends 1 packet, they safely bypass the 200pps limit).
    `sudo hping3 -S -p 80 --flood --rand-source <MY_IP>`
*   **Simulating a Coordinated Botnet Ban:**
    To simulate 50 unique attackers simultaneously getting banned, run this bash loop in WSL/Linux:
    `for i in {1..50}; do sudo hping3 -S -p 80 --flood -a 10.0.0.$i <MY_IP> > /dev/null 2>&1 & done`
*   **Windows PowerShell Fast UDP Flood:**
    Bypasses Windows TCP socket limits to instantly spam UDP packets:
    `$code = @"
using System.Net.Sockets;
public class Flooder {
    public static void Run(string ip) {
        var ep = new System.Net.IPEndPoint(System.Net.IPAddress.Parse(ip), 80);
        System.Threading.Tasks.Parallel.For(0, 10, i => {
            using (var udp = new UdpClient()) {
                byte[] data = new byte[16];
                while (true) {
                    try { udp.Send(data, data.Length, ep); } catch {}
                }
            }
        });
    }
}
"@
Add-Type -TypeDefinition $code
[Flooder]::Run("<MY_IP>")`

## CLI Commands
| Command | Description |
|---|---|
| `sudo ./engine <INTERFACE> --enforce` | Starts the firewall on the specified Wi-Fi/Ethernet interface. |
| `engine-cli block <IP>` | Manually issue an eBPF hardware ban. |
| `engine-cli unblock <IP>` | Remove an eBPF ban. |
| `engine-cli stats` | View XDP drop statistics read from the per-cpu maps. |

## Requirements
*   Linux Kernel 5.8+ with BTF support.
*   Fedora: `sudo dnf install clang llvm libbpf-devel elfutils-libelf-devel sqlite-devel yaml-cpp-devel gtest-devel python3-flask`
