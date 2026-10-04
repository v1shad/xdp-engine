# Threat Model

## Assets
- **The Host System**: CPU, memory, and kernel stability.
- **Protected Applications**: The web servers and SSH daemons running on the host.
- **Engine Data**: The SQLite database containing historical offense data, alerts, and metrics.
- **The BPF Maps**: The direct interface between user space and kernel space packet dropping.

## Attacker Capabilities
We assume the attacker can:
- Send arbitrary volumes of network traffic to the host from any IP address.
- Forge (spoof) source IP addresses.
- Craft malicious payloads (e.g., XSS, SQLi) in HTTP requests.
- Attempt to bruteforce exposed services.
- Influence log file contents by causing target applications to log attacker-controlled strings.

## Trust Boundaries
1. **Log Files (`/tmp/fake_auth.log`)**: Untrusted. Attackers control usernames and User-Agent strings. The engine parses this data securely without passing it to a shell.
2. **The Control Socket (`/run/xdp_engine.sock`)**: Trusted but secured. Boundary strictly enforced via UNIX permissions (`0600`) and `SO_PEERCRED` checks ensuring only `root` can send commands.
3. **The Web Dashboard**: Read-only boundary. The dashboard runs locally and pulls state directly from a read-only connection to SQLite. Attacker data is safely rendered as raw text, neutering XSS payloads.
4. **Pinned BPF Maps**: Kernel boundary. Only the root-privileged C++ user space engine can write to these maps to dictate packet blocking.

## Built-In Mitigations
- **Validated IPs**: All user input, socket commands, and log file parses are strictly validated as legitimate IPv4 addresses before processing.
- **Allowlist Wins**: Built-in protection prevents blocking crucial infrastructure (e.g., `127.0.0.1` or admin IPs passed via `--allow`).
- **Rate Cap & Cooldown**: Syn-flood limits protect kernel and user space from being overwhelmed.
- **TTL & Expiry**: Blocks automatically expire via a kernel-checked timestamp (`blocked_until_ns`), preventing permanent lockouts in case the user space daemon crashes.
- **Fail-Open Design**: If the user space engine stops, XDP detaches and traffic flows normally, preventing accidental permanent outages.
- **Root-only Socket**: Hardened UNIX socket prevents local privilege escalation.
- **Read-Only Dashboard**: The presentation layer cannot alter the system state or database.

## Known Limitations
- **IPv4 Only**: The BPF program currently only parses and blocks IPv4 traffic. IPv6 is not supported.
- **Spoofed-Source SYN Floods**: The engine drops packets based on source IP. A highly distributed spoofed-source SYN flood could bypass threshold limits or erroneously block spoofed victims (though SYN cookies usually mitigate the latter).
- **No Encrypted-Payload Inspection**: The engine cannot inspect TLS/HTTPS payloads directly in kernel space; it relies on application logs for layer 7 insights.
- **Log Rotation**: Currently, if the monitored log file rotates or is deleted, the engine requires a restart or it may hang reading a stale inode.
- **Single Host**: The state is entirely local. It cannot synchronize blocks across a cluster of machines.
