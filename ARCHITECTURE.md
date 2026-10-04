# Architecture

The XDP Intrusion Engine is split into three tightly integrated components: an in-kernel XDP program, a C++20 user space daemon, and a lightweight Python/Flask web dashboard.

## Data Flow Diagram

```text
       +-------------------+
       | External Attacker |
       +--------+----------+
                | 1. Malicious Traffic
                v
+======================================================+
|                 KERNEL SPACE (eBPF)                  |
|                                                      |
|  [Network Interface]                                 |
|          |                                           |
|          v                                           |
|  [xdp_prog.bpf.c] <=======+ 3. BPF Maps (State)      |
|          |                | - blocked_ips            |
|     (Drop / Pass)         | - allowed_ips            |
|          |                | - stats                  |
+==========|================|==========================+
           |                |
           | 2. Logs        | 4. Map Updates
           v                |
+======================================================+
|                 USER SPACE (C++20)                   |
|                                                      |
|   [Target App] (e.g., SSH, Nginx)                    |
|          | writes to log                             |
|          v                                           |
|   [HttpDetector / SshDetector]                       |
|          |                                           |
|          v (Parsed Events)                           |
|                                                      |
|   [RuleEngine] (Evaluates YAML rules)                |
|          |                                           |
|          v (Alerts)                                  |
|                                                      |
|   [PlaybookRunner] -----------------> [BlockList] ---+
|          |                                |
|          v                                v
|      (Records)                        (UNIX Socket)
|          |                                ^
|          v                                |
|    [SQLite DB] <----------------- [engine-cli]
+==========|===========================================+
           |
           | 5. Read-Only Polling
           v
+======================================================+
|                 PRESENTATION (Python)                |
|                                                      |
|   [dashboard/app.py] (Flask)                         |
|          |                                           |
|          v                                           |
|   [Web Browser UI]                                   |
+======================================================+
```

## Components

1. **Kernel Space (XDP Program)**: Dropping packets natively inside the network driver before they reach the Linux networking stack. Extremely fast, lightweight, and uses pinned maps to communicate with user space.
2. **User Space (C++ Daemon)**: The brain of the operation. Parses logs, evaluates sequence and threshold rules, updates SQLite, triggers playbook actions (like blocking IPs via BPF maps), and listens for manual commands via a secure socket.
3. **Dashboard (Python/Flask)**: An entirely passive, read-only interface that presents system health, live events, metrics, and alerts to the administrator using SQLite.
