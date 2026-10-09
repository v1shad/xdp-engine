import sys
with open('engine.cpp', 'r') as f:
    content = f.read()

old_cmd_block = """        auto process_command = [&](const std::string& line, std::function<void(const std::string&)> out) {
            std::istringstream iss{line};
            std::string cmd, arg, arg2;
            iss >> cmd >> arg >> arg2;
            if (cmd == "quit") g_running = false;
            else if (cmd == "list")  blocklist.print_blocked(out);
            else if (cmd == "stats") blocklist.print_stats(out);
            else if (cmd == "alerts") storage.print_last_alerts(10, out);
            else if (cmd == "limit") {
                try { engine.set_limit(std::stoi(arg)); out("ok"); } catch (...) { out("error"); }
            }
            else if (cmd == "mode") {
                if (arg == "detect") { enforce_mode = false; storage.insert_action({"mode_change", "DETECT", get_iso_time_str(), ""}); print_log("[MODE]", "detect"); out("mode set to detect"); }
                else if (arg == "enforce") { enforce_mode = true; storage.insert_action({"mode_change", "ENFORCE", get_iso_time_str(), ""}); print_log("[MODE]", "enforce"); out("mode set to enforce"); }
                else if (arg == "show") { out(enforce_mode ? "enforce" : "detect"); }
                else { out("error: mode [detect|enforce|show]"); }
            }
            else if (cmd == "approve") {
                try { runner.approve(std::stoi(arg)); out("ok"); } catch (...) { out("error"); }
            }
            else if (cmd == "deny") {
                try { runner.deny(std::stoi(arg)); out("ok"); } catch (...) { out("error"); }
            }
            else if (cmd == "block" || cmd == "unblock" || cmd == "allow" || cmd == "unallow") {
                if (auto ip = parse_ipv4_local(arg)) {
                    if (cmd == "block") {
                        int seconds = arg2.empty() ? 600 : std::stoi(arg2);
                        blocklist.block(*ip, "manual", std::chrono::seconds(seconds), false, true);
                        out("ok");
                    }
                    else if (cmd == "unblock") { blocklist.unblock(*ip); out("ok"); }
                    else if (cmd == "allow") { blocklist.allow_ip(*ip); out("ok"); }
                    else if (cmd == "unallow") { blocklist.unallow_ip(*ip); out("ok"); }
                } else out("invalid IPv4 address");
            } else if (!cmd.empty()) out("unknown command");
        };"""

new_cmd_block = """        auto process_command = [&](const std::string& line, std::function<void(const std::string&)> out) {
            std::istringstream iss{line};
            std::string cmd, arg, arg2;
            iss >> cmd >> arg >> arg2;
            if (cmd == "quit") g_running = false;
            else if (cmd == "list")  blocklist.print_blocked(out);
            else if (cmd == "stats") blocklist.print_stats(out);
            else if (cmd == "block" || cmd == "unblock") {
                if (auto ip = parse_ipv4_local(arg)) {
                    if (cmd == "block") {
                        try {
                            int seconds = arg2.empty() ? 600 : std::stoi(arg2);
                            blocklist.block(*ip, "manual", std::chrono::seconds(seconds), false, true);
                            out("ok");
                        } catch (...) {
                            out("error: invalid ttl");
                        }
                    }
                    else if (cmd == "unblock") { blocklist.unblock(*ip); out("ok"); }
                } else out("invalid IPv4 address");
            } else if (!cmd.empty()) out("unknown command");
        };"""

if old_cmd_block in content:
    content = content.replace(old_cmd_block, new_cmd_block)
    with open('engine.cpp', 'w') as f:
        f.write(content)
    print("Success")
else:
    print("Failed to find block")
