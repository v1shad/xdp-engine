#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <regex>
#include <fstream>
#include <csignal>
#include <unordered_set>
#include <map>
#include <mutex>
#include <optional>
#include <filesystem>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/un.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <bpf/bpf.h>
#include <sys/file.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <sys/socket.h>
#include <cstdint>
#include <cstring>
#include <deque>
#include <stdexcept>
#include <stop_token>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <numeric>

#include "common.h"
#include "event.h"
#include "rule_engine.h"
#include "storage.h"
#include "playbook_runner.h"
#include "notifier.h"
#include "http_detector.h"
#include "log_tailer.h"
#include "text_util.h"
#include "utils.h"

using namespace std::chrono_literals;

static bool use_color = true;
static std::atomic<bool> g_running{true};
extern "C" void on_signal(int) { g_running = false; }

std::string get_iso_time_str() {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", gmtime(&ts.tv_sec));
    return std::string(buf);
}

void print_log(std::string tag, const std::string& msg, const std::string& color_code = "") {
    std::string reset = use_color ? "\x1b[0m" : "";
    std::string color = use_color ? color_code : "";
    while (tag.length() < 10) tag += " ";
    std::cout << get_iso_time_str() << " " << color << tag << reset << " " << msg << "\n";
}
void log_info(const std::string& msg) { print_log("[INFO]", msg); }
void log_warn(const std::string& msg) { print_log("[WARN]", msg, "\x1b[33m"); }
void log(const std::string& msg) { log_info(msg); } // Compatibility

std::string ip_to_string(std::uint32_t ip_net) {
    char buf[INET_ADDRSTRLEN]{};
    in_addr addr{.s_addr = ip_net};
    inet_ntop(AF_INET, &addr, buf, sizeof buf);
    return buf;
}

std::optional<std::uint32_t> parse_ipv4_local(const std::string& text) {
    in_addr addr{};
    if (inet_pton(AF_INET, text.c_str(), &addr) != 1) return std::nullopt;
    return addr.s_addr;
}

void add_iface_ips(std::unordered_set<std::uint32_t>& allow, const std::string& ifname) {
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) return;
    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;
        if (ifa->ifa_addr->sa_family == AF_INET && std::string(ifa->ifa_name) == ifname) {
            auto* sa = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr);
            allow.insert(sa->sin_addr.s_addr);
        }
    }
    freeifaddrs(ifaddr);
}

void add_gateway_ips(std::unordered_set<std::uint32_t>& allow) {
    std::ifstream in("/proc/net/route");
    std::string line;
    std::getline(in, line);
    while (std::getline(in, line)) {
        std::istringstream iss(line);
        std::string iface, dest, gw;
        if (iss >> iface >> dest >> gw) {
            if (dest == "00000000") {
                unsigned int gw_ip;
                if (std::sscanf(gw.c_str(), "%X", &gw_ip) == 1 && gw_ip != 0) {
                    allow.insert(gw_ip);
                }
            }
        }
    }
}

bool check_process(const std::string& name) {
    DIR* dir = opendir("/proc");
    if (!dir) return false;
    struct dirent* ent;
    while ((ent = readdir(dir)) != nullptr) {
        if (ent->d_type == DT_DIR && std::isdigit(ent->d_name[0])) {
            std::string comm_path = std::string("/proc/") + ent->d_name + "/comm";
            std::ifstream comm_file(comm_path);
            if (comm_file.is_open()) {
                std::string comm;
                if (std::getline(comm_file, comm) && comm == name) {
                    closedir(dir);
                    return true;
                }
            }
        }
    }
    closedir(dir);
    return false;
}

template <typename K, typename V>
bool map_update(int fd, const K& key, const V& value, __u64 flags = BPF_ANY) {
    return bpf_map_update_elem(fd, &key, &value, flags) == 0;
}

struct RingBufDeleter {
    void operator()(struct ring_buffer* rb) const { ring_buffer__free(rb); }
};
using RingBufPtr = std::unique_ptr<struct ring_buffer, RingBufDeleter>;

class BlockList {
public:
    BlockList(int allowed_fd, int blocked_fd, int stats_fd, int proto_stats_fd, const std::unordered_set<std::uint32_t>& allow, Storage* storage = nullptr)
    : allowed_fd_{allowed_fd}, blocked_fd_{blocked_fd}, stats_fd_{stats_fd}, proto_stats_fd_{proto_stats_fd}, storage_{storage},
      sweeper_{[this](std::stop_token st) { sweep_loop(st); }} {
        for (std::uint32_t ip : allow) {
            allow_ip(ip);
        }
    }

    bool allow_ip(std::uint32_t ip) {
        std::uint8_t dummy = 1;
        if (map_update(allowed_fd_, ip, dummy)) {
            print_log("[ALLOWED]", ip_to_string(ip));
            return true;
        }
        return false;
    }

    bool unallow_ip(std::uint32_t ip) {
        return bpf_map_delete_elem(allowed_fd_, &ip) == 0;
    }

    bool is_allowed(std::uint32_t ip) const {
        std::uint8_t dummy = 0;
        return (bpf_map_lookup_elem(allowed_fd_, &ip, &dummy) == 0);
    }

    bool block(std::uint32_t ip, std::string_view reason, std::chrono::seconds duration = std::chrono::seconds(600), bool detect_only = false, bool manual = false) {
        if (detect_only) return false;
        if (is_allowed(ip)) {
            log_warn("refusing to block allow-listed " + ip_to_string(ip));
            return false;
        }
        
        struct block_record rec{};
        rec.hits = 0;
        if (duration.count() > 0) {
            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            rec.expires_at_ns = (ts.tv_sec * 1000000000ULL + ts.tv_nsec) + (duration.count() * 1000000000ULL);
        } else {
            rec.expires_at_ns = 0;
        }

        if (!map_update(blocked_fd_, ip, rec)) {
            log_warn(std::string{"[error] map update failed: "} + std::strerror(errno));
            return false;
        }
        std::string label = manual ? "manual" : "automatic";
        print_log("[BLOCKED]", ip_to_string(ip) + " ttl=" + std::to_string(duration.count()) + "s " + label, "\x1b[31m");
        return true;
    }

    void unblock(std::uint32_t ip) {
        if (bpf_map_delete_elem(blocked_fd_, &ip) == 0) {
            print_log("[EXPIRED]", ip_to_string(ip) + " (manual unblock)");
        }
    }

    void print_blocked(std::function<void(const std::string&)> out) {
        std::uint32_t key = 0, next_key;
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        std::uint64_t now_ns = ts.tv_sec * 1000000000ULL + ts.tv_nsec;

        out("Active Blocks:");
        bool any = false;
        while (bpf_map_get_next_key(blocked_fd_, &key, &next_key) == 0) {
            struct block_record rec;
            if (bpf_map_lookup_elem(blocked_fd_, &next_key, &rec) == 0) {
                if (rec.expires_at_ns > 0 && rec.expires_at_ns <= now_ns) {
                    key = next_key;
                    continue; // expired
                }
                std::string exp = (rec.expires_at_ns == 0) ? "permanent" : 
                    std::to_string((rec.expires_at_ns - now_ns) / 1000000000) + "s left";
                out("  " + ip_to_string(next_key) + " (hits: " + std::to_string(rec.hits) + ", " + exp + ")");
                any = true;
            }
            key = next_key;
        }
        if (!any) out("  <none>");
    }

    std::tuple<std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t> get_stats() {
        int ncpus = libbpf_num_possible_cpus();
        std::uint32_t zero = 0;
        struct Stats { std::uint64_t dropped, passed; };
        std::vector<Stats> global_stats(ncpus);
        std::uint64_t dropped = 0, passed = 0;
        if (bpf_map_lookup_elem(stats_fd_, &zero, global_stats.data()) == 0) {
            for(int i=0; i<ncpus; i++) { dropped += global_stats[i].dropped; passed += global_stats[i].passed; }
        }
        
        std::uint64_t tcp=0, udp=0, icmp=0, other=0;
        std::uint32_t proto_tcp=6, proto_udp=17, proto_icmp=1;
        std::vector<std::uint64_t> vals(ncpus);
        if (bpf_map_lookup_elem(proto_stats_fd_, &proto_tcp, vals.data()) == 0) for(int i=0; i<ncpus; i++) tcp += vals[i];
        if (bpf_map_lookup_elem(proto_stats_fd_, &proto_udp, vals.data()) == 0) for(int i=0; i<ncpus; i++) udp += vals[i];
        if (bpf_map_lookup_elem(proto_stats_fd_, &proto_icmp, vals.data()) == 0) for(int i=0; i<ncpus; i++) icmp += vals[i];
        
        std::uint32_t k = 0, nk;
        while (bpf_map_get_next_key(proto_stats_fd_, &k, &nk) == 0) {
            if (nk != proto_tcp && nk != proto_udp && nk != proto_icmp) {
                if (bpf_map_lookup_elem(proto_stats_fd_, &nk, vals.data()) == 0) {
                    for(int i=0; i<ncpus; i++) other += vals[i];
                }
            }
            k = nk;
        }
        return {dropped, passed, tcp, udp, icmp, other};
    }

    void print_stats(std::function<void(const std::string&)> out) {
        auto [dropped, passed, tcp, udp, icmp, other] = get_stats();
        std::ostringstream oss;
        oss << "Stats: dropped=" << dropped << " passed=" << passed 
            << " | Proto: TCP=" << tcp << " UDP=" << udp << " ICMP=" << icmp << " Other=" << other;
        out(oss.str());
    }

private:
    void sweep_loop(std::stop_token st) {
        while (!st.stop_requested()) {
            std::this_thread::sleep_for(2s);
            
            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            std::uint64_t now_ns = ts.tv_sec * 1000000000ULL + ts.tv_nsec;

            std::vector<std::uint32_t> to_delete;
            std::uint32_t key = 0, next_key;
            
            while (bpf_map_get_next_key(blocked_fd_, &key, &next_key) == 0) {
                struct block_record rec;
                if (bpf_map_lookup_elem(blocked_fd_, &next_key, &rec) == 0) {
                    if (rec.expires_at_ns > 0 && rec.expires_at_ns <= now_ns) {
                        to_delete.push_back(next_key);
                    }
                }
                key = next_key;
            }
            
            for (auto k : to_delete) {
                if (bpf_map_delete_elem(blocked_fd_, &k) == 0) {
                    print_log("[EXPIRED]", ip_to_string(k) + " (ttl elapsed)");
                }
            }
        }
    }

    int allowed_fd_;
    int blocked_fd_;
    int stats_fd_;
    int proto_stats_fd_;
    Storage* storage_;
    std::jthread sweeper_;
};

class XdpEngine {
public:
    XdpEngine(const std::string& obj_path, const std::string& ifname) : ifname_{ifname} {
        const unsigned ifindex = if_nametoindex(ifname.c_str());
        if (ifindex == 0) throw std::runtime_error("no such interface: " + ifname);

        obj_.reset(bpf_object__open_file(obj_path.c_str(), nullptr));
        if (!obj_) throw std::runtime_error("open failed: " + std::string{std::strerror(errno)});

        bpf_map* allowed  = bpf_object__find_map_by_name(obj_.get(), "allowed_ips");
        bpf_map* blocked  = bpf_object__find_map_by_name(obj_.get(), "blocked_ips");
        if (!allowed || !blocked) throw std::runtime_error("missing map in object");

        if (int err = bpf_object__load(obj_.get()))
            throw std::runtime_error("load failed: " + std::string{std::strerror(-err)});

        bpf_program* prog = bpf_object__find_program_by_name(obj_.get(), "xdp_firewall");
        if (!prog) throw std::runtime_error("program xdp_firewall not found");

        link_.reset(bpf_program__attach_xdp(prog, ifindex));
        if (!link_) throw std::runtime_error("attach failed: " + std::string{std::strerror(errno)});

        allowed_fd_ = bpf_map__fd(allowed);
        blocked_fd_ = bpf_map__fd(blocked);
        
        bpf_map* stats = bpf_object__find_map_by_name(obj_.get(), "ip_stats");
        stats_fd_ = stats ? bpf_map__fd(stats) : -1;
        
        bpf_map* events = bpf_object__find_map_by_name(obj_.get(), "events");
        events_fd_ = events ? bpf_map__fd(events) : -1;

        bpf_map* limits = bpf_object__find_map_by_name(obj_.get(), "limits");
        limits_fd_ = limits ? bpf_map__fd(limits) : -1;

        bpf_map* pstats = bpf_object__find_map_by_name(obj_.get(), "proto_stats");
        proto_stats_fd_ = pstats ? bpf_map__fd(pstats) : -1;

        set_limit(200);
    }

    int allowed_fd() const { return allowed_fd_; }
    int blocked_fd() const { return blocked_fd_; }
    int stats_fd() const { return stats_fd_; }
    int events_fd() const { return events_fd_; }
    int proto_stats_fd() const { return proto_stats_fd_; }
    std::string get_ifname() const { return ifname_; }
    int get_limit() const { return limit_; }

    void set_limit(std::uint32_t limit) {
        if (limits_fd_ >= 0) {
            std::uint32_t zero = 0;
            if (!map_update(limits_fd_, zero, limit)) {
                log_warn("Failed to set limit");
            } else {
                limit_ = limit;
                log_info("SYN rate limit set to " + std::to_string(limit) + "/s");
            }
        }
    }

private:
    struct BpfObjDeleter {
        void operator()(struct bpf_object* obj) const { bpf_object__close(obj); }
    };
    struct BpfLinkDeleter {
        void operator()(struct bpf_link* link) const { bpf_link__destroy(link); }
    };
    
    std::string ifname_;
    std::unique_ptr<struct bpf_object, BpfObjDeleter> obj_;
    std::unique_ptr<struct bpf_link, BpfLinkDeleter> link_;
    int allowed_fd_{-1}, blocked_fd_{-1}, stats_fd_{-1}, events_fd_{-1}, limits_fd_{-1}, proto_stats_fd_{-1};
    int limit_{200};
};

using EventCallback = std::function<void(const Event&)>;

class SshDetector {
public:
    SshDetector(std::string path, EventCallback cb)
        : cb_(std::move(cb)), tailer_(std::move(path), [this](const std::string& line) { handle_line(line); }) {}
    
    void run(std::stop_token st) { tailer_.run(st); }

private:
    void handle_line(const std::string& line) {
        static const std::regex re{R"(Failed password for (?:invalid user )?(\S+) from (\d{1,3}(?:\.\d{1,3}){3}) port \d+ ssh2)"};
        std::smatch m;
        if (!std::regex_search(line, m, re)) return;

        std::string user = sanitize_utf8(m[1].str());
        std::string ip_str = m[2].str();

        if (!parse_ipv4_local(ip_str)) return;

        Event e;
        e.ts_iso = get_iso_time_str();
        e.source = "ssh_log";
        e.type = "ssh_failed";
        e.src_ip = ip_str;
        e.user = user;
        e.severity = 3;
        
        if (cb_) cb_(e);
    }
    EventCallback cb_;
    LogTailer tailer_;
};

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: sudo " << argv[0] << " <iface> [--enforce] [--allow IP]... [--ttl S] [--threshold N] [--window S] [--auth-log P] [--access-log P]\n";
        std::cerr << "       sudo " << argv[0] << " cleanup <iface>\n";
        std::cerr << "       sudo " << argv[0] << " reset\n";
        std::cerr << "       sudo " << argv[0] << " report\n";
        return 1;
    }

    std::string cmd_or_iface = argv[1];

    if (cmd_or_iface == "cleanup") {
        if (argc < 3) {
            std::cerr << "Usage: sudo " << argv[0] << " cleanup <iface>\n";
            return 1;
        }
        std::string iface = argv[2];
        unsigned int ifindex = if_nametoindex(iface.c_str());
        if (ifindex == 0) {
            std::cerr << "Interface " << iface << " not found.\n";
            return 1;
        }
        __u32 prog_id = 0;
        if (bpf_xdp_query_id(ifindex, 0, &prog_id) == 0 && prog_id > 0) {
            DECLARE_LIBBPF_OPTS(bpf_xdp_attach_opts, attach_opts);
            if (bpf_xdp_detach(ifindex, 0, &attach_opts) == 0) {
                std::cout << "Detached XDP program (ID: " << prog_id << ") from " << iface << "\n";
            } else {
                std::cerr << "Failed to detach XDP program.\n";
                return 1;
            }
        } else {
            std::cout << "No XDP program attached to " << iface << ".\n";
        }
        return 0;
    }

    if (cmd_or_iface == "reset") {
        std::filesystem::remove_all("/sys/fs/bpf/xdp_engine");
        std::cout << "Removed pinned maps from /sys/fs/bpf/xdp_engine\n";
        unlink("/run/xdp_engine.sock");
        // Database renaming removed; history is wiped inside instead.
        return 0;
    }

    if (cmd_or_iface == "report") {
        Storage storage{"engine.db"};
        storage.wipe_history();
        storage.generate_report("report.md");
        std::cout << "Report written to report.md\n";
        
        auto print = [](const std::string& msg) { std::cout << msg << "\n"; };
        std::cout << "=== Last 10 Alerts ===\n";
        storage.print_last_alerts(10, print);
        return 0;
    }

    // Normal Start
    std::string iface = cmd_or_iface;
    std::unordered_set<std::uint32_t> allow{*parse_ipv4_local("127.0.0.1")};
    add_iface_ips(allow, iface);
    add_gateway_ips(allow);

    bool enforce_mode = false;
    int ttl = 600;
    int threshold = 5;
    int window = 60;
    std::string auth_log;
    if (access("/var/log/secure", R_OK) == 0) auth_log = "/var/log/secure";
    else auth_log = "/var/log/auth.log";
    std::string access_log = "/var/log/nginx/access.log";

    use_color = isatty(STDOUT_FILENO);

    for (int i = 2; i < argc; i++) {
        std::string_view arg{argv[i]};
        if (arg == "--allow" && i + 1 < argc) {
            if (auto ip = parse_ipv4_local(argv[++i])) allow.insert(*ip);
        } else if (arg == "--enforce") {
            enforce_mode = true;
        } else if (arg == "--ttl" && i + 1 < argc) {
            ttl = std::stoi(argv[++i]);
        } else if (arg == "--threshold" && i + 1 < argc) {
            threshold = std::stoi(argv[++i]);
        } else if (arg == "--window" && i + 1 < argc) {
            window = std::stoi(argv[++i]);
        } else if (arg == "--auth-log" && i + 1 < argc) {
            auth_log = argv[++i];
        } else if (arg == "--access-log" && i + 1 < argc) {
            access_log = argv[++i];
        }
    }

    bool all_pass = true;
    auto check_fail = [&](const std::string& msg) {
        std::cerr << "FAIL: " << msg << "\n";
        
    };

    if (getuid() != 0) check_fail("Not running as root. Fix: use sudo");
    else std::cout << "PASS: Running as root\n";

    struct utsname buffer;
    if (uname(&buffer) == 0) std::cout << "PASS: Kernel " << buffer.release << "\n";
    else check_fail("uname failed");
    
    if (access("/sys/kernel/btf/vmlinux", R_OK) == 0) std::cout << "PASS: BTF file found\n";
    else check_fail("BTF file missing. Fix: install kernel headers");

    unsigned int ifindex = if_nametoindex(iface.c_str());
    if (ifindex > 0) std::cout << "PASS: Interface " << iface << " exists\n";
    else check_fail("Interface " + iface + " not found");

    if (check_process("sshd")) std::cout << "PASS: sshd is running\n";
    else check_fail("sshd not running. Fix: sudo systemctl start sshd");

    if (check_process("rsyslogd")) std::cout << "PASS: rsyslogd is running\n";
    else std::cout << "WARN: rsyslogd not running (journal-only setups do not populate /var/log by default)\n";

    if (access(auth_log.c_str(), R_OK) == 0) std::cout << "PASS: " << auth_log << " readable\n";
    else check_fail(auth_log + " not readable. Fix: ensure rsyslog is logging auth authpriv to it");

    if (access(access_log.c_str(), R_OK) == 0) std::cout << "PASS: " << access_log << " readable\n";
    else std::cout << "WARN: " << access_log << " not readable\n";

    auto check_ssh_conf = [&](const std::string& p) {
        std::ifstream f(p);
        std::string line;
        while (std::getline(f, line)) {
            if (line.find("PasswordAuthentication") != std::string::npos && line[0] != '#') return line;
        }
        return std::string("");
    };
    std::string pwd_auth = check_ssh_conf("/etc/ssh/sshd_config");
    if (pwd_auth.empty()) {
        std::error_code ec;
        if (std::filesystem::exists("/etc/ssh/sshd_config.d", ec)) {
            for (const auto& entry : std::filesystem::directory_iterator("/etc/ssh/sshd_config.d", ec)) {
            pwd_auth = check_ssh_conf(entry.path());
            if (!pwd_auth.empty()) break;
        }
        }
    }
    if (pwd_auth.find("yes") != std::string::npos) std::cout << "PASS: " << pwd_auth << "\n";
    else std::cout << "WARN: PasswordAuth not explicitly 'yes'. Failed password lines will not appear in logs if disabled!\n";

    if (ifindex > 0) {
        __u32 prog_id = 0;
        if (bpf_xdp_query_id(ifindex, 0, &prog_id) == 0 && prog_id > 0) {
            check_fail("XDP program already attached (ID: " + std::to_string(prog_id) + "). Fix: sudo ./engine cleanup " + iface);
        } else {
            std::cout << "PASS: No existing XDP program attached to " << iface << "\n";
        }
    }

    if (!all_pass) return 1;

    std::string mode_str = enforce_mode ? "ENFORCE" : "DETECT";

    std::cout << "=== ENGINE STARTUP BANNER ===\n";
    std::cout << "Interface: " << iface << "\n";
    std::cout << "XDP Mode:  Auto\n";
    std::cout << "Mode:      " << mode_str << "\n";
    std::cout << "TTL:       " << ttl << "s\n";
    std::cout << "Threshold: " << threshold << "\n";
    std::cout << "Window:    " << window << "s\n";
    std::cout << "Auth Log:  " << auth_log << "\n";
    std::cout << "Access Log:" << access_log << "\n";
    std::cout << "Allowed:   ";
    for (auto ip : allow) std::cout << ip_to_string(ip) << " ";
    std::cout << "\nDashboard: http://127.0.0.1:5000/?showcase=1\n";
    std::cout << "=============================\n";
    
    struct sigaction sa{};
    sa.sa_handler = [](int) { g_running = false; };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    try {
        Storage storage{"engine.db"};
        storage.wipe_history();
        storage.insert_action({"mode_change", mode_str, get_iso_time_str(), ""});

        RuleEngine rule_engine{"rules.yaml"};
        // override_rules removed to respect rules.yaml

        std::string bpf_obj = "xdp_prog.bpf.o";
        char proc_exe[256];
        ssize_t len = readlink("/proc/self/exe", proc_exe, sizeof(proc_exe)-1);
        if (len != -1) {
            proc_exe[len] = '\0';
            std::string exe_path(proc_exe);
            size_t last_slash = exe_path.find_last_of('/');
            if (last_slash != std::string::npos) {
                std::string bpf_path = exe_path.substr(0, last_slash) + "/xdp_prog.bpf.o";
                if (access(bpf_path.c_str(), R_OK) == 0) bpf_obj = bpf_path;
            }
        }

        XdpEngine engine{bpf_obj, iface};
        BlockList blocklist{engine.allowed_fd(), engine.blocked_fd(), engine.stats_fd(), engine.proto_stats_fd(), allow, &storage};
        
        PlaybookRunner::BlockCallback block_cb = [&](const std::string& ip_str, const std::string& rule, int seconds) -> int {
            auto ip = parse_ipv4_local(ip_str);
            if (!ip) return -1;
            if (blocklist.is_allowed(*ip)) return 1;
            
            if (!enforce_mode) {
                print_log("[DETECTED]", "would block " + ip_str + " (detect mode)", "\x1b[34m");
                storage.insert_action({"detected", ip_str, get_iso_time_str(), rule});
                return 1;
            }
            return blocklist.block(*ip, rule, std::chrono::seconds(seconds), false, false) ? 0 : -1;
        };
        
        PlaybookRunner::RecordCallback record_cb = [&](const ActionRecord& act) {
            storage.insert_action(act);
        };
        
        Notifier notifier;
        PlaybookRunner::NotifyCallback notify_cb = [&](const Alert& a) {
            notifier.notify(a);
        };
        
        PlaybookRunner::OffenseCallback off_cb = [&](const std::string& ip) {
            return storage.get_offense_count(ip);
        };
        PlaybookRunner::RecordOffenseCallback rec_off_cb = [&](const std::string& ip) {
            storage.record_offense(ip);
        };
        
        PlaybookRunner runner{"playbooks.yaml", "known_ips.txt", "blocklist.txt", block_cb, record_cb, notify_cb, off_cb, rec_off_cb};
        
        EventCallback on_event = [&](const Event& e) {
            if (e.type == "ssh_failed") {
                print_log("[AUTH]", "SSH failure from " + e.src_ip + " (" + e.user + ")", "\x1b[33m");
            } else if (e.type == "port_scan") {
                print_log("[SCAN]", "Port scan from " + e.src_ip, "\x1b[33m");
            } else if (e.type.find("http_") == 0) {
                print_log("[WEB]", e.type + " from " + e.src_ip, "\x1b[33m");
            } else if (e.type == "rate_limit_exceeded") {
                print_log("[FLOOD]", "SYN rate limit exceeded from " + e.src_ip, "\x1b[33m");
            }
            storage.insert_event(e);
            
            auto alerts = rule_engine.process(e);
            for (auto a : alerts) { 
                runner.execute(a); 
                storage.insert_alert(a);
            }
        };

        SshDetector detector{auth_log, on_event};
        std::jthread watcher{[&detector](std::stop_token st) { detector.run(st); }};
        
        HttpDetector http_detector{access_log, rule_engine, on_event};
        std::jthread http_watcher{[&http_detector](std::stop_token st) { http_detector.watch_loop(st); }};

        auto handle_event = [](void* ctx, void* data, size_t size) -> int {
            if (size < sizeof(drop_event)) return 0;
            auto* d = static_cast<const drop_event*>(data);
            auto* on_event_ptr = static_cast<EventCallback*>(ctx);
            Event e;
            e.ts_iso = get_iso_time_str();
            e.source = "xdp";
            if (d->reason == REASON_RATELIMIT) e.type = "rate_limit_exceeded";
            else if (d->reason == REASON_PORTSCAN) e.type = "port_scan";
            else if (d->reason == REASON_ICMP) e.type = "icmp_seen";
            else e.type = "xdp_drop";
            e.src_ip = ip_to_string(d->src_ip);
            e.severity = 4;
            (*on_event_ptr)(e);
            return 0;
        };

        RingBufPtr rb{ring_buffer__new(engine.events_fd(), handle_event, &on_event, nullptr)};
        if (!rb) throw std::runtime_error("failed to create ring buffer");
        std::jthread rb_poller{[&rb, &runner](std::stop_token st) {
            while (!st.stop_requested()) {
                ring_buffer__poll(rb.get(), 100);
                runner.check_expiries();
            }
        }};
        
        auto get_xdp_mode = [](const std::string& ifname) -> std::string {
            int ifindex = if_nametoindex(ifname.c_str());
            if (ifindex == 0) return "none";
            DECLARE_LIBBPF_OPTS(bpf_xdp_query_opts, opts);
            if (bpf_xdp_query(ifindex, 0, &opts) < 0) return "none";
            switch (opts.attach_mode) {
                case XDP_ATTACHED_DRV: return "native";
                case XDP_ATTACHED_SKB: return "skb";
                case XDP_ATTACHED_HW: return "offload";
                default: return "none";
            }
        };

        uint64_t last_dropped = 0;
        
        std::jthread metrics_poller{[&](std::stop_token st) {
            while (!st.stop_requested()) {
                std::mutex m; std::unique_lock lk(m);
                if (std::condition_variable_any().wait_for(lk, st, 2s, []{return false;})) {
                    break;
                }
                
                auto [dropped, passed, tcp, udp, icmp, other] = blocklist.get_stats();
                struct timespec ts;
                clock_gettime(CLOCK_REALTIME, &ts);
                
                std::string xdp_mode = get_xdp_mode(engine.get_ifname());
                storage.insert_metrics(ts.tv_sec, dropped, passed, tcp, udp, icmp, other, engine.get_limit(), enforce_mode ? "ENFORCE" : "DETECT");
                
                if (dropped > last_dropped) {
                    uint64_t rate = (dropped - last_dropped) / 2;
                    print_log("[DROPPING]", "total=" + std::to_string(dropped) + " rate=" + std::to_string(rate) + "/s", "\x1b[31m");
                    last_dropped = dropped;
                }
            }
        }};

        log_info("XDP attached to " + iface + ". Commands: mode [detect|enforce|show] | allow <ip> | unallow <ip> | block <ip> | unblock <ip> | list | stats | alerts | approve <id> | deny <id> | quit");

        auto process_command = [&](const std::string& line, std::function<void(const std::string&)> out) {
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
        };

        std::jthread socket_listener{[&](std::stop_token st) {
            const char* sock_path = "/run/xdp_engine.sock";
            unlink(sock_path);
            int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
            if (server_fd < 0) return;
            
            struct sockaddr_un addr{};
            addr.sun_family = AF_UNIX;
            strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);
            
            if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
                chmod(sock_path, 0600);
                listen(server_fd, 5);
                
                struct timeval tv{1, 0};
                setsockopt(server_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                
                while (!st.stop_requested()) {
                    int client_fd = accept(server_fd, nullptr, nullptr);
                    if (client_fd >= 0) {
                        struct ucred ucred{};
                        socklen_t len = sizeof(struct ucred);
                        if (getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED, &ucred, &len) == 0 && ucred.uid == 0) {
                            char buf[257];
                            int n = read(client_fd, buf, 256);
                            if (n > 0) {
                                buf[n] = '\0';
                                std::string req(buf);
                                req.erase(req.find_last_not_of(" \t\r\n") + 1);
                                process_command(req, [client_fd](const std::string& msg) {
                                    std::string out = msg + "\n";
                                    write(client_fd, out.c_str(), out.length());
                                });
                            }
                        }
                        close(client_fd);
                    }
                }
            }
            close(server_fd);
            unlink(sock_path);
        }};

        std::string line;
        if (isatty(STDIN_FILENO)) {
            while (g_running && std::getline(std::cin, line)) {
                process_command(line, [](const std::string& msg) { log_info(msg); });
            }
        }
        
        if (g_running) {
            log_info("running in daemon mode, control via engine-cli");
            while (g_running) {
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }
        }
        log_info("shutting down, detaching XDP");
    } catch (const std::exception& e) {
        std::cerr << "fatal: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
