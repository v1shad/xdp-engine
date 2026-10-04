// engine.cpp — user-space half of the Tier 3 Automated Intrusion Mitigation Engine
#include <arpa/inet.h>      // inet_pton / inet_ntop (text IP <-> binary IP)
#include <net/if.h>         // if_nametoindex ("eth0" -> interface number)
#include <signal.h>         // sigaction
#include <bpf/bpf.h>        // bpf_map_update_elem, bpf_map_lookup_elem, ... (syscall wrappers)
#include <bpf/libbpf.h>     // bpf_object__open_file, bpf_program__attach_xdp, ...
#include "common.h"
#include "http_detector.h"

#include <atomic>
#include <cerrno>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <deque>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <numeric>
#include <optional>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include "event.h"
#include "rule_engine.h"
#include "storage.h"
#include "playbook_runner.h"
#include "notifier.h"

using namespace std::chrono_literals;   // enables 200ms, 60s literals
using Clock = std::chrono::steady_clock; // monotonic clock: immune to system time changes

using EventCallback = std::function<void(const Event&)>;

/* ---------- tiny thread-safe logger (two threads print: avoid garbled output) ---------- */
static void log(const std::string& msg) {
    static std::mutex io_mutex;
    std::lock_guard lock{io_mutex};      // CTAD: template argument deduced automatically
    std::cout << msg << std::endl;
}

/* ---------- RAII wrappers: C resources -> automatic cleanup ---------- */
struct ObjDeleter  { void operator()(bpf_object* o) const noexcept { if (o) bpf_object__close(o); } };
struct LinkDeleter { void operator()(bpf_link*   l) const noexcept { if (l) bpf_link__destroy(l); } };
struct RingDeleter { void operator()(ring_buffer* r) const noexcept { if (r) ring_buffer__free(r); } };
using ObjPtr  = std::unique_ptr<bpf_object, ObjDeleter>;
using LinkPtr = std::unique_ptr<bpf_link,  LinkDeleter>;
using RingBufPtr = std::unique_ptr<ring_buffer, RingDeleter>;

/* ---------- C++20 concept: only raw-copyable types may cross into the kernel ---------- */
template <typename T>
concept KernelPod = std::is_trivially_copyable_v<T>;   // the kernel memcpy's these bytes

template <KernelPod K, KernelPod V>
bool map_update(int fd, const K& key, const V& value) {
    return bpf_map_update_elem(fd, &key, &value, BPF_ANY) == 0;  // BPF_ANY = create or overwrite
}

/* ---------- IP helpers ---------- */
std::optional<std::uint32_t> parse_ipv4(const std::string& text) {
    in_addr addr{};
    if (inet_pton(AF_INET, text.c_str(), &addr) != 1) return std::nullopt; // invalid text
    return addr.s_addr;                      // already in NETWORK byte order, matching the packet
}

std::string ip_to_string(std::uint32_t ip_net) {
    char buf[INET_ADDRSTRLEN]{};
    in_addr addr{.s_addr = ip_net};          // C++20 designated initializer
    inet_ntop(AF_INET, &addr, buf, sizeof buf);
    return buf;
}

constexpr std::chrono::seconds DEFAULT_BLOCK_DURATION{600}; // 10 minutes

/* ---------- BlockList: the C++ face of the kernel maps ---------- */
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
        if (!map_update(allowed_fd_, ip, dummy)) {
            log(std::string{"[error] allow map update failed: "} + std::strerror(errno));
            return false;
        }
        log("[ALLOWED] " + ip_to_string(ip));
        // unblock it if it was blocked
        bpf_map_delete_elem(blocked_fd_, &ip);
        return true;
    }

    bool is_allowed(std::uint32_t ip) const {
        std::uint8_t dummy = 0;
        return bpf_map_lookup_elem(allowed_fd_, &ip, &dummy) == 0;
    }

    bool unallow_ip(std::uint32_t ip) {
        if (bpf_map_delete_elem(allowed_fd_, &ip) != 0) {
            log("[info] " + ip_to_string(ip) + " was not in allowlist");
            return false;
        }
        log("[UNALLOWED] " + ip_to_string(ip));
        return true;
    }

    bool block(std::uint32_t ip, std::string_view reason, std::chrono::seconds duration = DEFAULT_BLOCK_DURATION) {
        std::uint8_t dummy = 0;
        if (bpf_map_lookup_elem(allowed_fd_, &ip, &dummy) == 0) {
            log("[warn] refusing to block allow-listed " + ip_to_string(ip));
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
            log(std::string{"[error] map update failed: "} + std::strerror(errno));
            return false;
        }
        log("[BLOCKED] " + ip_to_string(ip) + " (" + std::string{reason} + ")");
        return true;
    }

    bool unblock(std::uint32_t ip) {
        if (bpf_map_delete_elem(blocked_fd_, &ip) != 0) {   // fails with ENOENT if absent
            log("[info] " + ip_to_string(ip) + " was not blocked");
            return false;
        }
        log("[UNBLOCKED] " + ip_to_string(ip));
        return true;
    }

    void print_blocked(std::function<void(const std::string&)> out) const {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        __u64 now = ts.tv_sec * 1000000000ULL + ts.tv_nsec;

        std::uint32_t key{}, next{};
        const std::uint32_t* prev = nullptr;               // nullptr => "give me the first key"
        int count = 0;
        while (bpf_map_get_next_key(blocked_fd_, prev, &next) == 0) {  // iterate the hash table
            struct block_record rec{};
            if (bpf_map_lookup_elem(blocked_fd_, &next, &rec) == 0) {
                std::string expire_str = "permanent";
                if (rec.expires_at_ns != 0) {
                    if (rec.expires_at_ns > now) {
                        __u64 remain = (rec.expires_at_ns - now) / 1000000000ULL;
                        expire_str = std::to_string(remain) + "s";
                    } else {
                        expire_str = "EXPIRED";
                    }
                }
                std::string off_str = "";
                if (storage_) {
                    int off = storage_->get_offense_count(ip_to_string(next));
                    if (off > 0) off_str = " offense=" + std::to_string(off);
                }
                out("  " + ip_to_string(next) + "  dropped=" + std::to_string(rec.hits) + " expires in " + expire_str + off_str);
                ++count;
            }
            key = next; prev = &key;
        }
        out("  (" + std::to_string(count) + " blocked IPs)");
    }

    void print_stats(std::function<void(const std::string&)> out) const {
        out("  packets dropped=" + std::to_string(read_stat(0)) +
        "  passed=" + std::to_string(read_stat(1)));
        out("  protocols: TCP=" + std::to_string(read_proto_stat(0)) +
        " UDP=" + std::to_string(read_proto_stat(1)) +
        " ICMP=" + std::to_string(read_proto_stat(2)) +
        " Other=" + std::to_string(read_proto_stat(3)));
    }

    std::tuple<std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t> get_stats() const {
        return {read_stat(0), read_stat(1), read_proto_stat(0), read_proto_stat(1), read_proto_stat(2), read_proto_stat(3)};
    }

private:
    std::uint64_t read_stat(std::uint32_t idx) const {
        const int ncpu = libbpf_num_possible_cpus();
        if (ncpu <= 0) return 0;
        std::vector<std::uint64_t> per_cpu(static_cast<std::size_t>(ncpu));
        if (bpf_map_lookup_elem(stats_fd_, &idx, per_cpu.data()) != 0) return 0;
        return std::accumulate(per_cpu.begin(), per_cpu.end(), std::uint64_t{0});
    }
    
    std::uint64_t read_proto_stat(std::uint32_t idx) const {
        const int ncpu = libbpf_num_possible_cpus();
        if (ncpu <= 0) return 0;
        std::vector<std::uint64_t> per_cpu(static_cast<std::size_t>(ncpu));
        if (bpf_map_lookup_elem(proto_stats_fd_, &idx, per_cpu.data()) != 0) return 0;
        return std::accumulate(per_cpu.begin(), per_cpu.end(), std::uint64_t{0});
    }

    void sweep_loop(std::stop_token st) {
        while (!st.stop_requested()) {
            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            __u64 now = ts.tv_sec * 1000000000ULL + ts.tv_nsec;

            std::uint32_t key{}, next{};
            const std::uint32_t* prev = nullptr;
            while (bpf_map_get_next_key(blocked_fd_, prev, &next) == 0) {
                struct block_record rec{};
                if (bpf_map_lookup_elem(blocked_fd_, &next, &rec) == 0) {
                    if (rec.expires_at_ns != 0 && rec.expires_at_ns < now) {
                        bpf_map_delete_elem(blocked_fd_, &next);
                        log("[EXPIRED] " + ip_to_string(next));
                    }
                }
                key = next; prev = &key;
            }
            // wait for 5 seconds or until stop requested
            std::mutex m; std::unique_lock lk(m);
            std::condition_variable_any().wait_for(lk, st, 5s, []{return false;});
        }
    }

    int allowed_fd_, blocked_fd_, stats_fd_, proto_stats_fd_;
    Storage* storage_;
    std::jthread sweeper_;
};

/* ---------- XdpEngine: load + attach, with automatic detach ---------- */
class XdpEngine {
public:
    XdpEngine(const std::string& obj_path, const std::string& ifname, bool fresh) {
        const unsigned ifindex = if_nametoindex(ifname.c_str());   // "eth0" -> e.g. 2
        if (ifindex == 0) throw std::runtime_error("no such interface: " + ifname);

        obj_.reset(bpf_object__open_file(obj_path.c_str(), nullptr));  // (1) parse the ELF file
        if (!obj_) throw std::runtime_error("open failed: " + std::string{std::strerror(errno)});

        bpf_map* allowed  = bpf_object__find_map_by_name(obj_.get(), "allowed_ips");
        bpf_map* blocked  = bpf_object__find_map_by_name(obj_.get(), "blocked_ips");
        if (!allowed || !blocked) throw std::runtime_error("missing map in object");

        // Trade-off: Persisting maps across restarts avoids dropping state (e.g. active blocks and allowlists
        // are remembered), but if the system crashes or bugs exist, stale entries might get stuck indefinitely.
        if (fresh) {
            unlink("/sys/fs/bpf/xdp_engine/allowed_ips");
            unlink("/sys/fs/bpf/xdp_engine/blocked_ips");
        }
        
        bool allow_exists = false, block_exists = false;
        
        int fd_allow = bpf_obj_get("/sys/fs/bpf/xdp_engine/allowed_ips");
        if (fd_allow >= 0) {
            bpf_map__reuse_fd(allowed, fd_allow);
            close(fd_allow);
            allow_exists = true;
        }
        
        int fd_block = bpf_obj_get("/sys/fs/bpf/xdp_engine/blocked_ips");
        if (fd_block >= 0) {
            bpf_map__reuse_fd(blocked, fd_block);
            close(fd_block);
            block_exists = true;
        }

        if (int err = bpf_object__load(obj_.get()))                    // (2) create maps, verify, JIT
            throw std::runtime_error("load failed (verifier?): " + std::string{std::strerror(-err)});
        
        mkdir("/sys/fs/bpf/xdp_engine", 0755);
        if (!allow_exists) bpf_map__pin(allowed, "/sys/fs/bpf/xdp_engine/allowed_ips");
        if (!block_exists) bpf_map__pin(blocked, "/sys/fs/bpf/xdp_engine/blocked_ips");

        bpf_program* prog = bpf_object__find_program_by_name(obj_.get(), "xdp_firewall");
        bpf_map* stats    = bpf_object__find_map_by_name(obj_.get(), "stats");
        bpf_map* events   = bpf_object__find_map_by_name(obj_.get(), "events");
        bpf_map* limits   = bpf_object__find_map_by_name(obj_.get(), "limits");
        bpf_map* pstats   = bpf_object__find_map_by_name(obj_.get(), "proto_stats");
        if (!prog || !allowed || !blocked || !stats || !events || !limits || !pstats) throw std::runtime_error("program/map not found in object");

        allowed_fd_ = bpf_map__fd(allowed);
        blocked_fd_ = bpf_map__fd(blocked);       // integer handles for the bpf() syscall
        stats_fd_   = bpf_map__fd(stats);
        events_fd_  = bpf_map__fd(events);
        limits_fd_  = bpf_map__fd(limits);
        proto_stats_fd_ = bpf_map__fd(pstats);
        
        // Write default limit
        set_limit(200);

        link_.reset(bpf_program__attach_xdp(prog, static_cast<int>(ifindex)));  // (3) hook into NIC
        if (!link_) throw std::runtime_error("attach failed: " + std::string{std::strerror(errno)});
    }
    int allowed_fd() const { return allowed_fd_; }
    int blocked_fd() const { return blocked_fd_; }
    int stats_fd()   const { return stats_fd_; }
    int events_fd()  const { return events_fd_; }
    int proto_stats_fd() const { return proto_stats_fd_; }
    
    void set_limit(std::uint32_t limit) {
        std::uint32_t zero = 0;
        if (!map_update(limits_fd_, zero, limit)) {
            log("[error] Failed to set limit");
        } else {
            log("[engine] SYN rate limit set to " + std::to_string(limit) + "/s");
        }
    }

private:
    ObjPtr  obj_;      // declared first => destroyed LAST (link must go before the object)
    LinkPtr link_;     // destroyed first => XDP program detaches from the interface
    int allowed_fd_{-1}, blocked_fd_{-1}, stats_fd_{-1}, events_fd_{-1}, limits_fd_{-1}, proto_stats_fd_{-1};
};

/* ---------- SSH brute-force detector (runs on its own jthread) ---------- */
class SshDetector {
public:
    SshDetector(std::string path, EventCallback cb)
    : path_{std::move(path)}, cb_{std::move(cb)} {}

    void run(std::stop_token st) {
        std::ifstream in{path_};
        if (!in) { log("[error] cannot open log: " + path_); return; }
        in.seekg(0, std::ios::end);
        std::string line;
        while (!st.stop_requested()) {
            if (std::getline(in, line)) handle_line(line);
            else { in.clear(); std::this_thread::sleep_for(200ms); }
        }
    }

private:
    void handle_line(const std::string& line) {
        static const std::regex re{
            R"(Failed password for (?:invalid user )?(\S+) from (\d{1,3}(?:\.\d{1,3}){3}))"};
        std::smatch m;
        if (!std::regex_search(line, m, re)) return;
        
        std::string user = m[1].str();
        std::string ip_str = m[2].str();
        
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        char time_buf[32];
        strftime(time_buf, sizeof(time_buf), "%Y-%m-%dT%H:%M:%SZ", gmtime(&ts.tv_sec));

        Event e;
        e.ts_iso = time_buf;
        e.source = "ssh_log";
        e.type = "ssh_failed";
        e.src_ip = ip_str;
        e.user = user;
        e.severity = 3;
        
        if (cb_) cb_(e);
    }

    std::string path_;
    EventCallback cb_;
};

#include "event.h"

static std::atomic<bool> g_running{true};
extern "C" void on_signal(int) { g_running = false; }

static int handle_event(void* ctx, void *data, size_t size) {
    if (size < sizeof(struct drop_event)) return 0;
    auto* ev = static_cast<struct drop_event*>(data);
    
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    char time_buf[32];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%dT%H:%M:%SZ", gmtime(&ts.tv_sec));

    Event e;
    e.ts_iso = time_buf;
    e.source = "xdp_ringbuf";
    if (ev->reason == REASON_RATELIMIT) {
        e.type = "rate_limit_exceeded";
    } else if (ev->reason == REASON_PORTSCAN) {
        e.type = "port_scan";
        e.severity = 4; // Or something
    } else {
        e.type = "packet_dropped";
    }
    e.src_ip = ip_to_string(ev->src_ip);
    e.user = "";
    e.severity = 5;
    
    if (ctx) {
        auto* cb = static_cast<EventCallback*>(ctx);
        (*cb)(e);
    }
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 4) {
        std::cerr << "usage: sudo " << argv[0]
        << " <iface> <xdp_prog.bpf.o> <logfile> [--allow IP]...\n";
        return 2;
    }
    std::unordered_set<std::uint32_t> allow{*parse_ipv4("127.0.0.1")};
    bool dry_run = false;
    bool fresh = false;
    for (int i = 4; i < argc; ++i) {
        if (std::string_view{argv[i]} == "--allow" && i + 1 < argc) {
            if (auto ip = parse_ipv4(argv[i + 1])) allow.insert(*ip);
            i++;
        } else if (std::string_view{argv[i]} == "--dry-run") {
            dry_run = true;
        } else if (std::string_view{argv[i]} == "--fresh") {
            fresh = true;
        }
    }

    struct sigaction sa{};                  // no SA_RESTART => blocking read is interrupted by Ctrl-C
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    try {
        Storage storage{"engine.db"};
        RuleEngine rule_engine{"rules.yaml"};

        XdpEngine engine{argv[2], argv[1], fresh};
        BlockList blocklist{engine.allowed_fd(), engine.blocked_fd(), engine.stats_fd(), engine.proto_stats_fd(), allow, &storage};
        
        // BlockCallback returns: 0 = ok, 1 = skipped (allowlist/dry-run), -1 = failed
        PlaybookRunner::BlockCallback block_cb = [&](const std::string& ip_str, const std::string& rule, int seconds) -> int {
            auto ip = parse_ipv4(ip_str);
            if (!ip) return -1;
            if (blocklist.is_allowed(*ip)) return 1; // skipped
            if (dry_run) {
                log("[DRY RUN] would block " + ip_str);
                return 1; // skipped
            }
            return blocklist.block(*ip, rule, std::chrono::seconds(seconds)) ? 0 : -1;
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
            log("[EVENT] " + e.to_json().dump());
            storage.insert_event(e);
            
            auto alerts = rule_engine.process(e);
            for (auto a : alerts) { // By value so we can mutate for enrichment
                runner.execute(a); // Modifies 'a' (enrichment, block_seconds)
                log("[ALERT] " + a.to_json().dump());
                storage.insert_alert(a);
            }
        };

        SshDetector detector{argv[3], on_event};
        std::jthread watcher{[&detector](std::stop_token st) { detector.run(st); }};
        
        HttpDetector http_detector{"/tmp/fake_access.log", rule_engine, on_event};

        RingBufPtr rb{ring_buffer__new(engine.events_fd(), handle_event, &on_event, nullptr)};
        if (!rb) throw std::runtime_error("failed to create ring buffer");
        std::jthread rb_poller{[&rb, &runner](std::stop_token st) {
            while (!st.stop_requested()) {
                ring_buffer__poll(rb.get(), 100);
                runner.check_expiries();
            }
        }};
        
        std::jthread metrics_poller{[&storage, &blocklist](std::stop_token st) {
            while (!st.stop_requested()) {
                std::mutex m; std::unique_lock lk(m);
                if (std::condition_variable_any().wait_for(lk, st, 2s, []{return false;})) {
                    break; // stop requested
                }
                
                auto [dropped, passed, tcp, udp, icmp, other] = blocklist.get_stats();
                struct timespec ts;
                clock_gettime(CLOCK_REALTIME, &ts);
                storage.insert_metrics(ts.tv_sec, dropped, passed, tcp, udp, icmp, other);
            }
        }};

        log("[engine] XDP attached to " + std::string{argv[1]} +
        ". Commands: allow <ip> | unallow <ip> | block <ip> | unblock <ip> | list | stats | alerts | approve <id> | deny <id> | quit");

        auto process_command = [&](const std::string& line, std::function<void(const std::string&)> out) {
            std::istringstream iss{line};
            std::string cmd, arg, arg2;
            iss >> cmd >> arg >> arg2;
            if (cmd == "quit") g_running = false;
            else if (cmd == "list")  blocklist.print_blocked(out);
            else if (cmd == "stats") blocklist.print_stats(out);
            else if (cmd == "alerts") storage.print_last_alerts(10, out);
            else if (cmd == "report") { storage.generate_report("report.md"); out("ok"); }
            else if (cmd == "limit") {
                try { engine.set_limit(std::stoi(arg)); out("ok"); } catch (...) { out("error"); }
            }
            else if (cmd == "approve") {
                try { runner.approve(std::stoi(arg)); out("ok"); } catch (...) { out("error"); }
            }
            else if (cmd == "deny") {
                try { runner.deny(std::stoi(arg)); out("ok"); } catch (...) { out("error"); }
            }
            else if (cmd == "block" || cmd == "unblock" || cmd == "allow" || cmd == "unallow") {
                if (auto ip = parse_ipv4(arg)) {
                    if (cmd == "block") {
                        int seconds = arg2.empty() ? 600 : std::stoi(arg2);
                        blocklist.block(*ip, "manual", std::chrono::seconds(seconds));
                        out("ok");
                    }
                    else if (cmd == "unblock") { blocklist.unblock(*ip); out("ok"); }
                    else if (cmd == "allow") { blocklist.allow_ip(*ip); out("ok"); }
                    else if (cmd == "unallow") { blocklist.unallow_ip(*ip); out("ok"); }
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
        while (g_running && std::getline(std::cin, line)) {
            process_command(line, [](const std::string& msg) { log(msg); });
        }
        log("[engine] shutting down, detaching XDP");
    } catch (const std::exception& e) {
        std::cerr << "fatal: " << e.what() << "\n";
        return 1;
    }   // destructors run here in reverse order: watcher stops+joins, then link detaches
    return 0;
}
