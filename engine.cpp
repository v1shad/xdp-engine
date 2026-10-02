// engine.cpp — user-space half of the Tier 3 Automated Intrusion Mitigation Engine
#include <arpa/inet.h>      // inet_pton / inet_ntop (text IP <-> binary IP)
#include <net/if.h>         // if_nametoindex ("eth0" -> interface number)
#include <signal.h>         // sigaction
#include <bpf/bpf.h>        // bpf_map_update_elem, bpf_map_lookup_elem, ... (syscall wrappers)
#include <bpf/libbpf.h>     // bpf_object__open_file, bpf_program__attach_xdp, ...
#include "common.h"

#include <atomic>
#include <cerrno>
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

using namespace std::chrono_literals;   // enables 200ms, 60s literals
using Clock = std::chrono::steady_clock; // monotonic clock: immune to system time changes

/* ---------- tiny thread-safe logger (two threads print: avoid garbled output) ---------- */
static void log(const std::string& msg) {
    static std::mutex io_mutex;
    std::lock_guard lock{io_mutex};      // CTAD: template argument deduced automatically
    std::cout << msg << std::endl;
}

/* ---------- RAII wrappers: C resources -> automatic cleanup ---------- */
struct ObjDeleter  { void operator()(bpf_object* o) const noexcept { if (o) bpf_object__close(o); } };
struct LinkDeleter { void operator()(bpf_link*   l) const noexcept { if (l) bpf_link__destroy(l); } };
using ObjPtr  = std::unique_ptr<bpf_object, ObjDeleter>;
using LinkPtr = std::unique_ptr<bpf_link,  LinkDeleter>;

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
    BlockList(int allowed_fd, int blocked_fd, int stats_fd, const std::unordered_set<std::uint32_t>& allow)
    : allowed_fd_{allowed_fd}, blocked_fd_{blocked_fd}, stats_fd_{stats_fd},
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

    void print_blocked() const {
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
                log("  " + ip_to_string(next) + "  dropped=" + std::to_string(rec.hits) + " expires in " + expire_str);
                ++count;
            }
            key = next; prev = &key;
        }
        log("  (" + std::to_string(count) + " blocked IPs)");
    }

    void print_stats() const {
        log("  packets dropped=" + std::to_string(read_stat(0)) +
        "  passed=" + std::to_string(read_stat(1)));
    }

private:
    // A PERCPU map returns one value PER CPU, so we sum them.
    std::uint64_t read_stat(std::uint32_t idx) const {
        const int ncpu = libbpf_num_possible_cpus();
        if (ncpu <= 0) return 0;
        std::vector<std::uint64_t> per_cpu(static_cast<std::size_t>(ncpu));
        if (bpf_map_lookup_elem(stats_fd_, &idx, per_cpu.data()) != 0) return 0;
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

    int allowed_fd_, blocked_fd_, stats_fd_;
    std::jthread sweeper_;
};

/* ---------- XdpEngine: load + attach, with automatic detach ---------- */
class XdpEngine {
public:
    XdpEngine(const std::string& obj_path, const std::string& ifname) {
        const unsigned ifindex = if_nametoindex(ifname.c_str());   // "eth0" -> e.g. 2
        if (ifindex == 0) throw std::runtime_error("no such interface: " + ifname);

        obj_.reset(bpf_object__open_file(obj_path.c_str(), nullptr));  // (1) parse the ELF file
        if (!obj_) throw std::runtime_error("open failed: " + std::string{std::strerror(errno)});

        if (int err = bpf_object__load(obj_.get()))                    // (2) create maps, verify, JIT
            throw std::runtime_error("load failed (verifier?): " + std::string{std::strerror(-err)});

        bpf_program* prog = bpf_object__find_program_by_name(obj_.get(), "xdp_firewall");
        bpf_map* allowed  = bpf_object__find_map_by_name(obj_.get(), "allowed_ips");
        bpf_map* blocked  = bpf_object__find_map_by_name(obj_.get(), "blocked_ips");
        bpf_map* stats    = bpf_object__find_map_by_name(obj_.get(), "stats");
        if (!prog || !allowed || !blocked || !stats) throw std::runtime_error("program/map not found in object");

        allowed_fd_ = bpf_map__fd(allowed);
        blocked_fd_ = bpf_map__fd(blocked);       // integer handles for the bpf() syscall
        stats_fd_   = bpf_map__fd(stats);

        link_.reset(bpf_program__attach_xdp(prog, static_cast<int>(ifindex)));  // (3) hook into NIC
        if (!link_) throw std::runtime_error("attach failed: " + std::string{std::strerror(errno)});
    }
    int allowed_fd() const { return allowed_fd_; }
    int blocked_fd() const { return blocked_fd_; }
    int stats_fd()   const { return stats_fd_; }

private:
    ObjPtr  obj_;      // declared first => destroyed LAST (link must go before the object)
    LinkPtr link_;     // destroyed first => XDP program detaches from the interface
    int allowed_fd_{-1}, blocked_fd_{-1}, stats_fd_{-1};
};

/* ---------- SSH brute-force detector (runs on its own jthread) ---------- */
class SshDetector {
public:
    SshDetector(BlockList& bl, std::string path, std::size_t threshold, std::chrono::seconds window)
    : blocklist_{bl}, path_{std::move(path)}, threshold_{threshold}, window_{window} {}

    void run(std::stop_token st) {              // jthread supplies the stop_token
        std::ifstream in{path_};
        if (!in) { log("[error] cannot open log: " + path_); return; }
        in.seekg(0, std::ios::end);             // start at END: only react to NEW lines (like tail -f)
        std::string line;
        while (!st.stop_requested()) {
            if (std::getline(in, line)) handle_line(line);
            else { in.clear(); std::this_thread::sleep_for(200ms); }  // EOF: reset flags, wait
        }
    }

private:
    void handle_line(const std::string& line) {
        static const std::regex re{
            R"(Failed password for (?:invalid user )?\S+ from (\d{1,3}(?:\.\d{1,3}){3}))"};
        std::smatch m;
        if (!std::regex_search(line, m, re)) return;
        auto ip = parse_ipv4(m[1].str());
        if (!ip) return;

        const auto now = Clock::now();
        auto& attempts = tries_[*ip];                       // deque of timestamps for this IP
        attempts.push_back(now);
        while (!attempts.empty() && now - attempts.front() > window_)
            attempts.pop_front();                           // slide the window forward

        if (attempts.size() >= threshold_) {
            const auto n = attempts.size();
            if (blocklist_.block(*ip, "ssh brute force, " + std::to_string(n) + " failures"))
                tries_.erase(*ip);                          // 'attempts' is invalid after this line
        }
    }

    BlockList& blocklist_;
    std::string path_;
    std::size_t threshold_;
    std::chrono::seconds window_;
    std::unordered_map<std::uint32_t, std::deque<Clock::time_point>> tries_;
};

/* ---------- graceful Ctrl-C ---------- */
static std::atomic<bool> g_running{true};
extern "C" void on_signal(int) { g_running = false; }

int main(int argc, char** argv) {
    if (argc < 4) {
        std::cerr << "usage: sudo " << argv[0]
        << " <iface> <xdp_prog.bpf.o> <logfile> [--allow IP]...\n";
        return 2;
    }
    std::unordered_set<std::uint32_t> allow{*parse_ipv4("127.0.0.1")};
    for (int i = 4; i + 1 < argc; i += 2) {
        if (std::string_view{argv[i]} == "--allow") {
            if (auto ip = parse_ipv4(argv[i + 1])) allow.insert(*ip);
        }
    }

    struct sigaction sa{};                  // no SA_RESTART => blocking read is interrupted by Ctrl-C
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    try {
        XdpEngine engine{argv[2], argv[1]};                             // load + attach
        BlockList blocklist{engine.allowed_fd(), engine.blocked_fd(), engine.stats_fd(), allow};
        SshDetector detector{blocklist, argv[3], 5, 60s};               // 5 failures / 60 s
        std::jthread watcher{[&detector](std::stop_token st) { detector.run(st); }};

        log("[engine] XDP attached to " + std::string{argv[1]} +
        ". Commands: allow <ip> | unallow <ip> | block <ip> | unblock <ip> | list | stats | quit");

        std::string line;
        while (g_running && std::getline(std::cin, line)) {
            std::istringstream iss{line};
            std::string cmd, arg;
            iss >> cmd >> arg;
            if (cmd == "quit") break;
            else if (cmd == "list")  blocklist.print_blocked();
            else if (cmd == "stats") blocklist.print_stats();
            else if (cmd == "block" || cmd == "unblock" || cmd == "allow" || cmd == "unallow") {
                if (auto ip = parse_ipv4(arg)) {
                    if (cmd == "block") blocklist.block(*ip, "manual");
                    else if (cmd == "unblock") blocklist.unblock(*ip);
                    else if (cmd == "allow") blocklist.allow_ip(*ip);
                    else if (cmd == "unallow") blocklist.unallow_ip(*ip);
                } else log("[error] invalid IPv4 address");
            } else if (!cmd.empty()) log("[error] unknown command");
        }
        log("[engine] shutting down, detaching XDP");
    } catch (const std::exception& e) {
        std::cerr << "fatal: " << e.what() << "\n";
        return 1;
    }   // destructors run here in reverse order: watcher stops+joins, then link detaches
    return 0;
}
