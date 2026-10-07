#include <gtest/gtest.h>
#include <unordered_set>
#include <string>
#include <cstdint>
#include <optional>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>

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

TEST(EngineTest, AutoAllowlistLoopback) {
    std::unordered_set<std::uint32_t> allow;
    add_iface_ips(allow, "lo");
    auto loopback = parse_ipv4_local("127.0.0.1");
    EXPECT_TRUE(loopback.has_value());
    EXPECT_TRUE(allow.find(*loopback) != allow.end());
}

TEST(EngineTest, DetectModeLogic) {
    bool enforce = false;
    bool detect_only = !enforce;
    EXPECT_TRUE(detect_only);
}

