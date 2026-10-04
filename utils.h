#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <optional>
#include <cstdint>
#include <arpa/inet.h>

inline std::optional<std::uint32_t> parse_ipv4(const std::string& text) {
    in_addr addr{};
    if (inet_pton(AF_INET, text.c_str(), &addr) != 1) return std::nullopt;
    return addr.s_addr;
}

#endif
