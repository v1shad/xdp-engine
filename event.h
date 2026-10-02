#ifndef EVENT_H
#define EVENT_H

#include <string>
#include <nlohmann/json.hpp>

struct Event {
    std::string ts_iso;   // ISO 8601 timestamp
    std::string source;   // "ssh_log" or "xdp_ringbuf"
    std::string type;     // "ssh_failed" or "packet_dropped"
    std::string src_ip;   // The IP address associated with the event
    std::string user;     // Username (if applicable, e.g., for SSH)
    int severity;         // 1 to 5 (or similar scale)

    nlohmann::json to_json() const {
        return nlohmann::json{
            {"ts_iso", ts_iso},
            {"source", source},
            {"type", type},
            {"src_ip", src_ip},
            {"user", user},
            {"severity", severity}
        };
    }
};

#endif // EVENT_H
