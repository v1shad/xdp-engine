#ifndef RULE_ENGINE_H
#define RULE_ENGINE_H

#include <string>
#include <vector>
#include <chrono>
#include <deque>
#include <unordered_map>
#include <yaml-cpp/yaml.h>
#include <nlohmann/json.hpp>
#include "event.h"

struct Alert {
    std::string rule;
    std::string src_ip;
    std::string severity;
    std::string mitre;
    std::string action;
    int block_seconds;
    std::string ts_iso;
    
    nlohmann::json to_json() const {
        return nlohmann::json{
            {"rule", rule},
            {"src_ip", src_ip},
            {"severity", severity},
            {"mitre", mitre},
            {"action", action},
            {"block_seconds", block_seconds},
            {"ts_iso", ts_iso}
        };
    }
};

struct RuleDef {
    std::string name;
    std::string match_type;
    std::size_t threshold;
    std::chrono::seconds window;
    std::string severity;
    std::string mitre;
    std::string action;
    int block_seconds;
};

class RuleEngine {
public:
    RuleEngine(const std::string& yaml_path);
    std::vector<Alert> process(const Event& e);

private:
    std::vector<RuleDef> rules_;
    using TimePoint = std::chrono::steady_clock::time_point;
    // rule_name -> (ip -> deque of timestamps)
    std::unordered_map<std::string, std::unordered_map<std::string, std::deque<TimePoint>>> windows_;
};

#endif // RULE_ENGINE_H
