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
    std::string label; // Added for enrichment
    bool requires_approval = false;
    
    nlohmann::json to_json() const {
        return nlohmann::json{
            {"rule", rule},
            {"src_ip", src_ip},
            {"severity", severity},
            {"mitre", mitre},
            {"action", action},
            {"block_seconds", block_seconds},
            {"ts_iso", ts_iso},
            {"label", label},
            {"requires_approval", requires_approval}
        };
    }
};

struct RuleDef {
    std::string name;
    std::string type = "threshold"; // "threshold" or "sequence"
    std::string match_type; // For threshold
    std::size_t threshold = 1; // For threshold
    std::chrono::seconds window;
    std::string severity;
    std::vector<std::string> mitre; // Changed to vector since prompt says mitre: [T1046, T1110]
    std::string action;
    int block_seconds;
    bool requires_approval = false;
    
    // For sequence rules
    std::vector<std::string> steps;
    
    // For signatures
    std::vector<std::string> patterns;
};

class RuleEngine {
public:
    RuleEngine(const std::string& yaml_path);
    std::vector<Alert> process(const Event& e);
    const std::vector<RuleDef>& get_rules() const { return rules_; }

private:
    std::vector<RuleDef> rules_;
    using TimePoint = std::chrono::steady_clock::time_point;
    // rule_name -> (ip -> deque of timestamps)
    std::unordered_map<std::string, std::unordered_map<std::string, std::deque<TimePoint>>> windows_;
    
    struct SeqState {
        std::size_t next_step_idx = 0;
        TimePoint start_time;
    };
    // rule_name -> (ip -> SeqState)
    std::unordered_map<std::string, std::unordered_map<std::string, SeqState>> seq_states_;
};

#endif // RULE_ENGINE_H
