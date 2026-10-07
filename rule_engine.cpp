#include <unordered_set>
#include "rule_engine.h"
#include <arpa/inet.h>
#include <iostream>

RuleEngine::RuleEngine(const std::string& yaml_path) {
    YAML::Node config = YAML::LoadFile(yaml_path);
    for (const auto& node : config) {
        RuleDef r;
        r.name = node["name"].as<std::string>();
        if (node["type"]) r.type = node["type"].as<std::string>();
        if (node["match_type"]) r.match_type = node["match_type"].as<std::string>();
        
        if (r.type == "threshold") {
            r.threshold = node["threshold"].as<std::size_t>();
            r.window = std::chrono::seconds(node["window_seconds"].as<int>());
        } else if (r.type == "sequence") {
            r.steps = node["steps"].as<std::vector<std::string>>();
            r.window = std::chrono::seconds(node["within_seconds"].as<int>());
            
            static const std::unordered_set<std::string> valid = {"port_scan", "ssh_failed", "http_traversal", "http_sqli", "http_scanner"};
            for (const auto& step : r.steps) {
                if (valid.find(step) == valid.end()) {
                    throw std::runtime_error("Unknown step: " + step);
                }
            }
        }
        
        r.severity = node["severity"].as<std::string>();
        
        if (node["mitre"].IsSequence()) {
            r.mitre = node["mitre"].as<std::vector<std::string>>();
        } else {
            r.mitre.push_back(node["mitre"].as<std::string>());
        }
        
        r.action = node["action"].as<std::string>();
        r.block_seconds = node["block_seconds"].as<int>();
        if (node["approval"]) r.requires_approval = node["approval"].as<bool>();
        if (node["patterns"]) r.patterns = node["patterns"].as<std::vector<std::string>>();
        
        rules_.push_back(r);
    }
}

// IP validation: NEVER trust logs when passing strings to a system
static bool is_valid_ip(const std::string& ip) {
    struct in_addr addr;
    return inet_pton(AF_INET, ip.c_str(), &addr) == 1;
}

std::vector<Alert> RuleEngine::process(const Event& e) {
    std::vector<Alert> generated_alerts;
    
    // Strict IP validation
    if (!is_valid_ip(e.src_ip)) return generated_alerts;

    auto now = std::chrono::steady_clock::now();

    for (const auto& rule : rules_) {
        if (rule.type == "threshold") {
            if (rule.match_type == e.type) {
                auto& ip_map = windows_[rule.name];
                auto& attempts = ip_map[e.src_ip];
                attempts.push_back(now);

                while (!attempts.empty() && now - attempts.front() > rule.window) {
                    attempts.pop_front();
                }

                if (attempts.size() >= rule.threshold) {
                    Alert a;
                    a.rule = rule.name;
                    a.src_ip = e.src_ip;
                    a.severity = rule.severity;
                    if (!rule.mitre.empty()) {
                        a.mitre = rule.mitre[0];
                        for (size_t i = 1; i < rule.mitre.size(); ++i) a.mitre += "," + rule.mitre[i];
                    }
                    a.action = rule.action;
                    a.block_seconds = rule.block_seconds;
                    a.ts_iso = e.ts_iso;
                    a.requires_approval = rule.requires_approval;
                    generated_alerts.push_back(a);
                    
                    ip_map.erase(e.src_ip);
                }
            }
        } else if (rule.type == "sequence") {
            auto& state = seq_states_[rule.name][e.src_ip];
            if (state.next_step_idx == 0) {
                // Not in sequence yet, check if this is the first step
                if (!rule.steps.empty() && rule.steps[0] == e.type) {
                    state.next_step_idx = 1;
                    state.start_time = now;
                }
            } else {
                // In sequence, check expiration
                if (now - state.start_time > rule.window) {
                    // Expired, reset and check if it's the first step again
                    state.next_step_idx = 0;
                    if (!rule.steps.empty() && rule.steps[0] == e.type) {
                        state.next_step_idx = 1;
                        state.start_time = now;
                    }
                } else if (rule.steps[state.next_step_idx] == e.type) {
                    // Next step matched
                    state.next_step_idx++;
                }
            }
            
            // Check if sequence completed
            if (state.next_step_idx > 0 && state.next_step_idx == rule.steps.size()) {
                Alert a;
                a.rule = rule.name;
                a.src_ip = e.src_ip;
                a.severity = rule.severity;
                if (!rule.mitre.empty()) {
                    a.mitre = rule.mitre[0];
                    for (size_t i = 1; i < rule.mitre.size(); ++i) a.mitre += "," + rule.mitre[i];
                }
                a.action = rule.action;
                a.block_seconds = rule.block_seconds;
                a.ts_iso = e.ts_iso;
                a.requires_approval = rule.requires_approval;
                generated_alerts.push_back(a);
                
                seq_states_[rule.name].erase(e.src_ip);
            }
        }
    }
    return generated_alerts;
}

void RuleEngine::override_rules(int threshold, int window) {
    for (auto& r : rules_) {
        if (r.type == "threshold") {
            if (threshold > 0) r.threshold = threshold;
            if (window > 0) r.window = std::chrono::seconds(window);
        }
    }
}
