#include "playbook_runner.h"
#include <yaml-cpp/yaml.h>
#include <fstream>
#include <sstream>
#include <iostream>
#include <stdexcept>

PlaybookRunner::PlaybookRunner(const std::string& yaml_path, const std::string& known_ips_path,
                               BlockCallback block_cb, RecordCallback record_cb, NotifyCallback notify_cb)
    : block_cb_(std::move(block_cb)), record_cb_(std::move(record_cb)), notify_cb_(std::move(notify_cb)) 
{
    // Load known IPs
    std::ifstream in(known_ips_path);
    std::string line;
    while (std::getline(in, line)) {
        std::istringstream iss(line);
        std::string ip, label;
        if (iss >> ip >> label) {
            known_ips_[ip] = label;
        }
    }

    // Load playbooks
    YAML::Node config = YAML::LoadFile(yaml_path);
    for (YAML::const_iterator it = config.begin(); it != config.end(); ++it) {
        std::string rule_name = it->first.as<std::string>();
        std::vector<std::string> steps;
        for (const auto& step_node : it->second) {
            std::string step_name = step_node["step"].as<std::string>();
            if (step_name != "enrich" && step_name != "block" && step_name != "notify" && step_name != "record") {
                throw std::runtime_error("Unknown playbook step: " + step_name);
            }
            steps.push_back(step_name);
        }
        playbooks_[rule_name] = steps;
    }
}

void PlaybookRunner::execute(Alert& alert) {
    auto it = playbooks_.find(alert.rule);
    if (it == playbooks_.end()) {
        return; // No playbook for this rule
    }

    auto now = std::chrono::steady_clock::now();
    std::string run_key = alert.rule + ":" + alert.src_ip;
    if (last_run_.count(run_key) > 0 && (now - last_run_[run_key]) < std::chrono::seconds(60)) {
        return; // Cooldown active
    }
    last_run_[run_key] = now;

    for (const auto& step : it->second) {
        std::string result = "ok";
        
        if (step == "enrich") {
            auto label_it = known_ips_.find(alert.src_ip);
            if (label_it != known_ips_.end()) {
                alert.label = label_it->second;
            } else {
                alert.label = "unknown";
            }
        } else if (step == "block") {
            // Check rate cap
            while (!recent_blocks_.empty() && (now - recent_blocks_.front()) > std::chrono::seconds(60)) {
                recent_blocks_.pop_front();
            }
            if (recent_blocks_.size() >= 20) {
                std::cout << "[PLAYBOOK] rate cap exceeded, pausing blocks" << std::endl;
                result = "skipped: ratecap";
            } else if (block_cb_) {
                int cb_res = block_cb_(alert.src_ip, alert.rule, alert.block_seconds);
                if (cb_res == 1) {
                    result = "skipped: allowlisted/dry-run";
                } else if (cb_res == -1) {
                    result = "failed";
                    std::cout << "[PLAYBOOK] " << alert.rule << " step=" << step << " result=" << result << std::endl;
                    break; // Stop on failed block
                } else {
                    recent_blocks_.push_back(now);
                }
            }
        } else if (step == "notify") {
            if (notify_cb_) notify_cb_(alert);
        } else if (step == "record") {
            if (record_cb_) {
                ActionRecord act{alert.ts_iso, alert.src_ip, "block", alert.rule};
                record_cb_(act);
            }
        }
        
        std::cout << "[PLAYBOOK] " << alert.rule << " step=" << step << " result=" << result << std::endl;
    }
}
