#include "playbook_runner.h"
#include <yaml-cpp/yaml.h>
#include <fstream>
#include <sstream>
#include <iostream>
#include <stdexcept>

#include <arpa/inet.h>

static bool is_valid_ip_pr(const std::string& ip) {
    struct in_addr addr;
    return inet_pton(AF_INET, ip.c_str(), &addr) == 1;
}

PlaybookRunner::PlaybookRunner(const std::string& yaml_path, const std::string& known_ips_path,
                               const std::string& blocklist_path,
                               BlockCallback block_cb, RecordCallback record_cb, NotifyCallback notify_cb,
                               OffenseCallback off_cb, RecordOffenseCallback rec_off_cb)
    : block_cb_(std::move(block_cb)), record_cb_(std::move(record_cb)), notify_cb_(std::move(notify_cb)),
      offense_cb_(std::move(off_cb)), record_offense_cb_(std::move(rec_off_cb))
{
    // Load known IPs
    std::ifstream in(known_ips_path);
    std::string line;
    while (std::getline(in, line)) {
        std::istringstream iss(line);
        std::string ip, label;
        if (iss >> ip >> label) {
            if (is_valid_ip_pr(ip)) known_ips_[ip] = label;
        }
    }
    
    // Load public blocklist
    std::ifstream bl_in(blocklist_path);
    if (bl_in.is_open()) {
        while (std::getline(bl_in, line)) {
            // Trim whitespace and skip comments
            line.erase(0, line.find_first_not_of(" \t\r\n"));
            line.erase(line.find_last_not_of(" \t\r\n") + 1);
            if (line.empty() || line[0] == '#') continue;
            
            if (is_valid_ip_pr(line)) {
                known_ips_[line] = "in_public_blocklist";
            }
        }
    }

    // Load playbooks
    YAML::Node config = YAML::LoadFile(yaml_path);
    for (YAML::const_iterator it = config.begin(); it != config.end(); ++it) {
        std::string rule_name = it->first.as<std::string>();
        std::vector<std::string> steps;
        YAML::Node steps_node = it->second;
        for (const auto& step_node : steps_node) {
            std::string step_name = step_node["step"].as<std::string>();
            if (step_name != "enrich" && step_name != "block" && step_name != "notify" && step_name != "record") {
                throw std::runtime_error("Unknown playbook step: " + step_name);
            }
            steps.push_back(step_name);
            
            if (step_name == "block") {
                if (step_node["ladder"]) {
                    ladders_[rule_name] = step_node["ladder"].as<std::vector<int>>();
                } else {
                    ladders_[rule_name] = {600, 3600, 86400};
                }
            }
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
            if (alert.requires_approval) {
                std::lock_guard<std::mutex> lock(approval_mutex_);
                int id = next_approval_id_++;
                pending_approvals_[id] = {alert, now + std::chrono::minutes(2)};
                std::cout << "[PLAYBOOK] " << alert.rule << " step=" << step << " result=pending (id=" << id << ")" << std::endl;
                break; // Pause playbook
            }

            // Check rate cap
            while (!recent_blocks_.empty() && (now - recent_blocks_.front()) > std::chrono::seconds(60)) {
                recent_blocks_.pop_front();
            }
            if (recent_blocks_.size() >= 20) {
                std::cout << "[PLAYBOOK] rate cap exceeded, pausing blocks" << std::endl;
                result = "skipped: ratecap";
            } else if (block_cb_) {
                int count = offense_cb_ ? offense_cb_(alert.src_ip) : 0;
                
                // If it's a known malicious IP (from enrichment, maybe), we can skip to highest tier later.
                // For now, just use the ladder.
                if (alert.label == "in_public_blocklist") {
                    count = 2;
                }
                
                int max_idx = ladders_[alert.rule].size() - 1;
                int idx = std::min(count, max_idx);
                int duration = ladders_[alert.rule].empty() ? alert.block_seconds : ladders_[alert.rule][idx];
                
                int cb_res = block_cb_(alert.src_ip, alert.rule, duration);
                if (cb_res == 1) {
                    result = "skipped: allowlisted/dry-run";
                } else if (cb_res == -1) {
                    result = "failed";
                    std::cout << "[PLAYBOOK] " << alert.rule << " step=" << step << " result=" << result << std::endl;
                    break; // Stop on failed block
                } else {
                    recent_blocks_.push_back(now);
                    if (record_offense_cb_) record_offense_cb_(alert.src_ip);
                    std::cout << "[ESCALATE] " << alert.src_ip << " offense=" << (count + 1) << " block=" << duration << "\n";
                    alert.block_seconds = duration; // Update for record step
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

void PlaybookRunner::approve(int id) {
    Alert alert;
    {
        std::lock_guard<std::mutex> lock(approval_mutex_);
        auto it = pending_approvals_.find(id);
        if (it == pending_approvals_.end()) {
            std::cout << "[PLAYBOOK] Invalid or expired approval id " << id << std::endl;
            return;
        }
        alert = it->second.alert;
        pending_approvals_.erase(it);
    }
    std::cout << "[PLAYBOOK] approved block for " << alert.src_ip << std::endl;

    if (block_cb_ && block_cb_(alert.src_ip, alert.rule, alert.block_seconds) == 0) {
        if (record_cb_) {
            ActionRecord act{alert.ts_iso, alert.src_ip, "block", alert.rule};
            record_cb_(act);
        }
    }
}

void PlaybookRunner::deny(int id) {
    Alert alert;
    {
        std::lock_guard<std::mutex> lock(approval_mutex_);
        auto it = pending_approvals_.find(id);
        if (it == pending_approvals_.end()) {
            std::cout << "[PLAYBOOK] Invalid or expired approval id " << id << std::endl;
            return;
        }
        alert = it->second.alert;
        pending_approvals_.erase(it);
    }
    std::cout << "[PLAYBOOK] denied block for " << alert.src_ip << std::endl;
    if (record_cb_) {
        ActionRecord act{alert.ts_iso, alert.src_ip, "deny", alert.rule};
        record_cb_(act);
    }
}

void PlaybookRunner::check_expiries() {
    std::lock_guard<std::mutex> lock(approval_mutex_);
    auto now = std::chrono::steady_clock::now();
    for (auto it = pending_approvals_.begin(); it != pending_approvals_.end(); ) {
        if (now > it->second.expiry) {
            std::cout << "[PLAYBOOK] auto-denied block for " << it->second.alert.src_ip << std::endl;
            if (record_cb_) {
                ActionRecord act{it->second.alert.ts_iso, it->second.alert.src_ip, "auto-deny", it->second.alert.rule};
                record_cb_(act);
            }
            it = pending_approvals_.erase(it);
        } else {
            ++it;
        }
    }
}
