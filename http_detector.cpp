#include "http_detector.h"
#include <fstream>
#include <iostream>
#include <arpa/inet.h>
#include <chrono>
#include <ctime>

static bool is_valid_ip(const std::string& ip) {
    struct in_addr addr;
    return inet_pton(AF_INET, ip.c_str(), &addr) == 1;
}

HttpDetector::HttpDetector(const std::string& log_file, const RuleEngine& rule_engine, EventCallback cb)
    : log_file_{log_file}, cb_{std::move(cb)} {
        
    for (const auto& r : rule_engine.get_rules()) {
        if (r.match_type == "http_traversal") {
            for (const auto& pat : r.patterns) traversal_patterns_.emplace_back(pat, std::regex::icase);
        } else if (r.match_type == "http_sqli") {
            for (const auto& pat : r.patterns) sqli_patterns_.emplace_back(pat, std::regex::icase);
        } else if (r.match_type == "http_scanner") {
            for (const auto& pat : r.patterns) scanner_patterns_.emplace_back(pat, std::regex::icase);
        }
    }
    
    watcher_ = std::jthread([this](std::stop_token st) { watch_loop(st); });
}

HttpDetector::~HttpDetector() {}

void HttpDetector::watch_loop(std::stop_token st) {
    std::ifstream ifs;
    
    while (!st.stop_requested()) {
        if (!ifs.is_open()) {
            ifs.open(log_file_);
            if (!ifs.is_open()) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                continue;
            }
            ifs.seekg(0, std::ios::end);
        }
        
        std::string line;
        while (std::getline(ifs, line)) {
            process_line(line);
        }
        
        if (ifs.eof()) {
            ifs.clear();
        } else {
            // maybe an error, reopen
            ifs.close();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

void HttpDetector::process_line(const std::string& line) {
    if (line.size() > 4096) return; // cap line length
    
    // Basic nginx combined format
    static std::regex log_rx(R"rx(^(\S+)\s+\S+\s+\S+\s+\[.*?\]\s+"(?:[A-Z]+)\s+(\S+)\s+.*?"\s+\d+\s+\d+\s+"(?:[^"]*)"\s+"([^"]*)")rx");
    std::smatch match;
    if (!std::regex_search(line, match, log_rx)) return;
    
    std::string ip = match[1].str();
    std::string path = match[2].str();
    std::string ua = match[3].str();
    
    if (!is_valid_ip(ip)) return;
    
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    char time_buf[32];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%dT%H:%M:%SZ", gmtime(&ts.tv_sec));
    
    auto emit = [&](const std::string& type) {
        Event e;
        e.ts_iso = time_buf;
        e.source = "http_log";
        e.type = type;
        e.src_ip = ip;
        e.user = "";
        e.severity = 3;
        cb_(e);
    };
    
    for (const auto& rx : traversal_patterns_) {
        if (std::regex_search(path, rx)) { emit("http_traversal"); return; }
    }
    for (const auto& rx : sqli_patterns_) {
        if (std::regex_search(path, rx) || std::regex_search(ua, rx)) { emit("http_sqli"); return; }
    }
    for (const auto& rx : scanner_patterns_) {
        if (std::regex_search(ua, rx)) { emit("http_scanner"); return; }
    }
}
