#ifndef HTTP_DETECTOR_H
#define HTTP_DETECTOR_H

#include <string>
#include <thread>
#include <functional>
#include <regex>
#include "event.h"
#include "rule_engine.h"

class HttpDetector {
public:
    using EventCallback = std::function<void(const Event&)>;
    HttpDetector(const std::string& log_file, const RuleEngine& rule_engine, EventCallback cb);
    ~HttpDetector();

private:
    void watch_loop(std::stop_token st);
    void process_line(const std::string& line);

    std::string log_file_;
    EventCallback cb_;
    std::jthread watcher_;
    
    // Extracted signatures
    std::vector<std::regex> traversal_patterns_;
    std::vector<std::regex> sqli_patterns_;
    std::vector<std::regex> scanner_patterns_;
};

#endif // HTTP_DETECTOR_H
