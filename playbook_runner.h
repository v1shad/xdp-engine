#ifndef PLAYBOOK_RUNNER_H
#define PLAYBOOK_RUNNER_H

#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include "rule_engine.h"
#include "storage.h"

class PlaybookRunner {
public:
    using BlockCallback = std::function<int(const std::string& ip, const std::string& rule, int seconds)>;
    using RecordCallback = std::function<void(const ActionRecord&)>;
    using NotifyCallback = std::function<void(const Alert&)>;

    PlaybookRunner(const std::string& yaml_path, const std::string& known_ips_path,
                   BlockCallback block_cb, RecordCallback record_cb, NotifyCallback notify_cb);

    void execute(Alert& alert);

private:
    std::unordered_map<std::string, std::vector<std::string>> playbooks_;
    std::unordered_map<std::string, std::string> known_ips_;
    BlockCallback block_cb_;
    RecordCallback record_cb_;
    NotifyCallback notify_cb_;
    
    // Safety state
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> last_run_;
    std::deque<std::chrono::steady_clock::time_point> recent_blocks_;
};

#endif // PLAYBOOK_RUNNER_H
