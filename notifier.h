#ifndef NOTIFIER_H
#define NOTIFIER_H

#include <string>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <stop_token>
#include "rule_engine.h"

class Notifier {
public:
    Notifier();
    ~Notifier();

    void notify(const Alert& alert);

private:
    void worker_loop(std::stop_token st);

    std::string webhook_url_;
    std::queue<std::string> queue_;
    std::mutex mutex_;
    std::condition_variable_any cv_;
    std::jthread worker_;
};

#endif // NOTIFIER_H
