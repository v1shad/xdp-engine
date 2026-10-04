#ifndef STORAGE_H
#define STORAGE_H

#include <string>
#include <vector>
#include <sqlite3.h>
#include <memory>
#include <mutex>
#include "event.h"
#include "rule_engine.h"

struct SqliteDeleter {
    void operator()(sqlite3* db) const noexcept {
        if (db) sqlite3_close(db);
    }
};
struct StmtDeleter {
    void operator()(sqlite3_stmt* stmt) const noexcept {
        if (stmt) sqlite3_finalize(stmt);
    }
};
using DbPtr = std::unique_ptr<sqlite3, SqliteDeleter>;
using StmtPtr = std::unique_ptr<sqlite3_stmt, StmtDeleter>;

struct ActionRecord {
    std::string ts_iso;
    std::string src_ip;
    std::string action;
    std::string reason;
};

class Storage {
public:
    Storage(const std::string& db_path);
    
    void insert_event(const Event& e);
    void insert_alert(const Alert& a);
    void insert_action(const ActionRecord& act);
    void insert_metrics(uint64_t ts, uint64_t dropped, uint64_t passed, uint64_t tcp, uint64_t udp, uint64_t icmp, uint64_t other);
    
    int get_offense_count(const std::string& ip);
    void record_offense(const std::string& ip);
    
    void print_last_alerts(int limit, std::function<void(const std::string&)> out);
    void generate_report(const std::string& path);

private:
    void exec_schema();
    
    std::mutex db_mutex_;
    DbPtr db_;
    StmtPtr insert_event_stmt_;
    StmtPtr insert_alert_stmt_;
    StmtPtr insert_action_stmt_;
    StmtPtr get_alerts_stmt_;
    StmtPtr insert_metrics_stmt_;
    StmtPtr delete_metrics_stmt_;
    StmtPtr get_offense_stmt_;
    StmtPtr record_offense_stmt_;
    StmtPtr reset_offense_stmt_;
};

#endif // STORAGE_H
