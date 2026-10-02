#include "storage.h"
#include <stdexcept>
#include <iostream>

Storage::Storage(const std::string& db_path) {
    sqlite3* db_raw = nullptr;
    if (sqlite3_open(db_path.c_str(), &db_raw) != SQLITE_OK) {
        throw std::runtime_error("failed to open sqlite db");
    }
    db_.reset(db_raw);
    
    exec_schema();
    
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db_.get(), "INSERT INTO events(ts, source, type, src_ip, user, severity) VALUES(?, ?, ?, ?, ?, ?)", -1, &stmt, nullptr);
    insert_event_stmt_.reset(stmt);
    
    sqlite3_prepare_v2(db_.get(), "INSERT INTO alerts(ts, rule, src_ip, severity, mitre, action, block_seconds) VALUES(?, ?, ?, ?, ?, ?, ?)", -1, &stmt, nullptr);
    insert_alert_stmt_.reset(stmt);
    
    sqlite3_prepare_v2(db_.get(), "INSERT INTO actions(ts, src_ip, action, reason) VALUES(?, ?, ?, ?)", -1, &stmt, nullptr);
    insert_action_stmt_.reset(stmt);
    
    sqlite3_prepare_v2(db_.get(), "SELECT ts, rule, src_ip, action FROM alerts ORDER BY id DESC LIMIT ?", -1, &stmt, nullptr);
    get_alerts_stmt_.reset(stmt);
}

void Storage::exec_schema() {
    const char* schema = R"(
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, source TEXT, type TEXT, src_ip TEXT, user TEXT, severity INTEGER
        );
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, rule TEXT, src_ip TEXT, severity TEXT, mitre TEXT, action TEXT, block_seconds INTEGER
        );
        CREATE TABLE IF NOT EXISTS actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, src_ip TEXT, action TEXT, reason TEXT
        );
    )";
    char* err = nullptr;
    if (sqlite3_exec(db_.get(), schema, nullptr, nullptr, &err) != SQLITE_OK) {
        std::string e = err;
        sqlite3_free(err);
        throw std::runtime_error("sqlite schema error: " + e);
    }
}

void Storage::insert_event(const Event& e) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    sqlite3_reset(insert_event_stmt_.get());
    sqlite3_bind_text(insert_event_stmt_.get(), 1, e.ts_iso.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(insert_event_stmt_.get(), 2, e.source.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(insert_event_stmt_.get(), 3, e.type.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(insert_event_stmt_.get(), 4, e.src_ip.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(insert_event_stmt_.get(), 5, e.user.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(insert_event_stmt_.get(), 6, e.severity);
    sqlite3_step(insert_event_stmt_.get());
}

void Storage::insert_alert(const Alert& a) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    sqlite3_reset(insert_alert_stmt_.get());
    sqlite3_bind_text(insert_alert_stmt_.get(), 1, a.ts_iso.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(insert_alert_stmt_.get(), 2, a.rule.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(insert_alert_stmt_.get(), 3, a.src_ip.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(insert_alert_stmt_.get(), 4, a.severity.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(insert_alert_stmt_.get(), 5, a.mitre.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(insert_alert_stmt_.get(), 6, a.action.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int(insert_alert_stmt_.get(), 7, a.block_seconds);
    sqlite3_step(insert_alert_stmt_.get());
}

void Storage::insert_action(const ActionRecord& act) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    sqlite3_reset(insert_action_stmt_.get());
    sqlite3_bind_text(insert_action_stmt_.get(), 1, act.ts_iso.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(insert_action_stmt_.get(), 2, act.src_ip.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(insert_action_stmt_.get(), 3, act.action.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(insert_action_stmt_.get(), 4, act.reason.c_str(), -1, SQLITE_STATIC);
    sqlite3_step(insert_action_stmt_.get());
}

void Storage::print_last_alerts(int limit) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    sqlite3_reset(get_alerts_stmt_.get());
    sqlite3_bind_int(get_alerts_stmt_.get(), 1, limit);
    
    int count = 0;
    while (sqlite3_step(get_alerts_stmt_.get()) == SQLITE_ROW) {
        const unsigned char* ts = sqlite3_column_text(get_alerts_stmt_.get(), 0);
        const unsigned char* rule = sqlite3_column_text(get_alerts_stmt_.get(), 1);
        const unsigned char* ip = sqlite3_column_text(get_alerts_stmt_.get(), 2);
        const unsigned char* action = sqlite3_column_text(get_alerts_stmt_.get(), 3);
        std::cout << "  [" << (ts ? (const char*)ts : "") << "] " 
                  << (rule ? (const char*)rule : "") << " | IP: " 
                  << (ip ? (const char*)ip : "") << " | Action: " 
                  << (action ? (const char*)action : "") << std::endl;
        count++;
    }
    if (count == 0) {
        std::cout << "  (no alerts found)" << std::endl;
    }
}
