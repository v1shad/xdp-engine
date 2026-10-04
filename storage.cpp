#include "storage.h"
#include <stdexcept>
#include <iostream>
#include <fstream>

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
    
    sqlite3_prepare_v2(db_.get(), "INSERT INTO alerts(ts, rule, src_ip, severity, mitre, action, block_seconds, label) VALUES(?, ?, ?, ?, ?, ?, ?, ?)", -1, &stmt, nullptr);
    insert_alert_stmt_.reset(stmt);
    
    sqlite3_prepare_v2(db_.get(), "INSERT INTO actions(ts, src_ip, action, reason) VALUES(?, ?, ?, ?)", -1, &stmt, nullptr);
    insert_action_stmt_.reset(stmt);
    
    sqlite3_prepare_v2(db_.get(), "SELECT a.ts, a.rule, a.src_ip, a.action, a.label, o.offense_count FROM alerts a LEFT JOIN offenders o ON a.src_ip = o.ip ORDER BY a.id DESC LIMIT ?", -1, &stmt, nullptr);
    get_alerts_stmt_.reset(stmt);
    
    sqlite3_prepare_v2(db_.get(), "INSERT INTO metrics(ts, dropped, passed, tcp, udp, icmp, other) VALUES(?, ?, ?, ?, ?, ?, ?)", -1, &stmt, nullptr);
    insert_metrics_stmt_.reset(stmt);
    
    sqlite3_prepare_v2(db_.get(), "DELETE FROM metrics WHERE ts < ?", -1, &stmt, nullptr);
    delete_metrics_stmt_.reset(stmt);
    
    sqlite3_prepare_v2(db_.get(), "SELECT offense_count, last_offense FROM offenders WHERE ip = ?", -1, &stmt, nullptr);
    get_offense_stmt_.reset(stmt);
    
    sqlite3_prepare_v2(db_.get(), "INSERT INTO offenders(ip, offense_count, last_offense) VALUES(?, 1, ?) ON CONFLICT(ip) DO UPDATE SET offense_count = offense_count + 1, last_offense = ?", -1, &stmt, nullptr);
    record_offense_stmt_.reset(stmt);
    
    sqlite3_prepare_v2(db_.get(), "UPDATE offenders SET offense_count = 0 WHERE ip = ?", -1, &stmt, nullptr);
    reset_offense_stmt_.reset(stmt);
}

void Storage::exec_schema() {
    const char* schema = R"(
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, source TEXT, type TEXT, src_ip TEXT, user TEXT, severity INTEGER
        );
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, rule TEXT, src_ip TEXT, severity TEXT, mitre TEXT, action TEXT, block_seconds INTEGER, label TEXT
        );
        CREATE TABLE IF NOT EXISTS actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, src_ip TEXT, action TEXT, reason TEXT
        );
        CREATE TABLE IF NOT EXISTS metrics (
            ts INTEGER, dropped INTEGER, passed INTEGER, tcp INTEGER, udp INTEGER, icmp INTEGER, other INTEGER
        );
        CREATE TABLE IF NOT EXISTS offenders (
            ip TEXT PRIMARY KEY,
            offense_count INTEGER,
            last_offense INTEGER
        );
    )";
    char* err = nullptr;
    if (sqlite3_exec(db_.get(), schema, nullptr, nullptr, &err) != SQLITE_OK) {
        std::string e = err;
        sqlite3_free(err);
        throw std::runtime_error("sqlite schema error: " + e);
    }
    
    // Attempt to add label column for backwards compatibility
    sqlite3_exec(db_.get(), "ALTER TABLE alerts ADD COLUMN label TEXT", nullptr, nullptr, nullptr);
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
    sqlite3_bind_text(insert_alert_stmt_.get(), 8, a.label.c_str(), -1, SQLITE_STATIC);
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

void Storage::print_last_alerts(int limit, std::function<void(const std::string&)> out) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    sqlite3_reset(get_alerts_stmt_.get());
    sqlite3_bind_int(get_alerts_stmt_.get(), 1, limit);
    
    int count = 0;
    while (sqlite3_step(get_alerts_stmt_.get()) == SQLITE_ROW) {
        const unsigned char* ts = sqlite3_column_text(get_alerts_stmt_.get(), 0);
        const unsigned char* rule = sqlite3_column_text(get_alerts_stmt_.get(), 1);
        const unsigned char* ip = sqlite3_column_text(get_alerts_stmt_.get(), 2);
        const unsigned char* action = sqlite3_column_text(get_alerts_stmt_.get(), 3);
        const unsigned char* label = sqlite3_column_text(get_alerts_stmt_.get(), 4);
        int offense = sqlite3_column_type(get_alerts_stmt_.get(), 5) != SQLITE_NULL ? sqlite3_column_int(get_alerts_stmt_.get(), 5) : 0;
        
        std::string line = "  [" + std::string(ts ? (const char*)ts : "") + "] " +
                           std::string(rule ? (const char*)rule : "") + " | IP: " +
                           std::string(ip ? (const char*)ip : "") + " | Action: " +
                           std::string(action ? (const char*)action : "");
                  
        if (label && label[0]) line += " | Label: " + std::string((const char*)label);
        if (offense > 0) line += " | Offense: " + std::to_string(offense);
        
        out(line);
        count++;
    }
    if (count == 0) {
        out("  (no alerts found)");
    }
}

void Storage::insert_metrics(uint64_t ts, uint64_t dropped, uint64_t passed, uint64_t tcp, uint64_t udp, uint64_t icmp, uint64_t other) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    
    // Insert new metrics
    sqlite3_reset(insert_metrics_stmt_.get());
    sqlite3_bind_int64(insert_metrics_stmt_.get(), 1, ts);
    sqlite3_bind_int64(insert_metrics_stmt_.get(), 2, dropped);
    sqlite3_bind_int64(insert_metrics_stmt_.get(), 3, passed);
    sqlite3_bind_int64(insert_metrics_stmt_.get(), 4, tcp);
    sqlite3_bind_int64(insert_metrics_stmt_.get(), 5, udp);
    sqlite3_bind_int64(insert_metrics_stmt_.get(), 6, icmp);
    sqlite3_bind_int64(insert_metrics_stmt_.get(), 7, other);
    if (sqlite3_step(insert_metrics_stmt_.get()) != SQLITE_DONE) {
        std::cerr << "[error] metrics insert failed: " << sqlite3_errmsg(db_.get()) << "\n";
    }
    
    // Delete old metrics (> 1 hour old)
    uint64_t cutoff = ts - 3600;
    sqlite3_reset(delete_metrics_stmt_.get());
    sqlite3_bind_int64(delete_metrics_stmt_.get(), 1, cutoff);
    sqlite3_step(delete_metrics_stmt_.get());
}

int Storage::get_offense_count(const std::string& ip) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    sqlite3_reset(get_offense_stmt_.get());
    sqlite3_bind_text(get_offense_stmt_.get(), 1, ip.c_str(), -1, SQLITE_STATIC);
    
    int count = 0;
    if (sqlite3_step(get_offense_stmt_.get()) == SQLITE_ROW) {
        count = sqlite3_column_int(get_offense_stmt_.get(), 0);
        uint64_t last_offense = sqlite3_column_int64(get_offense_stmt_.get(), 1);
        uint64_t now = std::time(nullptr);
        if (now > last_offense && (now - last_offense > 7 * 24 * 3600)) {
            count = 0; // expired
            sqlite3_reset(reset_offense_stmt_.get());
            sqlite3_bind_text(reset_offense_stmt_.get(), 1, ip.c_str(), -1, SQLITE_STATIC);
            sqlite3_step(reset_offense_stmt_.get());
        }
    }
    return count;
}

void Storage::record_offense(const std::string& ip) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    uint64_t now = std::time(nullptr);
    sqlite3_reset(record_offense_stmt_.get());
    sqlite3_bind_text(record_offense_stmt_.get(), 1, ip.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(record_offense_stmt_.get(), 2, now);
    sqlite3_bind_int64(record_offense_stmt_.get(), 3, now);
    sqlite3_step(record_offense_stmt_.get());
}

static std::string escape_md(const std::string& text) {
    std::string out;
    for (char c : text) {
        if (c == '<' || c == '>' || c == '&' || c == '*' || c == '_' || c == '`' || c == '[' || c == ']') {
            out += '\\';
        }
        out += c;
    }
    return out;
}

void Storage::generate_report(const std::string& path) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    std::ofstream out(path);
    if (!out) return;
    
    out << "# Intrusion Engine Report\n\n";
    
    sqlite3_stmt* stmt = nullptr;
    
    // Time range
    if (sqlite3_prepare_v2(db_.get(), "SELECT min(ts), max(ts) FROM alerts", -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char* min_ts = sqlite3_column_text(stmt, 0);
            const unsigned char* max_ts = sqlite3_column_text(stmt, 1);
            out << "**Time Range:** " << (min_ts ? (const char*)min_ts : "N/A") << " to " 
                << (max_ts ? (const char*)max_ts : "N/A") << "\n\n";
        }
        sqlite3_finalize(stmt);
    }
    
    out << "## Alerts by Rule\n";
    if (sqlite3_prepare_v2(db_.get(), "SELECT rule, count(*) FROM alerts GROUP BY rule ORDER BY count(*) DESC", -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            out << "- " << escape_md((const char*)sqlite3_column_text(stmt, 0)) << ": " << sqlite3_column_int(stmt, 1) << "\n";
        }
        sqlite3_finalize(stmt);
    }
    out << "\n";
    
    out << "## Alerts by Severity\n";
    if (sqlite3_prepare_v2(db_.get(), "SELECT severity, count(*) FROM alerts GROUP BY severity ORDER BY count(*) DESC", -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            out << "- " << escape_md((const char*)sqlite3_column_text(stmt, 0)) << ": " << sqlite3_column_int(stmt, 1) << "\n";
        }
        sqlite3_finalize(stmt);
    }
    out << "\n";
    
    out << "## MITRE Techniques\n";
    if (sqlite3_prepare_v2(db_.get(), "SELECT mitre, count(*) FROM alerts WHERE mitre != '' GROUP BY mitre ORDER BY count(*) DESC", -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            out << "- " << escape_md((const char*)sqlite3_column_text(stmt, 0)) << ": " << sqlite3_column_int(stmt, 1) << "\n";
        }
        sqlite3_finalize(stmt);
    }
    out << "\n";
    
    out << "## Actions Taken\n";
    if (sqlite3_prepare_v2(db_.get(), "SELECT action, count(*) FROM actions GROUP BY action ORDER BY count(*) DESC", -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            out << "- " << escape_md((const char*)sqlite3_column_text(stmt, 0)) << ": " << sqlite3_column_int(stmt, 1) << "\n";
        }
        sqlite3_finalize(stmt);
    }
    out << "\n";
    
    out << "## Top Attackers\n";
    out << "| IP | Alerts | Offense Count | Label |\n";
    out << "|---|---|---|---|\n";
    if (sqlite3_prepare_v2(db_.get(), "SELECT a.src_ip, count(*), o.offense_count, a.label FROM alerts a LEFT JOIN offenders o ON a.src_ip = o.ip GROUP BY a.src_ip ORDER BY count(*) DESC LIMIT 10", -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char* ip = sqlite3_column_text(stmt, 0);
            int count = sqlite3_column_int(stmt, 1);
            int offense = sqlite3_column_type(stmt, 2) != SQLITE_NULL ? sqlite3_column_int(stmt, 2) : 0;
            const unsigned char* label = sqlite3_column_text(stmt, 3);
            
            out << "| " << (ip ? escape_md((const char*)ip) : "") 
                << " | " << count 
                << " | " << offense 
                << " | " << (label ? escape_md((const char*)label) : "") << " |\n";
        }
        sqlite3_finalize(stmt);
    }
    out << "\n";
}
