with open('storage.cpp', 'r') as f:
    c = f.read()

old = """    // Delete old metrics (> 1 hour old)
    uint64_t cutoff = ts - 3600;
    sqlite3_reset(delete_metrics_stmt_.get());
    sqlite3_bind_int64(delete_metrics_stmt_.get(), 1, cutoff);
    sqlite3_step(delete_metrics_stmt_.get());
}"""
new = """    // Delete old metrics (> 1 hour old)
    uint64_t cutoff = ts - 3600;
    sqlite3_reset(delete_metrics_stmt_.get());
    sqlite3_bind_int64(delete_metrics_stmt_.get(), 1, cutoff);
    sqlite3_step(delete_metrics_stmt_.get());
    
    // Prune old events, alerts, and actions (older than 24h) periodically
    static int prune_ticks = 0;
    if (++prune_ticks >= 30) { // every ~60 seconds (since metrics are polled every 2s)
        prune_ticks = 0;
        char* err = nullptr;
        sqlite3_exec(db_.get(), "DELETE FROM events WHERE ts < datetime('now', '-24 hours');", nullptr, nullptr, &err);
        if (err) sqlite3_free(err);
        sqlite3_exec(db_.get(), "DELETE FROM alerts WHERE ts < datetime('now', '-24 hours');", nullptr, nullptr, &err);
        if (err) sqlite3_free(err);
        sqlite3_exec(db_.get(), "DELETE FROM actions WHERE ts < datetime('now', '-24 hours');", nullptr, nullptr, &err);
        if (err) sqlite3_free(err);
    }
}"""

c = c.replace(old, new)
with open('storage.cpp', 'w') as f:
    f.write(c)
