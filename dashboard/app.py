import sqlite3
import os
from flask import Flask, render_template, jsonify, g
import time

app = Flask(__name__)
DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'engine.db'))

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        # Open READ-ONLY using URI
        uri = f"file:{DB_PATH}?mode=ro"
        db = g._database = sqlite3.connect(uri, uri=True)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/summary')
def api_summary():
    db = get_db()
    total_events = db.execute("SELECT count(*) FROM events").fetchone()[0]
    total_alerts = db.execute("SELECT count(*) FROM alerts").fetchone()[0]
    # Estimate active blocks (blocks in the last 10 minutes)
    active_blocks = db.execute("SELECT count(*) FROM actions WHERE action='block' AND datetime(ts) > datetime('now', '-10 minutes')").fetchone()[0]
    
    # Total drops (max dropped metric)
    row = db.execute("SELECT dropped FROM metrics ORDER BY ts DESC LIMIT 1").fetchone()
    total_drops = row[0] if row else 0
    
    return jsonify({
        "total_events": total_events,
        "total_alerts": total_alerts,
        "active_blocks": active_blocks,
        "total_drops": total_drops
    })

@app.route('/api/alerts')
def api_alerts():
    db = get_db()
    rows = db.execute("SELECT ts, rule, src_ip, severity, action FROM alerts ORDER BY id DESC LIMIT 20").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/top_attackers')
def api_top_attackers():
    db = get_db()
    rows = db.execute("SELECT src_ip, count(*) as count FROM events GROUP BY src_ip ORDER BY count DESC LIMIT 10").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/blocks_over_time')
def api_blocks_over_time():
    db = get_db()
    # SQLite strftime for minute grouping
    rows = db.execute("SELECT strftime('%Y-%m-%d %H:%M', ts) as minute, count(*) as count FROM actions WHERE action='block' AND datetime(ts) > datetime('now', '-30 minutes') GROUP BY minute ORDER BY minute").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route('/api/drops_per_sec')
def api_drops_per_sec():
    db = get_db()
    now = int(time.time())
    cutoff = now - 300
    rows = db.execute("SELECT ts, dropped FROM metrics WHERE ts > ? ORDER BY ts", (cutoff,)).fetchall()
    
    data = []
    for i in range(1, len(rows)):
        dt = rows[i]['ts'] - rows[i-1]['ts']
        if dt > 0:
            d_dropped = rows[i]['dropped'] - rows[i-1]['dropped']
            # handle counter wraps if any (unlikely for 64-bit but good practice)
            if d_dropped < 0: d_dropped = 0
            pps = d_dropped / dt
            data.append({"ts": rows[i]['ts'], "pps": round(pps, 2)})
            
    return jsonify(data)

if __name__ == '__main__':
    # Bind to 127.0.0.1:5000, no debug mode
    app.run(host='127.0.0.1', port=5000, debug=False)
