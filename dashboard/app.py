import sqlite3
import os
from flask import Flask, render_template, jsonify, g, request
import time

app = Flask(__name__)
DB_PATH = os.environ.get("ENGINE_DB", "/opt/xdp-engine/engine.db")
if not os.path.exists(DB_PATH) and os.path.exists("../engine.db"):
    DB_PATH = "../engine.db"
elif not os.path.exists(DB_PATH) and os.path.exists("engine.db"):
    DB_PATH = "engine.db"
print(f"[*] Dashboard starting. Using database: {DB_PATH}")

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        # Open READ-ONLY using URI
        uri = f"file:{DB_PATH}?mode=ro"
        db = g._database = sqlite3.connect(uri, uri=True)
        db.text_factory = lambda b: b.decode("utf-8", "replace")
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

@app.route('/')
def index():
    if request.args.get('showcase') == '1': return render_template('showcase.html')
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

@app.route('/api/feed')
def api_feed():
    db = get_db()
    query = """
    SELECT 'event' as row_type, ts, type as title, src_ip, 
      CASE severity 
        WHEN 1 THEN 'low' WHEN 2 THEN 'low' 
        WHEN 3 THEN 'medium' WHEN 4 THEN 'high' 
        WHEN 5 THEN 'critical' ELSE 'low' END as severity, 
      IFNULL(user, '') as detail, id FROM events
    UNION ALL
    SELECT 'alert' as row_type, ts, rule as title, src_ip, severity, action as detail, id FROM alerts
    UNION ALL
    SELECT 'action' as row_type, ts, action as title, src_ip, 'low' as severity, reason as detail, id FROM actions
    ORDER BY ts DESC LIMIT 50
    """
    rows = db.execute(query).fetchall()
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

@app.route('/api/alert/<int:alert_id>')
def api_alert(alert_id):
    db = get_db()
    alert = db.execute("""
        SELECT a.*, o.offense_count 
        FROM alerts a 
        LEFT JOIN offenders o ON a.src_ip = o.ip 
        WHERE a.id = ?
    """, (alert_id,)).fetchone()
    
    if not alert:
        return jsonify({"error": "not found"}), 404
        
    events = db.execute("""
        SELECT * FROM events 
        WHERE src_ip = ? AND ts <= ? AND ts >= datetime(?, '-5 minutes')
        ORDER BY ts DESC
    """, (alert['src_ip'], alert['ts'], alert['ts'])).fetchall()
    
    actions = db.execute("""
        SELECT * FROM actions 
        WHERE src_ip = ? AND ts >= ? AND ts <= datetime(?, '+1 minute')
        ORDER BY ts ASC
    """, (alert['src_ip'], alert['ts'], alert['ts'])).fetchall()
    
    return jsonify({
        "alert": dict(alert),
        "events": [dict(e) for e in events],
        "actions": [dict(a) for a in actions]
    })

@app.route('/api/panels')
def api_panels():
    db = get_db()
    
    rows = db.execute("""
        SELECT a.src_ip, a.block_seconds, 
               CAST((strftime('%s', 'now') - strftime('%s', a.ts)) AS INTEGER) as age,
               o.offense_count
        FROM alerts a 
        LEFT JOIN offenders o ON a.src_ip = o.ip 
        WHERE a.action = 'block' AND a.block_seconds > 0
    """).fetchall()
    
    active_blocks = []
    for r in rows:
        remain = r['block_seconds'] - r['age']
        if remain > 0:
            active_blocks.append({
                "ip": r['src_ip'],
                "remain": remain,
                "offense": r['offense_count'] or 0
            })
            
    offenders = db.execute("SELECT ip, offense_count, last_offense FROM offenders ORDER BY offense_count DESC, last_offense DESC LIMIT 10").fetchall()
    
    metrics = db.execute("SELECT tcp, udp, icmp, other, ts, syn_limit, xdp_mode FROM metrics ORDER BY ts DESC LIMIT 1").fetchone()
    if not metrics:
        metrics = {"tcp": 0, "udp": 0, "icmp": 0, "other": 0, "ts": 0, "syn_limit": 200, "xdp_mode": "unknown"}
        
    now = int(time.time())
    engine_running = (now - metrics['ts']) < 15
    try:
        db_size = os.path.getsize(DB_PATH)
    except:
        db_size = 0
        
    health = {
        "running": engine_running,
        "xdp_mode": metrics['xdp_mode'],
        "syn_limit": metrics['syn_limit'],
        "db_size": db_size
    }
    
    return jsonify({
        "active_blocks": active_blocks,
        "offenders": [dict(o) for o in offenders],
        "protocol_mix": {"tcp": metrics['tcp'], "udp": metrics['udp'], "icmp": metrics['icmp'], "other": metrics['other']},
        "health": health
    })

@app.route('/api/timeline')
def api_timeline():
    db = get_db()
    rows = db.execute("""
        SELECT strftime('%Y-%m-%d %H:%M', ts) as minute, severity, count(*) as count 
        FROM alerts 
        WHERE datetime(ts) > datetime('now', '-30 minutes') 
        GROUP BY minute, severity 
        ORDER BY minute
    """).fetchall()
    return jsonify([dict(r) for r in rows])

if __name__ == '__main__':
    # Bind to 127.0.0.1:5000, no debug mode
    app.run(host='127.0.0.1', port=5000, debug=False)
