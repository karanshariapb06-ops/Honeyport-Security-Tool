from flask import Flask, jsonify, render_template
import sqlite3

app = Flask(__name__)
DB = "honeyport.db"


def ensure_scan_type_column():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='events'")
    if cur.fetchone():
        cur.execute("PRAGMA table_info(events)")
        columns = [row[1] for row in cur.fetchall()]
        if "scan_type" not in columns:
            cur.execute("ALTER TABLE events ADD COLUMN scan_type TEXT")
    conn.commit()
    conn.close()


ensure_scan_type_column()


def run_query(sql, params=()):
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(sql, params)
    rows = cur.fetchall()
    conn.close()
    return rows


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/top_ips')
def top_ips():
    rows = run_query('SELECT src_ip, COUNT(*) as count FROM events GROUP BY src_ip ORDER BY count DESC LIMIT 10')
    return jsonify([dict(r) for r in rows])


@app.route('/api/top_ports')
def top_ports():
    rows = run_query('SELECT dest_port, COUNT(*) as count FROM events GROUP BY dest_port ORDER BY count DESC LIMIT 10')
    # ensure dest_port is string for labels
    out = [dict(r) for r in rows]
    return jsonify(out)


@app.route('/api/attacks_per_hour')
def attacks_per_hour():
    rows = run_query("SELECT strftime('%Y-%m-%d %H:00', event_time) as hour, COUNT(*) as count FROM events GROUP BY hour ORDER BY hour")
    return jsonify([dict(r) for r in rows])


@app.route('/api/attacks_per_day')
def attacks_per_day():
    rows = run_query("SELECT strftime('%Y-%m-%d', event_time) as day, COUNT(*) as count FROM events GROUP BY day ORDER BY day")
    return jsonify([dict(r) for r in rows])


@app.route('/api/protocols')
def protocols():
    rows = run_query('SELECT protocol, COUNT(*) as count FROM events GROUP BY protocol')
    return jsonify([dict(r) for r in rows])


@app.route('/api/scan_types')
def scan_types():
    rows = run_query(
        "SELECT COALESCE(scan_type, 'unknown') as scan_type, COUNT(*) as count"
        " FROM events GROUP BY scan_type ORDER BY count DESC"
    )
    return jsonify([dict(r) for r in rows])


@app.route('/api/summary')
def summary():
    total_rows = run_query('SELECT COUNT(*) as total_attacks, COUNT(DISTINCT src_ip) as unique_ips FROM events')
    total = dict(total_rows[0]) if total_rows else {'total_attacks': 0, 'unique_ips': 0}
    top_scan_types = run_query(
        "SELECT COALESCE(scan_type, 'unknown') as scan_type, COUNT(*) as count"
        " FROM events GROUP BY scan_type ORDER BY count DESC LIMIT 5"
    )
    top_protocols = run_query(
        "SELECT COALESCE(protocol, 'unknown') as protocol, COUNT(*) as count"
        " FROM events GROUP BY protocol ORDER BY count DESC LIMIT 1"
    )
    top_protocol = dict(top_protocols[0]) if top_protocols else {'protocol': 'unknown', 'count': 0}
    return jsonify({
        'total_attacks': total['total_attacks'],
        'unique_ips': total['unique_ips'],
        'top_scan_types': [dict(r) for r in top_scan_types],
        'top_protocol': top_protocol['protocol'],
        'top_protocol_count': top_protocol['count']
    })


@app.route('/api/tables')
def tables():
    rows = run_query("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
    return jsonify([r['name'] for r in rows])


@app.route('/api/table/<table_name>')
def table_rows(table_name):
    valid_tables = [r['name'] for r in run_query("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
    if table_name not in valid_tables:
        return jsonify({'error': 'Invalid table name'}), 400

    column_rows = run_query(f'PRAGMA table_info("{table_name}")')
    columns = [r['name'] for r in column_rows]
    rows = run_query(f'SELECT * FROM "{table_name}" LIMIT 100')
    return jsonify({
        'table': table_name,
        'columns': columns,
        'rows': [dict(r) for r in rows]
    })


@app.route('/api/logs')
def logs():
    rows = run_query(
        'SELECT src_ip, src_port, dest_port, protocol, COALESCE(scan_type, "unknown") as scan_type, event_time FROM events ORDER BY event_time DESC LIMIT 100'
    )
    return jsonify([dict(r) for r in rows])


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
