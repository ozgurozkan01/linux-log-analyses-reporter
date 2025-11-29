import sqlite3
import os
from datetime import datetime
from typing import Final

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_NAME: Final = os.path.join(BASE_DIR, "siem.db")
SCHEMA_FILE: Final = os.path.join(BASE_DIR, "schema.sql")

def create_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    if not os.path.exists(SCHEMA_FILE):
        print(f"[ERROR] Schema file could not be found !!: {SCHEMA_FILE}")
        return

    conn = create_db_connection()
    try:
        with open(SCHEMA_FILE, 'r', encoding='utf-8') as f:
            schema_script = f.read()
        
        conn.executescript(schema_script)
        
        conn.commit()
        print("[INFO] Database Schema loading successfully.")
        
    except sqlite3.Error as e:
        print(f"[ERROR] Database creationg failure !!: {e}")
    finally:
        conn.close()

def insert_event(event_type, source, username, severity, message):
    conn = create_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO events (timestamp, event_type, source, username, severity, message) 
        VALUES (?, ?, ?, ?, ?, ?)
    """, (datetime.now(), event_type, source, username, severity, message))
    conn.commit()
    conn.close()

def insert_metrics(failed_logins, open_ports, port_details, cpu_usage, ram_usage, disk_usage, risk_score):
    conn = create_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO metrics (
            timestamp, failed_logins, open_ports, port_details, cpu_usage, ram_usage, disk_usage, risk_score
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (datetime.now(), failed_logins, open_ports, port_details, cpu_usage, ram_usage, disk_usage, risk_score))
    conn.commit()
    conn.close()

def insert_alert(level, title, description):
    conn = create_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO alerts (timestamp, level, title, description)
        VALUES (?, ?, ?, ?)
    """, (datetime.now(), level, title, description))
    conn.commit()
    conn.close()

def insert_system_info(hostname, ip_address, os_info, uptime):
    conn = create_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM system_info ORDER BY id DESC LIMIT 1")
    last_row = cursor.fetchone()
    
    if last_row:
        if (last_row['hostname'] == hostname and 
            last_row['ip_address'] == ip_address and 
            last_row['os'] == os_info and 
            last_row['uptime'] == uptime):
            conn.close()
            return

    cursor.execute("""
        INSERT INTO system_info (hostname, ip_address, os, uptime)
        VALUES (?, ?, ?, ?)
    """, (hostname, ip_address, os_info, uptime))
    conn.commit()
    conn.close()

def get_event_timeline(limit=100):
    conn = create_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, timestamp, event_type, source, username, severity, message
        FROM events
        ORDER BY timestamp DESC
        LIMIT ?
    """, (limit,))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows

def advanced_filter_events(start_date=None, end_date=None, ip=None, username=None, severity=None, keyword=None, page=1, per_page=25):
    conn = create_db_connection()
    cursor = conn.cursor()

    base_query = "FROM events WHERE 1=1"
    params = []

    if start_date:
        base_query += " AND timestamp >= ?"
        params.append(start_date)
    if end_date:
        base_query += " AND timestamp <= ?"
        params.append(end_date)
    if severity and severity != "ALL":
        base_query += " AND severity = ?"
        params.append(severity)
    if keyword and keyword.strip():
        base_query += " AND (message LIKE ? OR source LIKE ? OR event_type LIKE ?)"
        wildcard = f"%{keyword}%"
        params.extend([wildcard, wildcard, wildcard])

    try:
        count_query = f"SELECT COUNT(*) {base_query}"
        cursor.execute(count_query, params)
        total_records = cursor.fetchone()[0]

        offset = (page - 1) * per_page
        data_query = f"SELECT * {base_query} ORDER BY id DESC LIMIT ? OFFSET ?"
        data_params = params + [per_page, offset]
        
        cursor.execute(data_query, data_params)
        rows = [dict(row) for row in cursor.fetchall()]
        
        return rows, total_records

    except Exception as e:
        print(f"[ERROR] Filtering error: {e}")
        return [], 0
    finally:
        conn.close()

def get_analytics_data():
    conn = create_db_connection()
    cursor = conn.cursor()
    stats = {}

    try:
        cursor.execute("""
            SELECT event_type, COUNT(*) as count 
            FROM events 
            GROUP BY event_type
        """)
        stats['event_distribution'] = [dict(row) for row in cursor.fetchall()]

        cursor.execute("""
            SELECT source, COUNT(*) as count 
            FROM events 
            WHERE source != 'Unknown' AND source != 'Local'
            GROUP BY source 
            ORDER BY count DESC 
            LIMIT 5
        """)
        stats['top_ips'] = [dict(row) for row in cursor.fetchall()]

    except Exception as e:
        print(f"[ERROR] Analytics error: {e}")
        stats = {'event_distribution': [], 'top_ips': []}
    finally:
        conn.close()
    
    return stats

def get_metrics(limit=50):
    conn = create_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT timestamp, failed_logins, open_ports, cpu_usage, ram_usage, disk_usage, risk_score
        FROM metrics
        ORDER BY timestamp DESC
        LIMIT ?
    """, (limit,))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows

def get_alerts(limit=50):
    conn = create_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM alerts
        ORDER BY timestamp DESC
        LIMIT ?
    """, (limit,))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows

def get_system_info():
    conn = create_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM system_info
        ORDER BY id DESC
        LIMIT 1
    """)
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def get_dashboard_data():
    conn = create_db_connection()
    cursor = conn.cursor()
    data = {}
    
    try:
        cursor.execute("SELECT * FROM system_info ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        data['sys_info'] = dict(row) if row else None
        
        cursor.execute("SELECT * FROM metrics ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        data['metrics'] = dict(row) if row else None
        
        cursor.execute("SELECT * FROM (SELECT * FROM metrics ORDER BY id DESC LIMIT 20) ORDER BY id ASC")
        data['history'] = [dict(r) for r in cursor.fetchall()]
        
        cursor.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 5")
        data['alerts'] = [dict(r) for r in cursor.fetchall()]
        
        cursor.execute("SELECT * FROM events ORDER BY id DESC LIMIT 10")
        data['events'] = [dict(r) for r in cursor.fetchall()]
        
    except Exception as e:
        print(f"[ERROR] ERROR while getting dashboard data !! : {e}")
        return None
    finally:
        conn.close()
        
    return data

def get_heatmap_data():
    conn = create_db_connection()
    cursor = conn.cursor()
    query = """
        SELECT strftime('%H', timestamp) as hour, COUNT(*) as count
        FROM events
        WHERE timestamp >= datetime('now', '-24 hours')
        GROUP BY hour
    """
    try:
        cursor.execute(query)
        rows = {int(row['hour']): row['count'] for row in cursor.fetchall()}
        
        heatmap_array = [rows.get(h, 0) for h in range(24)]
        return heatmap_array
    except Exception as e:
        print(f"[ERROR] Heatmap data error: {e}")
        return [0] * 24
    finally:
        conn.close()

def insert_firewall_log(action, protocol, src_ip, dst_port, direction="INBOUND"):
    conn = create_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO firewall_logs (timestamp, action, protocol, src_ip, dst_port, direction)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (datetime.now(), action, protocol, src_ip, dst_port, direction))
        conn.commit()
    except Exception as e:
        print(f"[DB ERROR] Firewall insert error: {e}")
    finally:
        conn.close()

def get_firewall_stats():
    conn = create_db_connection()
    cursor = conn.cursor()
    stats = {'allow': 0, 'deny': 0}
    
    try:
        cursor.execute("""
            SELECT action, COUNT(*) as count 
            FROM firewall_logs 
            WHERE timestamp >= datetime('now', '-24 hours') 
            GROUP BY action
        """)
        rows = cursor.fetchall()
        
        for row in rows:
            act = row['action'].upper()
            if 'BLOCK' in act or 'DENY' in act or 'DROP' in act or 'REJECT' in act:
                stats['deny'] += row['count']
            else:
                stats['allow'] += row['count']
                
    except Exception as e:
        print(f"[ERROR] Firewall stats error: {e}")
    finally:
        conn.close()
    return stats

def get_log_volume_stats():
    conn = create_db_connection()
    cursor = conn.cursor()
    
    intervals = [0, 4, 8, 12, 16, 20]
    volume_data = []
    
    try:
        for i in intervals:
            cursor.execute(f"""
                SELECT COUNT(*) FROM events 
                WHERE strftime('%H', timestamp) >= '{i:02d}' 
                AND strftime('%H', timestamp) < '{i+4:02d}'
                AND timestamp >= datetime('now', '-24 hours')
            """)
            count = cursor.fetchone()[0]
            volume_data.append(count)
    except Exception as e:
        print(f"[ERROR] Volume stats error: {e}")
        volume_data = [0, 0, 0, 0, 0, 0]
    finally:
        conn.close()
        
    return volume_data

def maintenance(retention_days=7):
    conn = create_db_connection()
    cursor = conn.cursor()
    
    cutoff_date = (datetime.now() - timedelta(days=retention_days)).strftime('%Y-%m-%d %H:%M:%S')
    
    print(f"[MAINTENANCE] Data older than {retention_days} days is being purged...")
    
    try:
        cursor.execute("DELETE FROM events WHERE timestamp < ?", (cutoff_date,))
        cursor.execute("DELETE FROM firewall_logs WHERE timestamp < ?", (cutoff_date,))
        cursor.execute("DELETE FROM metrics WHERE timestamp < ?", (cutoff_date,))
        cursor.execute("DELETE FROM alerts WHERE timestamp < ?", (cutoff_date,))
        
        deleted_count = cursor.rowcount
        conn.commit()
        
        cursor.execute("VACUUM")
        
        print(f"[MAINTENANCE] Completed succesfully. Maintenance Date: {cutoff_date} before.")
        
    except Exception as e:
        print(f"[ERRIR] Problem occured during maintenance: {e}")
    finally:
        conn.close()