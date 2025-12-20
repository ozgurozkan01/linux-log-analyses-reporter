import sqlite3
import os
from datetime import datetime, timedelta
from typing import Final, List, Dict, Any, Optional
from contextlib import contextmanager

try:
    from config import Config
except ImportError:
    import sys
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from config import Config

DB_NAME: Final = Config.DB_NAME
SCHEMA_FILE: Final = Config.SCHEMA_FILE


class DatabaseManager:
    def __init__(self, db_name: str):
        self.db_name = db_name

    def get_connection(self):
        conn = sqlite3.connect(self.db_name, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;") 
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    @contextmanager
    def execute(self, commit: bool = False):
        conn = self.get_connection()
        try:
            yield conn.cursor()
            if commit:
                conn.commit()
        except sqlite3.Error as e:
            if commit:
                conn.rollback()
            print(f"[DB ERROR] {e}")
            raise
        finally:
            conn.close()

    def query_one(self, sql: str, params: tuple = ()) -> Optional[dict]:
        with self.execute(commit=False) as cursor:
            cursor.execute(sql, params)
            row = cursor.fetchone()
            return dict(row) if row else None

    def query_all(self, sql: str, params: tuple = ()) -> List[dict]:
        with self.execute(commit=False) as cursor:
            cursor.execute(sql, params)
            return [dict(row) for row in cursor.fetchall()]

    def modify(self, sql: str, params: tuple = ()) -> int:
        with self.execute(commit=True) as cursor:
            cursor.execute(sql, params)
            return cursor.lastrowid

db = DatabaseManager(DB_NAME)

def init_db():
    if not os.path.exists(SCHEMA_FILE):
        print(f"[ERROR] Schema file not found: {SCHEMA_FILE}")
        return

    try:
        with open(SCHEMA_FILE, 'r', encoding='utf-8') as f:
            schema_script = f.read()
        
        conn = db.get_connection()
        conn.executescript(schema_script)
        conn.commit()
        conn.close()
        print("[INFO] Database Schema loaded successfully (WAL Mode Enabled).")
    except sqlite3.Error as e:
        print(f"[ERROR] Database creation failure: {e}")

def insert_event(event_type, source, username, severity, message):
    db.modify("""
        INSERT INTO events (timestamp, event_type, source, username, severity, message) 
        VALUES (?, ?, ?, ?, ?, ?)
    """, (datetime.now(), event_type, source, username, severity, message))

def insert_metrics(failed_logins, open_ports, port_details, cpu, ram, disk, risk_score):
    db.modify("""
        INSERT INTO metrics (timestamp, failed_logins, open_ports, port_details, cpu_usage, ram_usage, disk_usage, risk_score) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (datetime.now(), failed_logins, open_ports, port_details, cpu, ram, disk, risk_score))

def insert_alert(level, title, description, details, score=0):
    existing = db.query_one("SELECT id, count FROM alerts WHERE title = ? AND status = 'OPEN'", (title,))
    
    if existing:
        new_count = (existing['count'] or 1) + 1
        db.modify("""
            UPDATE alerts SET timestamp = ?, description = ?, count = ? WHERE id = ?
        """, (datetime.now(), description, new_count, existing['id']))
        print(f"   [INFO] Updated existing alert: {title} (Count: {new_count})")
    else:
        try:
            db.modify("""
                INSERT INTO alerts (timestamp, level, title, description, status, details, score, count)
                VALUES (?, ?, ?, ?, 'OPEN', ?, ?, 1)
            """, (datetime.now(), level, title, description, details, score))
        except sqlite3.OperationalError:
            try:
                with db.execute(commit=True) as cur:
                    cur.execute("ALTER TABLE alerts ADD COLUMN score INTEGER DEFAULT 0")
                    cur.execute("ALTER TABLE alerts ADD COLUMN count INTEGER DEFAULT 1")
            except: pass
            insert_alert(level, title, description, details, score)

def insert_system_info(hostname, ip_address, os_info, uptime):
    last_row = db.query_one("SELECT * FROM system_info ORDER BY id DESC LIMIT 1")
    
    if last_row and (last_row['hostname'] == hostname and last_row['uptime'] == uptime):
        return

    db.modify("""
        INSERT INTO system_info (hostname, ip_address, os, uptime) VALUES (?, ?, ?, ?)
    """, (hostname, ip_address, os_info, uptime))

def insert_firewall_log(action, protocol, src_ip, dst_port, direction="INBOUND"):
    db.modify("""
        INSERT INTO firewall_logs (timestamp, action, protocol, src_ip, dst_port, direction)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (datetime.now(), action, protocol, src_ip, dst_port, direction))

def update_file_baseline(file_path, new_hash, content, perms, uid, gid, inode, mtime):
    db.modify("""
        INSERT INTO file_integrity (file_path, file_hash, content, permissions, uid, gid, inode, last_mtime, last_checked)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(file_path) DO UPDATE SET
            file_hash = excluded.file_hash,
            content = excluded.content,
            permissions = excluded.permissions,
            uid = excluded.uid,
            gid = excluded.gid,
            inode = excluded.inode,
            last_mtime = excluded.last_mtime,
            last_checked = excluded.last_checked
    """, (file_path, new_hash, content, perms, uid, gid, inode, mtime, datetime.now()))

def update_alert_status(alert_id, status, note=None):
    if note:
        db.modify("UPDATE alerts SET status = ?, resolution_note = ?, timestamp = ? WHERE id = ?", (status, note, datetime.now(), alert_id))
    else:
        db.modify("UPDATE alerts SET status = ?, timestamp = ? WHERE id = ?", (status, datetime.now(), alert_id))
    return True

def get_event_timeline(limit=100):
    return db.query_all("SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,))

def get_metrics(limit=50):
    return db.query_all("SELECT * FROM metrics ORDER BY timestamp DESC LIMIT ?", (limit,))

def get_alerts(limit=50):
    return db.query_all("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,))

def get_system_info():
    return db.query_one("SELECT * FROM system_info ORDER BY id DESC LIMIT 1")

def get_file_baseline(file_path):
    row = db.query_one("SELECT * FROM file_integrity WHERE file_path = ?", (file_path,))
    if row:
        return {
            "hash": row['file_hash'], "content": row['content'], "perms": row['permissions'],
            "uid": row['uid'], "gid": row['gid'], "inode": row['inode'], "mtime": row['last_mtime']
        }
    return None

def get_latest_risk_score():
    row = db.query_one("SELECT risk_score FROM metrics ORDER BY id DESC LIMIT 1")
    return row['risk_score'] if row else 0

def get_resolved_alerts(limit=100):
    return db.query_all("SELECT * FROM alerts WHERE status = 'CLOSED' ORDER BY timestamp DESC LIMIT ?", (limit,))

def get_firewall_stats():
    """
    Firewall loglarını analiz ederek Dashboard ve FW Stream için
    gerekli tüm istatistikleri üretir.
    (GÜNCELLENMİŞ VERSİYON: Tarih formatı hatalarını tolere eder)
    """
    stats = {
        'traffic_labels': [],
        'traffic_values': [],
        'traffic_baseline': [],
        'network_analysis': {
            'internal': {'total': 0, 'allow': 0, 'block': 0, 'drop': 0},
            'external': {'total': 0, 'allow': 0, 'block': 0, 'drop': 0}
        },
        'actions': {'ALLOW': 0, 'BLOCK': 0},
        'scan_types': {},       
        'top_ports': [],
        'repeated_offenders': [],
        'geo_stats': {'Internal': 0, 'External': 0}
    }

    try:
        logs = db.query_all("SELECT * FROM firewall_logs ORDER BY timestamp ASC")

        hourly_traffic = {}
        now = datetime.now()
        
        for log in logs:
            ts_str = log['timestamp']
            dt = None
            
            formats = [
                '%Y-%m-%d %H:%M:%S.%f', # Mikro saniyeli
                '%Y-%m-%d %H:%M:%S',    # Standart
                '%Y-%m-%dT%H:%M:%S'     # ISO formatı
            ]
            
            for fmt in formats:
                try:
                    dt = datetime.strptime(ts_str, fmt)
                    break
                except ValueError:
                    continue
            
            if not dt:
                continue

            if dt < now - timedelta(hours=24):
                continue

            if dt > now - timedelta(hours=12):
                hour_key = dt.strftime('%H:00')
                hourly_traffic[hour_key] = hourly_traffic.get(hour_key, 0) + 1

            ip = log['src_ip']
            action = log['action'].upper()
            if action in ['DENY', 'REJECT']: action = 'BLOCK'
            
            if action in ['ALLOW', 'BLOCK']:
                stats['actions'][action] = stats['actions'].get(action, 0) + 1

            is_internal = False
            try:
                if ip and ip != '0.0.0.0':
                    if ipaddress.ip_address(ip).is_private: is_internal = True
            except: pass 

            target_group = 'internal' if is_internal else 'external'
            stats['network_analysis'][target_group]['total'] += 1
            
            if action == 'ALLOW': stats['network_analysis'][target_group]['allow'] += 1
            elif action == 'BLOCK': stats['network_analysis'][target_group]['block'] += 1
            elif action == 'DROP': stats['network_analysis'][target_group]['drop'] += 1
            else: stats['network_analysis'][target_group]['block'] += 1

        if hourly_traffic:
            sorted_hours = sorted(hourly_traffic.keys())
            stats['traffic_labels'] = sorted_hours
            stats['traffic_values'] = [hourly_traffic[h] for h in sorted_hours]
            stats['traffic_baseline'] = [int(v * 0.8) for v in stats['traffic_values']]
        else:
            stats['traffic_labels'] = ["No Data"]
            stats['traffic_values'] = [0]

        stats['geo_stats']['Internal'] = stats['network_analysis']['internal']['total']
        stats['geo_stats']['External'] = stats['network_analysis']['external']['total']

        cutoff = (now - timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
        
        port_rows = db.query_all(f"SELECT dst_port, count(*) as count FROM firewall_logs WHERE action IN ('BLOCK', 'DROP', 'DENY') AND timestamp > '{cutoff}' GROUP BY dst_port ORDER BY count DESC LIMIT 5")
        stats['top_ports'] = [dict(row) for row in port_rows]

        offender_rows = db.query_all(f"SELECT src_ip, count(*) as count, max(timestamp) as last_seen FROM firewall_logs WHERE action IN ('BLOCK', 'DROP', 'DENY') AND timestamp > '{cutoff}' GROUP BY src_ip ORDER BY count DESC LIMIT 10")
        
        for row in offender_rows:
            itype = 'External'
            try:
                if ipaddress.ip_address(row['src_ip']).is_private: itype = 'Internal'
            except: pass
            
            lseen = str(row['last_seen']).split('.')[0]
            stats['repeated_offenders'].append({'ip': row['src_ip'], 'count': row['count'], 'type': itype, 'last_seen': lseen})

    except Exception as e:
        print(f"[ERROR] get_firewall_stats failed: {e}")
        import traceback
        traceback.print_exc() # Detaylı hatayı konsola bas
    
    return stats

def get_latest_firewall_logs(limit=50):
    return db.query_all(
        "SELECT * FROM firewall_logs ORDER BY id DESC LIMIT ?", 
        (limit,)
    )

def get_recent_firewall_logs(hours=24):
    return db.query_all("""
        SELECT * FROM firewall_logs 
        WHERE timestamp > datetime('now', ?) 
        ORDER BY timestamp ASC
    """, (f'-{hours} hours',))

def get_events_by_type(event_types, limit=50):

    if not event_types or not isinstance(event_types, list):
        return []

    try:
        placeholders = ', '.join(['?'] * len(event_types))
        query = f"SELECT * FROM events WHERE event_type IN ({placeholders}) ORDER BY id DESC LIMIT ?"
        params = tuple(event_types + [limit])
        
        rows = db.query_all(query, params)
        return rows
        
    except Exception as e:
        print(f"[ERROR] get_events_by_type error: {e}")
        return []

def get_heatmap_data():
    rows = db.query_all("""
        SELECT strftime('%H', timestamp) as hour, COUNT(*) as count
        FROM events WHERE timestamp >= datetime('now', '-24 hours') GROUP BY hour
    """)
    data = {int(row['hour']): row['count'] for row in rows}
    return [data.get(h, 0) for h in range(24)]

def get_log_volume_stats():
    volume_data = []
    for i in [0, 4, 8, 12, 16, 20]:
        row = db.query_one(f"""
            SELECT COUNT(*) as c FROM events 
            WHERE strftime('%H', timestamp) >= '{i:02d}' AND strftime('%H', timestamp) < '{i+4:02d}'
            AND timestamp >= datetime('now', '-24 hours')
        """)
        volume_data.append(row['c'] if row else 0)
    return volume_data

def advanced_filter_events(start_date=None, end_date=None, ip=None, username=None, 
                           severity=None, keyword=None, page=1, per_page=25, 
                           event_types_exclude=None): # <<< 1. PARAMETRE ADI DEĞİŞTİ (ÇOĞUL OLDU)
    
    base_query = "FROM events WHERE 1=1"
    params = []

    if event_types_exclude and isinstance(event_types_exclude, list):
        placeholders = ', '.join(['?'] * len(event_types_exclude))
        
        base_query += f" AND event_type NOT IN ({placeholders})"
        
        params.extend(event_types_exclude)

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
        count_row = db.query_one(f"SELECT COUNT(*) as c {base_query}", tuple(params))
        total_records = count_row['c']

        offset = (page - 1) * per_page
        rows = db.query_all(f"SELECT * {base_query} ORDER BY id DESC LIMIT ? OFFSET ?", tuple(params + [per_page, offset]))
        
        return rows, total_records
    except Exception as e:
        print(f"[ERROR] Filtering error: {e}")
        return [], 0

def get_analytics_data():
    try:
        dist = db.query_all("SELECT event_type, COUNT(*) as count FROM events GROUP BY event_type")
        top_ips = db.query_all("SELECT source, COUNT(*) as count FROM events WHERE source NOT IN ('Unknown', 'Local') GROUP BY source ORDER BY count DESC LIMIT 5")
        return {'event_distribution': dist, 'top_ips': top_ips}
    except Exception:
        return {'event_distribution': [], 'top_ips': []}

def get_dashboard_data():
    return {
        'sys_info': get_system_info(),
        'metrics': get_metrics(limit=1)[0] if get_metrics(limit=1) else None,
        'history': list(reversed(get_metrics(limit=20))),
        'alerts': db.query_all("SELECT * FROM alerts WHERE status = 'OPEN' ORDER BY timestamp DESC"),
        'events': get_event_timeline(limit=10)
    }

def maintenance(retention_days=7):
    cutoff = (datetime.now() - timedelta(days=retention_days)).strftime('%Y-%m-%d %H:%M:%S')
    print(f"[MAINTENANCE] Purging data older than {retention_days} days...")
    
    try:
        with db.execute(commit=True) as cur:
            cur.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
            cur.execute("DELETE FROM firewall_logs WHERE timestamp < ?", (cutoff,))
            cur.execute("DELETE FROM metrics WHERE timestamp < ?", (cutoff,))
            cur.execute("DELETE FROM alerts WHERE timestamp < ?", (cutoff,))
    except Exception as e:
        print(f"[ERROR] Maintenance delete failed: {e}")
        return

    try:
        conn = db.get_connection()
        conn.isolation_level = None
        conn.execute("VACUUM")
        conn.close()
        print(f"[MAINTENANCE] Cleanup and VACUUM complete.")
    except Exception as e:
        print(f"[ERROR] VACUUM failed: {e}")

def create_db_connection():
    return db.get_connection()