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

def advanced_filter_events(start_date=None, end_date=None, ip=None, username=None, severity=None, keyword=None, limit=500):
    conn = create_db_connection()
    cursor = conn.cursor()

    query = "SELECT * FROM events WHERE 1=1"
    params = []

    if start_date:
        query += " AND timestamp >= ?"
        params.append(start_date)

    if end_date:
        query += " AND timestamp <= ?"
        params.append(end_date)

    if ip and ip.strip():
        query += " AND source = ?"
        params.append(ip)

    if username and username.strip():
        query += " AND username = ?"
        params.append(username)

    if severity and severity != "ALL":
        query += " AND severity = ?"
        params.append(severity)

    if keyword and keyword.strip():
        query += " AND message LIKE ?"
        params.append(f"%{keyword}%")

    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    try:
        cursor.execute(query, params)
        rows = [dict(row) for row in cursor.fetchall()]
        return rows
    except Exception as e:
        print(f"[ERROR] Filtering ERROR: {e}")
        return []
    finally:
        conn.close()

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