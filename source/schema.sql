CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    event_type TEXT, 
    source TEXT,     
    username TEXT,   
    severity TEXT,   
    message TEXT
);

CREATE TABLE IF NOT EXISTS metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    failed_logins INTEGER,
    open_ports INTEGER,
    port_details TEXT,
    cpu_usage REAL,
    ram_usage REAL,
    disk_usage REAL,
    risk_score INTEGER
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    level TEXT,
    title TEXT,
    description TEXT
);

CREATE TABLE IF NOT EXISTS system_info (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT,
    ip_address TEXT,
    os TEXT,
    uptime TEXT
);

CREATE TABLE IF NOT EXISTS firewall_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    action TEXT,      
    protocol TEXT,    
    src_ip TEXT,      
    dst_port INTEGER, 
    direction TEXT    
);

CREATE INDEX IF NOT EXISTS idx_fw_action ON firewall_logs(action);
CREATE INDEX IF NOT EXISTS idx_fw_src_ip ON firewall_logs(src_ip);
CREATE INDEX IF NOT EXISTS idx_fw_timestamp ON firewall_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(username);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
