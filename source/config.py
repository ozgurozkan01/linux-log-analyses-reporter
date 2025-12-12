# source/config.py

import os

class Config:
    SOURCE_DIR = os.path.dirname(os.path.abspath(__file__))
    
    ROOT_DIR = os.path.dirname(SOURCE_DIR)
    
    DATA_DIR = os.path.join(ROOT_DIR, "data")

    if not os.path.exists(DATA_DIR):
        try:
            os.makedirs(DATA_DIR)
            print(f"[INIT] Created data directory at: {DATA_DIR}")
        except Exception as e:
            print(f"[ERROR] Could not create data directory: {e}")


    SCHEMA_FILE = os.path.join(SOURCE_DIR, "schema.sql")

    DB_NAME = os.path.join(DATA_DIR, "siem.db")
    CURSOR_FILE = os.path.join(DATA_DIR, "last_scan_cursor.txt")

    RETENTION_DAYS = 7        
    LOOKBACK_MINUTES = 30     

    SSH_MAX_EVENTS = 2000
    SSH_BRUTE_FORCE_WINDOW = 300  
    SSH_BRUTE_FORCE_THRESHOLD = 3 

    SUDO_MAX_EVENTS = 1000
    SUDO_NORMAL_COOLDOWN = 10     
    SUDO_CRITICAL_COOLDOWN = 2    
    
    SUDO_SENSITIVE_FILES = [
        '/etc/shadow', 
        '/etc/passwd', 
        '/etc/sudoers', 
        '.ssh/id_rsa', 
        '.bash_history', 
        '/root/'
    ]

    FIM_MAX_FILE_SIZE = 5 * 1024 * 1024 
    
    FIM_TARGETS = [
        "/etc/passwd", 
        "/etc/shadow", 
        "/etc/group", 
        "/etc/sudoers", 
        "/etc/ssh/sshd_config", 
        "/etc/hosts", 
        "/bin/ls", 
        "/usr/bin/python3",
        "/home/zgr/Documents/siem_test.txt" 
    ]
    
    FIM_SAFE_CHANGES = ["/etc/hosts", "/etc/resolv.conf"]

    FW_TIME_WINDOW = 30           
    FW_HIT_THRESHOLD = 20         
    FW_UNIQUE_PORT_THRESHOLD = 5  
    FW_COOLDOWN = 60              
    
    FW_CRITICAL_PORTS = {'22','23','53','80','443','445','1433','3306','3389'}