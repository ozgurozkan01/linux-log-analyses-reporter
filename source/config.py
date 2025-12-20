# source/config.py

import os

class Config:
    
    SOURCE_DIR = os.path.dirname(os.path.abspath(__file__))
    SCHEMA_FILE = os.path.join(SOURCE_DIR, "schema.sql")
    ROOT_DIR = os.path.dirname(SOURCE_DIR)
    COLLECTOR_PATH = os.path.join(SOURCE_DIR, "agent.py")
    DATA_DIR = os.path.join(ROOT_DIR, "data")
    DB_NAME = os.path.join(DATA_DIR, "siem.db")
    CURSOR_FILE = os.path.join(DATA_DIR, "last_scan_cursor.txt")

    AGENT_MAX_WORKERS = 5
    RETENTION_DAYS = 7        
    LOOKBACK_MINUTES = 30     

    CMD_SSH_BASE = [ "journalctl", "-u", "ssh", "-u", "sshd", "--no-pager", "--output=short-iso" ]
    CMD_SUDO_BASE = ["journalctl", "-t", "sudo", "--no-pager", "--output=short-iso"]
    CMD_AUDIT_FULL = ["ausearch", "-k", "process_monitor", "-i", "-ts", "recent"]
    CMD_FIREWALL_TEMPLATE = "journalctl -k --grep='UFW|BLOCK|DROP|IN=' --since '{}' --no-pager --output=short-iso"
    
    # SSH
    SSH_MAX_EVENTS = 2000
    SSH_BRUTE_FORCE_WINDOW = 300  
    SSH_BRUTE_FORCE_THRESHOLD = 3 
    
    # SUDO
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
    SUDO_SERVICE_ACCOUNTS = {'www-data', 'apache', 'nginx', 'tomcat', 'jenkins', 'postgres', 'mysql', 'docker'}
    SUDO_GTFOBINS_RISKY = {'find', 'awk', 'nmap', 'man', 'less', 'more', 'vi', 'vim', 'gdb', 'tar', 'zip'}
    SUDO_PRIV_ESCALATION = {'chmod', 'chown', 'chgrp', 'passwd', 'useradd', 'usermod'}
    SUDO_SHELL_BINS = {'bash', 'sh', 'zsh', 'su'}
    SUDO_NET_BINS = {'wget', 'curl', 'nc', 'netcat', 'socat'}
    SUDO_READ_BINS = {'cat', 'head', 'tail', 'grep', 'more', 'less'}
    SUDO_DESTRUCTIVE_BINS = {'rm', 'dd', 'shred', 'wipe', 'truncate'}
    SUDO_EDITOR_BINS = {'vi', 'vim', 'nano', 'nvim', 'less', 'more', 'man'}
    SUDO_MITRE_MAPPING = {
        "SHELL_ESCAPE_ATTEMPT": "T1059.004", 
        "SUDO_INTERACTIVE_ROOT": "T1548.003", 
        "NON_INTERACTIVE_SUDO": "T1059",      
        "SUDO_NOPASSWD": "T1548.003",         
        "SENSITIVE_EDIT": "T1565.001",        
        "SENSITIVE_READ": "T1005",            
        "PRIVILEGE_MODIFICATION": "T1548",    
        "SUDO_NET_PIVOT": "T1090",            
        "SUID_ABUSE": "T1548.001",            
        "LOG_TAMPERING": "T1070",             
        "PERSISTENCE_MODIFICATION": "T1543",  
        "ROOT_DIR_ACCESS": "T1083",
        "ENV_ESCAPE": "T1574",                
        "SERVICE_ACCOUNT_ABUSE": "T1078.003",
        "SCRIPT_EXECUTION": "T1059.004",      
        "PRIV_ESCALATION_TOOL": "T1548",
        "SUDOEDIT_SENSITIVE_EDIT": "T1565.001",
        "SUDO_ENV_PRESERVE": "T1574"
    }

    # AUDIT
    AUDIT_CRITICAL_FILES = {'/etc/shadow', '/etc/passwd', '/etc/sudoers', '/var/log/auth.log'}
    AUDIT_SUSPICIOUS_BINS = [
        'nc', 'ncat', 'netcat', 'nmap', 'tcpdump', 'wireshark', 
        'gdb', 'strace', 'ftpd', 'socat'
    ]
    AUDIT_RECON_COMMANDS = [ 'whoami', 'id', 'uname -a', 'cat /etc/issue' ]
    AUDIT_PERM_MOD_CMDS = [ 'chmod', 'chown', 'chgrp' ]
    AUDIT_WEBSHELL_PATTERN = r'''(?x)
        \b(
        (?:python[23]?|perl|ruby|lua|php[578]?)\s+-[cer]|
        (?:bash|sh|zsh|dash|ksh)\s+-[ic]|
        /dev/(?:tcp|udp)/\d{1,3}\.\d{1,3}|
        base64\s+-(?:d|D|decode)|
        (?:wget|curl|fetch)\s+http
        )'''

    # FIM
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
    
    # FIREWALL
    FW_TIME_WINDOW = 30           
    FW_HIT_THRESHOLD = 20         
    FW_UNIQUE_PORT_THRESHOLD = 5  
    FW_COOLDOWN = 60              
    
    FW_CRITICAL_PORTS = {'22','23','53','80','443','445','1433','3306','3389'}