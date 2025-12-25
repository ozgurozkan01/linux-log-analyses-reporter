import os
from config import Config
from datetime import datetime
import subprocess
from typing import Final

CURRENT_DIR    : Final = Config.SOURCE_DIR
PROJECT_ROOT   : Final = Config.ROOT_DIR
COLLECTOR_PATH : Final = Config.COLLECTOR_PATH

CURSOR_FILE    : Final = Config.CURSOR_FILE
LOOKBACK_MINUTES = Config.LOOKBACK_MINUTES

def get_since_timestamp():
    if os.path.exists(CURSOR_FILE):
        try:
            with open(CURSOR_FILE, 'r') as f:
                last_time = f.read().strip()
                if last_time:
                    return last_time
        except Exception:
            pass
    return f"{LOOKBACK_MINUTES} minutes ago"

def is_root():
    if os.geteuid() != 0:
        print("[ERROR] This script should run with root permissions.")
        print("Otherwise, access to the file is blocked.")
        sys.exit(1)

def update_cursor():
    try:
        with open(CURSOR_FILE, 'w') as f:
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(now_str)
    except Exception as e:
        print(f"[ERROR] Could not update cursor file: {e}")

def check_collector_status():
    file_exists = os.path.isfile(COLLECTOR_PATH)
    cron_exists = False
    try:
        result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        if result.returncode == 0 and result.stdout:
            for line in result.stdout.splitlines():
                if COLLECTOR_PATH in line and not line.strip().startswith("#"):
                    cron_exists = True
                    break
    except Exception:
        pass

    return file_exists and cron_exists

def get_last_scan_time():
    if os.path.exists(CURSOR_FILE):
        try:
            with open(CURSOR_FILE, 'r') as f:
                return f.read().strip()
        except Exception:
            return "Read Error"
    else:
        return "Not Found"
