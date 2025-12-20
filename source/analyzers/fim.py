import os
import sys
import re
import time
import hashlib
import difflib
from pathlib import Path
from typing import List
from datetime import datetime, timezone

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

from config import Config
import utils
import db

def analyze_file_integrity():
    events = []
    
    CRITICAL_FILES = Config.FIM_TARGETS
    SAFE_CHANGES = Config.FIM_SAFE_CHANGES
    MAX_FILE_SIZE = Config.FIM_MAX_FILE_SIZE

    print(f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] START --- analyze_fim_logs ---\n")

    start_time = time.time()

    for filepath in CRITICAL_FILES:
        event_time = datetime.now(timezone.utc).isoformat()

        if not os.path.exists(filepath):
            stored_data = db.get_file_baseline(filepath)
            
            if stored_data:
                old_inode = stored_data['inode']
                new_path = utils.find_renamed_file(old_inode) 
                
                if new_path:
                    old_dir, old_name = os.path.split(filepath)
                    new_dir, new_name = os.path.split(new_path)
                    
                    try:
                        new_stat = os.stat(new_path)
                        new_uid = new_stat.st_uid
                        new_gid = new_stat.st_gid
                        new_perms = oct(new_stat.st_mode)[-3:]
                    except:
                        new_uid, new_gid, new_perms = "Unknown", "Unknown", "Unknown"

                    new_hash = "Unknown"
                    try:
                        sha256_hash = hashlib.sha256()
                        with open(new_path, "rb") as f:
                            for byte_block in iter(lambda: f.read(4096), b""):
                                sha256_hash.update(byte_block)
                        new_hash = sha256_hash.hexdigest()
                    except Exception as e:
                        print(f"[ERROR] Hash calculation failed during rename check: {e}")

                    event_type = "FIM_TRACKING"
                    status_desc = "Inode match found."

                    if old_dir == new_dir and old_name != new_name:
                        msg = f"FILE RENAMED: {old_name} -> {new_name}"
                        event_type = "FIM_RENAME"
                    elif old_dir != new_dir:
                        msg = f"FILE MOVED: {filepath} -> {new_path}"
                        event_type = "FIM_MOVED"

                    details_str = (
                        f"Event Type: {event_type}\n"
                        f"Original Path: {filepath}\n"
                        f"New Path: {new_path}\n"
                        f"Inode: {old_inode} (Preserved)\n"
                        f"UID: {new_uid}\n"        
                        f"GID: {new_gid}\n"        
                        f"Old Permissions: {stored_data['perms']}\n"  
                        f"New Permissions: {new_perms}\n"             
                        f"Old Hash: {stored_data['hash']}\n"          
                        f"New Hash: {new_hash}\n"                     
                        f"Analysis: {status_desc}"
                    )
                    
                    events.append({
                        "timestamp": event_time, "type": event_type, "source": "Local/FIM",
                        "user": "System", "severity": "HIGH", "msg": msg, "details": details_str
                    })
                    
                else:
                    msg = f"CRITICAL FILE MISSING: {filepath}"

                    last_uid = stored_data.get('uid', 'N/A')
                    last_gid = stored_data.get('gid', 'N/A')
                    last_perms = stored_data.get('permissions', 'N/A')
                    if last_perms == 'N/A': 
                        last_perms = stored_data.get('perms', 'N/A')

                    details_str = (
                        f"Event Type: FIM_MISSING\n"
                        f"Original Path: {filepath}\n"
                        f"Inode: {old_inode}\n"            
                        f"UID: {last_uid}\n"               
                        f"GID: {last_gid}\n"               
                        f"Old Permissions: {last_perms}\n" 
                        f"Analysis: File has been permanently removed from disk.\n"
                    )
                    events.append({
                        "timestamp": event_time, "type": "FIM_MISSING", "source": "Local/FIM",
                        "user": "System", "severity": "CRITICAL", "msg": msg, "details": details_str
                    })
            continue

        try:
            file_stat = os.stat(filepath)
            current_perms = oct(file_stat.st_mode)[-3:]
            current_uid = file_stat.st_uid
            current_gid = file_stat.st_gid
            current_inode = file_stat.st_ino
            current_mtime = file_stat.st_mtime
            
            stored_data = db.get_file_baseline(filepath)

            if  stored_data and stored_data['inode'] == current_inode and stored_data.get('mtime') == current_mtime and stored_data.get('perms') == current_perms and stored_data.get('uid') == current_uid and stored_data.get('gid') == current_gid:        
                print(f"   [FAST SKIP] {filepath} (No changes)") 
                continue

            print(f"   [HEAVY SCAN] {filepath} (Calculating Hash...)")

            sha256_hash = hashlib.sha256()
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            current_hash = sha256_hash.hexdigest()

            current_content = ""
            is_binary_or_large = False
            if file_stat.st_size > MAX_FILE_SIZE:
                current_content = "[INFO] File too large"
                is_binary_or_large = True
            else:
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='strict') as f:
                        current_content = f.read()
                except:
                    current_content = "[INFO] Binary"
                    is_binary_or_large = True

            if stored_data is None:
                db.update_file_baseline(filepath, current_hash, current_content, current_perms, current_uid, current_gid, current_inode, current_mtime)
                continue

            base_severity = "CRITICAL"
            if filepath in SAFE_CHANGES: base_severity = "INFO"

            if stored_data['inode'] != current_inode:
                msg = f"FILE REPLACEMENT DETECTED: {filepath}"
                details_str = (
                    f"Event Type: FIM_INODE_CHANGE\n"
                    f"Original Path: {filepath}\n"
                    f"UID: {current_uid}\n"        
                    f"GID: {current_gid}\n"        
                    f"Old Inode: {stored_data['inode']}\n" 
                    f"New Inode: {current_inode}\n"       
                    f"Old Permissions: {stored_data['perms']}\n"
                    f"New Permissions: {current_perms}\n"
                    f"Analysis: File deleted and recreated (Inode mismatch).\n"
                )
                events.append({
                    "timestamp": event_time, "type": "FIM_INODE_CHANGE", "source": "Local/FIM",
                    "user": "System", "severity": base_severity, "msg": msg, "details": details_str
                })
                db.update_file_baseline(filepath, current_hash, current_content, current_perms, current_uid, current_gid, current_inode, current_mtime)

            elif current_hash != stored_data['hash']:
                msg = f"FILE CONTENT CHANGED: {filepath}"
                
                diff_output = "No readable text diff available."
                if not is_binary_or_large:
                    old_content = stored_data['content'] if stored_data['content'] else ""
                    diff = list(difflib.unified_diff(
                        old_content.splitlines(), current_content.splitlines(), 
                        lineterm='', n=3
                    ))
                    if len(diff) > 2:
                        diff_output = "\n".join(diff[2:])

                details_str = (
                    f"Event Type: FIM_CONTENT_CHANGE\n"
                    f"Original Path: {filepath}\n"
                    f"UID: {current_uid}\n"
                    f"GID: {current_gid}\n"
                    f"Inode: {current_inode}\n"                 
                    f"Old Permissions: {stored_data['perms']}\n"  
                    f"New Permissions: {current_perms}\n"        
                    f"Old Hash: {stored_data['hash']}\n"
                    f"New Hash: {current_hash}\n"
                    f"Analysis: File content modified.\n"
                    f"---DIFF START---\n{diff_output}\n---DIFF END---"
                )

                events.append({
                    "timestamp": event_time, "type": "FIM_CONTENT_CHANGE", "source": "Local/FIM",
                    "user": "System", "severity": base_severity, "msg": msg, "details": details_str
                })
                db.update_file_baseline(filepath, current_hash, current_content, current_perms, current_uid, current_gid, current_inode, current_mtime)

            elif (current_perms != stored_data['perms'] or current_uid != stored_data['uid'] or current_gid != stored_data['gid']):
                
                msg = f"FILE METADATA CHANGED: {filepath}"
                
                details_str = (
                    f"Event Type: FIM_METADATA_CHANGE\n"
                    f"Original Path: {filepath}\n"
                    f"UID: {current_uid} (Old: {stored_data['uid']})\n"
                    f"GID: {current_gid} (Old: {stored_data['gid']})\n"
                    f"Inode: {current_inode}\n"
                    f"Old Permissions: {stored_data['perms']}\n"
                    f"New Permissions: {current_perms}\n"
                    f"Old Hash: {stored_data['hash']}\n"
                    f"New Hash: {current_hash}\n"
                    f"Analysis: Ownership or permissions modified.\n"
                )
                
                events.append({
                    "timestamp": event_time, "type": "FIM_PERM_CHANGE", "source": "Local/FIM",
                    "user": "System", "severity": "WARNING", "msg": msg, "details": details_str
                })

                db.update_file_baseline(filepath, current_hash, current_content, current_perms, current_uid, current_gid, current_inode, current_mtime)

        except Exception as e:
            print(f"[ERROR] FIM check failed for {filepath}: {e}")


    end_time = time.time()
    duration = end_time - start_time
    print(f"[RESULT] FIM Scan Completed in {duration:.4f} seconds.\n")
    
    return events
