import os

def calculate_file_hash(filepath):
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"[ERROR] Hash calculation error for {filepath}: {e}")
        return None

def find_renamed_file(target_inode, search_roots=None):
    if search_roots is None:
        search_roots = ["/home", "/tmp", "/etc", "/var", "/root", "/opt"]

    print(f"\n[DEBUG] DEDEKTİF: Inode {target_inode} için tüm sistem taranıyor...")
    
    try:
        target_inode = int(target_inode)
        
        for root_dir in search_roots:
            if not os.path.exists(root_dir): 
                continue
            
            for current_root, dirs, files in os.walk(root_dir, followlinks=True):
                
                if any(skip in current_root for skip in ["/proc", "/sys", "/dev", "/run", "/snap", "/.cache", "/.local"]):
                    continue
                
                if "Downloads" in current_root:
                    print(f"[DEBUG] -> Downloads klasörüne girildi: {current_root}")

                for name in files:
                    try:
                        full_path = os.path.join(current_root, name)
                        
                        if os.stat(full_path).st_ino == target_inode:
                            print(f"[DEBUG] BINGO! BULUNDU: {full_path}")
                            return full_path
                            
                    except (PermissionError, FileNotFoundError, OSError):
                        continue
                        
    except Exception as e:
        print(f"[ERROR] Dedektif hata aldi: {e}")
    
    print("[DEBUG] Dedektif aradı ama bulamadı (Dosya silinmiş veya Inode değişmiş).")
    return None
