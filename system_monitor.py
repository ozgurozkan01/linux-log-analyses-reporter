import psutil
import os

def get_system_stats():
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/home') 

    cpu_percent = psutil.cpu_percent(interval=1)
    ram_percent = memory.percent
    disk_percent = disk.percent

    return {
        "cpu_percent": cpu_percent,
        "ram_percent": ram_percent,
        "ram_total_gb": memory.total / (1024**3),
        "ram_used_gb": memory.used / (1024**3),
        "disk_total_gb": disk.total / (1024**3),
        "disk_used_gb": disk.used / (1024**3),
        "disk_free_gb": disk.free / (1024**3),
        "disk_percent": disk.percent
    }