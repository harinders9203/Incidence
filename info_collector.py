"""
System Information Gathering Script - Phase 1: Core Foundation
Collects OS info, running processes, and network connections.
"""

import json
import psutil
import platform
import socket
from datetime import datetime
import os

def get_os_info():
    """Collect operating system information."""
    try:
        os_info = {
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "uptime_seconds": psutil.boot_time(),
            "uptime_readable": datetime.fromtimestamp(psutil.boot_time()).strftime('%Y-%m-%d %H:%M:%S'),
            "current_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        return os_info
    except Exception as e:
        return {"error": f"Failed to collect OS info: {str(e)}"}

def get_running_processes():
    """Collect information about running processes."""
    processes = []
    try:
        for proc in psutil.process_iter(['pid', 'name', 'username', 'status', 'cpu_percent', 'memory_percent']):
            try:
                proc_info = {
                    "pid": proc.info['pid'],
                    "name": proc.info['name'],
                    "user": proc.info['username'],
                    "status": proc.info['status'],
                    "cpu_percent": proc.info['cpu_percent'],
                    "memory_percent": round(proc.info['memory_percent'], 2) if proc.info['memory_percent'] else 0
                }
                processes.append(proc_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # Process might have terminated or we don't have permission
                continue
        return processes
    except Exception as e:
        return [{"error": f"Failed to collect process info: {str(e)}"}]

def get_network_connections():
    """Collect network connection information."""
    connections = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            try:
                local_ip, local_port = conn.laddr if conn.laddr else ("", "")
                remote_ip, remote_port = conn.raddr if conn.raddr else ("", "")
                
                conn_info = {
                    "family": "IPv4" if conn.family == socket.AF_INET else "IPv6",
                    "type": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "status": conn.status if hasattr(conn, 'status') else "N/A",
                    "pid": conn.pid if conn.pid else "N/A"
                }
                connections.append(conn_info)
            except Exception as inner_e:
                # Skip problematic connections
                continue
        return connections
    except Exception as e:
        return [{"error": f"Failed to collect network info: {str(e)}"}]

def get_system_stats():
    """Get additional system statistics."""
    try:
        stats = {
            "cpu_count": psutil.cpu_count(logical=True),
            "cpu_count_physical": psutil.cpu_count(logical=False),
            "cpu_usage_percent": psutil.cpu_percent(interval=1),
            "memory_total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
            "memory_available_gb": round(psutil.virtual_memory().available / (1024**3), 2),
            "memory_used_percent": psutil.virtual_memory().percent,
            "disk_usage": []
        }
        
        # Get disk usage for all partitions
        for partition in psutil.disk_partitions():
            try:
                partition_usage = psutil.disk_usage(partition.mountpoint)
                disk_info = {
                    "device": partition.device,
                    "mountpoint": partition.mountpoint,
                    "file_system": partition.fstype,
                    "total_gb": round(partition_usage.total / (1024**3), 2),
                    "used_gb": round(partition_usage.used / (1024**3), 2),
                    "free_gb": round(partition_usage.free / (1024**3), 2),
                    "used_percent": round((partition_usage.used / partition_usage.total) * 100, 2)
                }
                stats["disk_usage"].append(disk_info)
            except PermissionError:
                # Skip partitions we can't access
                continue
                
        return stats
    except Exception as e:
        return {"error": f"Failed to collect system stats: {str(e)}"}

def collect_all_info():
    """Collect all system information and return as dictionary."""
    print("Collecting system information...")
    
    system_info = {
        "collection_timestamp": datetime.now().isoformat(),
        "os_info": get_os_info(),
        "system_stats": get_system_stats(),
        "running_processes": get_running_processes(),
        "network_connections": get_network_connections()
    }
    
    return system_info

def save_to_json(data, filename="system_info.json"):
    """Save collected data to JSON file."""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"System information saved to: {filename}")
        print(f"File size: {os.path.getsize(filename)} bytes")
        return True
    except Exception as e:
        print(f"Error saving to JSON: {str(e)}")
        return False

def print_summary(data):
    """Print a summary of collected information."""
    print("\n" + "="*50)
    print("SYSTEM INFORMATION SUMMARY")
    print("="*50)
    
    if "os_info" in data and "error" not in data["os_info"]:
        os_info = data["os_info"]
        print(f"Hostname: {os_info.get('hostname', 'N/A')}")
        print(f"Platform: {os_info.get('platform', 'N/A')}")
        print(f"Uptime: {os_info.get('uptime_readable', 'N/A')}")
    
    if "system_stats" in data and "error" not in data["system_stats"]:
        stats = data["system_stats"]
        print(f"CPU Cores: {stats.get('cpu_count', 'N/A')}")
        print(f"Memory Usage: {stats.get('memory_used_percent', 'N/A')}%")
        print(f"CPU Usage: {stats.get('cpu_usage_percent', 'N/A')}%")
    
    if "running_processes" in data and isinstance(data["running_processes"], list):
        process_count = len([p for p in data["running_processes"] if "error" not in p])
        print(f"Running Processes: {process_count}")
    
    if "network_connections" in data and isinstance(data["network_connections"], list):
        conn_count = len([c for c in data["network_connections"] if "error" not in c])
        print(f"Network Connections: {conn_count}")
    
    print("="*50)

def main():
    """Main function to orchestrate the data collection."""
    print("System Information Gathering Script - Phase 1")
    print("Starting data collection...\n")
    
    # Collect all information
    system_data = collect_all_info()
    
    # Save to JSON file
    filename = f"system_info_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    if save_to_json(system_data, filename):
        print_summary(system_data)
        print(f"\nData collection completed successfully!")
        print(f"Output saved to: {filename}")
    else:
        print("Failed to save data to file.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScript interrupted by user.")
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
