"""
System Information Gathering Script - Phase 2: Windows Enhanced
Adds Windows Event Logs, Installed Software, Startup Programs, and User Sessions.
"""

import json
import psutil
import platform
import socket
import subprocess
import sys
from datetime import datetime, timedelta
import os

# Windows-specific imports
try:
    import win32evtlog
    import win32evtlogutil
    import winreg
    import pywintypes
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False
    print("Warning: pywin32 not available. Install with: pip install pywin32")

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
            "current_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "is_windows": platform.system().lower() == 'windows'
        }
        return os_info
    except Exception as e:
        return {"error": f"Failed to collect OS info: {str(e)}"}

def get_running_processes():
    """Collect information about running processes."""
    processes = []
    try:
        for proc in psutil.process_iter(['pid', 'name', 'username', 'status', 'cpu_percent', 'memory_percent', 'exe']):
            try:
                proc_info = {
                    "pid": proc.info['pid'],
                    "name": proc.info['name'],
                    "user": proc.info['username'],
                    "status": proc.info['status'],
                    "cpu_percent": proc.info['cpu_percent'],
                    "memory_percent": round(proc.info['memory_percent'], 2) if proc.info['memory_percent'] else 0,
                    "executable_path": proc.info['exe'] if proc.info['exe'] else "N/A"
                }
                processes.append(proc_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
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
                continue
        return connections
    except Exception as e:
        return [{"error": f"Failed to collect network info: {str(e)}"}]

def get_windows_event_logs(max_events=100):
    """Collect Windows Event Logs from Security, System, and Application logs."""
    if not WIN32_AVAILABLE or platform.system().lower() != 'windows':
        return {"error": "Windows Event Logs only available on Windows with pywin32"}
    
    event_logs = {
        "Security": [],
        "System": [],
        "Application": []
    }
    
    for log_type in ["Security", "System", "Application"]:
        try:
            print(f"Collecting {log_type} event logs...")
            
            # Open event log
            hand = win32evtlog.OpenEventLog(None, log_type)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            events_collected = 0
            while events_collected < max_events:
                try:
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
                    if not events:
                        break
                        
                    for event in events:
                        if events_collected >= max_events:
                            break
                            
                        try:
                            event_info = {
                                "event_id": event.EventID & 0xFFFF,  # Remove severity bits
                                "event_category": event.EventCategory,
                                "time_generated": event.TimeGenerated.strftime('%Y-%m-%d %H:%M:%S'),
                                "source_name": event.SourceName,
                                "event_type": event.EventType,
                                "computer_name": event.ComputerName if hasattr(event, 'ComputerName') else "N/A",
                                "record_number": event.RecordNumber,
                                "string_inserts": event.StringInserts if event.StringInserts else []
                            }
                            event_logs[log_type].append(event_info)
                            events_collected += 1
                        except Exception as event_error:
                            continue
                            
                except pywintypes.error as e:
                    if e.winerror == 122:  # ERROR_INSUFFICIENT_BUFFER
                        continue
                    else:
                        break
                        
            win32evtlog.CloseEventLog(hand)
            print(f"Collected {events_collected} {log_type} events")
            
        except Exception as e:
            event_logs[log_type] = [{"error": f"Failed to collect {log_type} logs: {str(e)}"}]
    
    return event_logs

def get_windows_event_logs_powershell(max_events=100):
    """Alternative method using PowerShell wevtutil command."""
    if platform.system().lower() != 'windows':
        return {"error": "Windows Event Logs only available on Windows"}
    
    event_logs = {
        "Security": [],
        "System": [],
        "Application": []
    }
    
    for log_type in ["Security", "System", "Application"]:
        try:
            print(f"Collecting {log_type} event logs via PowerShell...")
            
            # Use wevtutil to export recent events
            cmd = f'wevtutil qe {log_type} /c:{max_events} /rd:true /f:text'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                # Parse the text output (basic parsing)
                lines = result.stdout.split('\n')
                current_event = {}
                events = []
                
                for line in lines:
                    line = line.strip()
                    if line.startswith('Event['):
                        if current_event:
                            events.append(current_event)
                        current_event = {"raw_data": line}
                    elif ':' in line and current_event:
                        key, value = line.split(':', 1)
                        current_event[key.strip()] = value.strip()
                
                if current_event:
                    events.append(current_event)
                
                event_logs[log_type] = events[:max_events]
                print(f"Collected {len(event_logs[log_type])} {log_type} events via PowerShell")
            else:
                event_logs[log_type] = [{"error": f"PowerShell command failed: {result.stderr}"}]
                
        except Exception as e:
            event_logs[log_type] = [{"error": f"Failed to collect {log_type} logs via PowerShell: {str(e)}"}]
    
    return event_logs

def get_installed_software():
    """Get list of installed software from Windows Registry."""
    if not WIN32_AVAILABLE or platform.system().lower() != 'windows':
        return {"error": "Registry access only available on Windows with pywin32"}
    
    installed_software = []
    
    # Registry paths to check
    registry_paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    
    for hkey, subkey_path in registry_paths:
        try:
            with winreg.OpenKey(hkey, subkey_path) as key:
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        i += 1
                        
                        try:
                            with winreg.OpenKey(key, subkey_name) as subkey:
                                software_info = {"registry_key": subkey_name}
                                
                                # Common values to extract
                                values_to_extract = [
                                    "DisplayName", "DisplayVersion", "Publisher", 
                                    "InstallDate", "InstallLocation", "UninstallString",
                                    "DisplayIcon", "EstimatedSize"
                                ]
                                
                                for value_name in values_to_extract:
                                    try:
                                        value, _ = winreg.QueryValueEx(subkey, value_name)
                                        software_info[value_name.lower()] = str(value)
                                    except FileNotFoundError:
                                        pass
                                
                                # Only add if it has a display name
                                if "displayname" in software_info:
                                    installed_software.append(software_info)
                                    
                        except Exception as subkey_error:
                            continue
                            
                    except OSError:
                        # No more subkeys
                        break
                        
        except Exception as e:
            print(f"Error accessing registry path {subkey_path}: {str(e)}")
    
    print(f"Found {len(installed_software)} installed programs")
    return installed_software

def get_startup_programs():
    """Get startup programs from Windows Registry (persistence check)."""
    if not WIN32_AVAILABLE or platform.system().lower() != 'windows':
        return {"error": "Registry access only available on Windows with pywin32"}
    
    startup_programs = {
        "current_user": [],
        "local_machine": []
    }
    
    # Registry paths for startup programs
    startup_paths = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "current_user"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "local_machine"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "current_user"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "local_machine"),
    ]
    
    for hkey, subkey_path, category in startup_paths:
        try:
            with winreg.OpenKey(hkey, subkey_path) as key:
                i = 0
                while True:
                    try:
                        value_name, value_data, value_type = winreg.EnumValue(key, i)
                        i += 1
                        
                        startup_info = {
                            "name": value_name,
                            "command": str(value_data),
                            "registry_path": subkey_path,
                            "type": "RunOnce" if "RunOnce" in subkey_path else "Run"
                        }
                        
                        startup_programs[category].append(startup_info)
                        
                    except OSError:
                        # No more values
                        break
                        
        except Exception as e:
            print(f"Error accessing startup registry path {subkey_path}: {str(e)}")
    
    total_startup = len(startup_programs["current_user"]) + len(startup_programs["local_machine"])
    print(f"Found {total_startup} startup programs")
    return startup_programs

def get_user_accounts_and_sessions():
    """Get user accounts and active sessions."""
    user_info = {
        "logged_in_users": [],
        "user_accounts": []
    }
    
    # Get currently logged-in users
    try:
        users = psutil.users()
        for user in users:
            user_session = {
                "name": user.name,
                "terminal": user.terminal if user.terminal else "N/A",
                "host": user.host if user.host else "N/A",
                "started": datetime.fromtimestamp(user.started).strftime('%Y-%m-%d %H:%M:%S'),
                "pid": user.pid if hasattr(user, 'pid') else "N/A"
            }
            user_info["logged_in_users"].append(user_session)
        
        print(f"Found {len(user_info['logged_in_users'])} active user sessions")
        
    except Exception as e:
        user_info["logged_in_users"] = [{"error": f"Failed to get user sessions: {str(e)}"}]
    
    # Get user accounts from registry (Windows only)
    if WIN32_AVAILABLE and platform.system().lower() == 'windows':
        try:
            # Get user profiles from registry
            profiles_key = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, profiles_key) as key:
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        i += 1
                        
                        if subkey_name.startswith('S-1-5-21'):  # User SID pattern
                            try:
                                with winreg.OpenKey(key, subkey_name) as profile_key:
                                    try:
                                        profile_path, _ = winreg.QueryValueEx(profile_key, "ProfileImagePath")
                                        username = os.path.basename(profile_path)
                                        
                                        user_account = {
                                            "sid": subkey_name,
                                            "username": username,
                                            "profile_path": profile_path
                                        }
                                        
                                        # Try to get additional info
                                        try:
                                            flags, _ = winreg.QueryValueEx(profile_key, "Flags")
                                            user_account["flags"] = flags
                                        except FileNotFoundError:
                                            pass
                                            
                                        user_info["user_accounts"].append(user_account)
                                        
                                    except FileNotFoundError:
                                        pass
                            except Exception as profile_error:
                                continue
                                
                    except OSError:
                        break
                        
            print(f"Found {len(user_info['user_accounts'])} user accounts")
            
        except Exception as e:
            user_info["user_accounts"] = [{"error": f"Failed to get user accounts: {str(e)}"}]
    
    return user_info

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
                continue
                
        return stats
    except Exception as e:
        return {"error": f"Failed to collect system stats: {str(e)}"}

def collect_all_info():
    """Collect all system information including new Phase 2 features."""
    print("System Information Gathering Script - Phase 2")
    print("=" * 60)
    
    system_info = {
        "collection_timestamp": datetime.now().isoformat(),
        "phase": "Phase 2 - Windows Enhanced",
        "os_info": get_os_info(),
        "system_stats": get_system_stats(),
        "running_processes": get_running_processes(),
        "network_connections": get_network_connections(),
        "user_sessions": get_user_accounts_and_sessions()
    }
    
    # Windows-specific features
    if platform.system().lower() == 'windows':
        print("\nCollecting Windows-specific information...")
        
        # Try win32evtlog first, fallback to PowerShell
        if WIN32_AVAILABLE:
            system_info["windows_event_logs"] = get_windows_event_logs(max_events=50)
        else:
            print("Falling back to PowerShell for event logs...")
            system_info["windows_event_logs"] = get_windows_event_logs_powershell(max_events=50)
        
        system_info["installed_software"] = get_installed_software()
        system_info["startup_programs"] = get_startup_programs()
    else:
        print(f"Skipping Windows-specific features (detected: {platform.system()})")
        system_info["windows_event_logs"] = {"error": "Not a Windows system"}
        system_info["installed_software"] = {"error": "Not a Windows system"}
        system_info["startup_programs"] = {"error": "Not a Windows system"}
    
    return system_info

def save_to_json(data, filename):
    """Save collected data to JSON file."""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"\nSystem information saved to: {filename}")
        print(f"File size: {os.path.getsize(filename)} bytes")
        return True
    except Exception as e:
        print(f"Error saving to JSON: {str(e)}")
        return False

def print_summary(data):
    """Print a summary of collected information."""
    print("\n" + "="*60)
    print("SYSTEM INFORMATION SUMMARY - PHASE 2")
    print("="*60)
    
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
    
    if "user_sessions" in data:
        sessions = data["user_sessions"].get("logged_in_users", [])
        if sessions and not any("error" in str(s) for s in sessions):
            print(f"Active User Sessions: {len(sessions)}")
    
    # Windows-specific summary
    if platform.system().lower() == 'windows':
        if "windows_event_logs" in data:
            event_counts = {}
            for log_type, events in data["windows_event_logs"].items():
                if isinstance(events, list) and not any("error" in str(e) for e in events):
                    event_counts[log_type] = len(events)
            if event_counts:
                print(f"Event Logs: {event_counts}")
        
        if "installed_software" in data and isinstance(data["installed_software"], list):
            software_count = len([s for s in data["installed_software"] if "error" not in str(s)])
            if software_count > 0:
                print(f"Installed Software: {software_count} programs")
        
        if "startup_programs" in data and isinstance(data["startup_programs"], dict):
            startup_count = (len(data["startup_programs"].get("current_user", [])) + 
                           len(data["startup_programs"].get("local_machine", [])))
            if startup_count > 0:
                print(f"Startup Programs: {startup_count}")
    
    print("="*60)

def main():
    """Main function to orchestrate the data collection."""
    print("System Information Gathering Script - Phase 2: Windows Enhanced")
    print("Starting comprehensive data collection...\n")
    
    # Check prerequisites
    if platform.system().lower() == 'windows' and not WIN32_AVAILABLE:
        print("WARNING: pywin32 not installed. Install with: pip install pywin32")
        print("Some Windows features will use PowerShell fallbacks.\n")
    
    # Collect all information
    system_data = collect_all_info()
    
    # Save to JSON file
    filename = f"system_info_phase2_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    if save_to_json(system_data, filename):
        print_summary(system_data)
        print(f"\nPhase 2 data collection completed successfully!")
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
        import traceback
        traceback.print_exc()
