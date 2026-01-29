
import json
import psutil
import platform
import socket
import subprocess
import sys
import hashlib
import requests
import time
import os
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import zipfile
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

# PDF and Chart Generation - Fixed imports
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    from reportlab.graphics.shapes import Drawing
    REPORTLAB_AVAILABLE = True
except ImportError as e:
    print(f"Warning: ReportLab not available - {e}")
    REPORTLAB_AVAILABLE = False

# Encryption
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import base64
    CRYPTO_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Cryptography not available - {e}")
    CRYPTO_AVAILABLE = False

# Windows-specific imports
try:
    import win32evtlog
    import win32evtlogutil
    import winreg
    import pywintypes
    import win32api
    import win32security
    import win32service
    import win32serviceutil
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False

class ServiceAnalyzer:
    """Windows Service Analysis and Security Assessment"""
    
    def __init__(self):
        # High-risk services that are commonly exploited or unnecessary
        self.high_risk_services = {
            "RemoteRegistry": {
                "reason": "Allows remote registry access - major security risk",
                "risk_level": "CRITICAL",
                "action": "STOP and DISABLE",
                "category": "Remote Access"
            },
            "Telnet": {
                "reason": "Unencrypted remote access protocol - use SSH instead",
                "risk_level": "CRITICAL", 
                "action": "STOP and DISABLE",
                "category": "Remote Access"
            },
            "TlntSvr": {
                "reason": "Telnet server - unencrypted and insecure",
                "risk_level": "CRITICAL",
                "action": "STOP and DISABLE", 
                "category": "Remote Access"
            },
            "SimpleMailTransferProtocol": {
                "reason": "SMTP service can be exploited for spam/relay attacks",
                "risk_level": "HIGH",
                "action": "STOP if not needed",
                "category": "Network Service"
            },
            "RemoteAccess": {
                "reason": "RAS service - potential attack vector if not needed",
                "risk_level": "HIGH",
                "action": "STOP if VPN not used",
                "category": "Remote Access"
            },
            "Messenger": {
                "reason": "Legacy service vulnerable to buffer overflow attacks",
                "risk_level": "HIGH",
                "action": "STOP and DISABLE",
                "category": "Legacy Service"
            },
            "NetMeeting": {
                "reason": "Outdated conferencing service with security vulnerabilities", 
                "risk_level": "HIGH",
                "action": "STOP and DISABLE",
                "category": "Legacy Service"
            },
            "ClipSrv": {
                "reason": "ClipBook service - rarely used and potential security risk",
                "risk_level": "MEDIUM",
                "action": "STOP if not needed",
                "category": "Utility Service"
            },
            "Alerter": {
                "reason": "Administrative alert service - can be exploited",
                "risk_level": "MEDIUM", 
                "action": "STOP if not needed",
                "category": "Administrative"
            },
            "Browser": {
                "reason": "Computer Browser service - network enumeration risk",
                "risk_level": "MEDIUM",
                "action": "STOP if not needed",
                "category": "Network Service"
            }
        }
        
        # Services that should be scrutinized for suspicious behavior
        self.suspicious_patterns = {
            "startup_paths": [
                "temp", "tmp", "appdata", "programdata", "users\\public",
                "downloads", "recycle.bin", "$recycle.bin"
            ],
            "suspicious_names": [
                "svchost", "winlogon", "csrss", "lsass", "services",
                "system", "explorer", "taskmgr", "cmd", "powershell"
            ],
            "malicious_extensions": [".tmp", ".bat", ".vbs", ".ps1", ".scr"],
            "network_services": ["http", "ftp", "smtp", "telnet", "ssh", "vnc"]
        }
        
        # Critical system services that should never be stopped
        self.critical_services = {
            "EventLog", "PlugPlay", "PolicyAgent", "ProtectedStorage", 
            "SamSs", "Spooler", "lanmanserver", "lanmanworkstation",
            "Netlogon", "Themes", "AudioSrv", "SENS", "ShellHWDetection",
            "Winmgmt", "W32Time", "Schedule", "Dhcp", "Dnscache"
        }

    def get_windows_services(self):
        """Get comprehensive Windows service information"""
        if platform.system().lower() != 'windows':
            return []
        
        services = []
        
        try:
            # Method 1: Using sc query command (most comprehensive)
            cmd = 'sc query state= all'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                services.extend(self._parse_sc_output(result.stdout))
            
            # Method 2: Using wmic (additional details)
            try:
                cmd = 'wmic service get Name,DisplayName,State,StartMode,PathName,ProcessId /format:csv'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    wmic_services = self._parse_wmic_output(result.stdout)
                    services = self._merge_service_data(services, wmic_services)
                    
            except Exception as e:
                print(f"WMIC query failed: {e}")
            
            # Method 3: Using Win32 APIs if available
            if WIN32_AVAILABLE:
                try:
                    api_services = self._get_services_via_api()
                    services = self._merge_service_data(services, api_services)
                except Exception as e:
                    print(f"Win32 API query failed: {e}")
            
            return services
            
        except Exception as e:
            print(f"Service enumeration failed: {e}")
            return []

    def _parse_sc_output(self, output):
        """Parse sc query output"""
        services = []
        current_service = {}
        
        for line in output.split('\n'):
            line = line.strip()
            if line.startswith('SERVICE_NAME:'):
                if current_service:
                    services.append(current_service)
                current_service = {'name': line.split(':', 1)[1].strip()}
            elif line.startswith('DISPLAY_NAME:'):
                current_service['display_name'] = line.split(':', 1)[1].strip()
            elif line.startswith('STATE:'):
                state_info = line.split(':', 1)[1].strip()
                current_service['state'] = state_info.split()[0]
            elif line.startswith('TYPE:'):
                current_service['type'] = line.split(':', 1)[1].strip()
        
        if current_service:
            services.append(current_service)
        
        return services

    def _parse_wmic_output(self, output):
        """Parse wmic service output"""
        services = []
        lines = output.strip().split('\n')
        
        if len(lines) < 2:
            return services
        
        headers = [h.strip() for h in lines[0].split(',')]
        
        for line in lines[1:]:
            if line.strip():
                try:
                    values = [v.strip() for v in line.split(',')]
                    if len(values) >= len(headers):
                        service = dict(zip(headers, values))
                        # Clean up the service data
                        cleaned_service = {
                            'name': service.get('Name', '').strip(),
                            'display_name': service.get('DisplayName', '').strip(),
                            'state': service.get('State', '').strip(),
                            'start_mode': service.get('StartMode', '').strip(),
                            'path_name': service.get('PathName', '').strip(),
                            'process_id': service.get('ProcessId', '').strip()
                        }
                        if cleaned_service['name']:  # Only add if we have a name
                            services.append(cleaned_service)
                except Exception as e:
                    continue
        
        return services

    def _get_services_via_api(self):
        """Get services using Win32 API"""
        services = []
        
        try:
            scm_handle = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ENUMERATE_SERVICE)
            service_list = win32service.EnumServicesStatus(scm_handle)
            
            for service in service_list:
                service_name = service[0]
                display_name = service[1]
                service_status = service[2]
                
                try:
                    service_handle = win32service.OpenService(scm_handle, service_name, win32service.SERVICE_QUERY_CONFIG)
                    config = win32service.QueryServiceConfig(service_handle)
                    
                    services.append({
                        'name': service_name,
                        'display_name': display_name,
                        'state': self._get_service_state_name(service_status[1]),
                        'start_mode': self._get_start_type_name(config[1]),
                        'path_name': config[3],
                        'service_type': config[0],
                        'error_control': config[2],
                        'load_order_group': config[4],
                        'dependencies': config[6]
                    })
                    
                    win32service.CloseServiceHandle(service_handle)
                    
                except Exception as e:
                    continue
            
            win32service.CloseServiceHandle(scm_handle)
            
        except Exception as e:
            print(f"Win32 service API error: {e}")
        
        return services

    def _get_service_state_name(self, state_code):
        """Convert service state code to name"""
        states = {
            1: "STOPPED",
            2: "START_PENDING", 
            3: "STOP_PENDING",
            4: "RUNNING",
            5: "CONTINUE_PENDING",
            6: "PAUSE_PENDING",
            7: "PAUSED"
        }
        return states.get(state_code, f"UNKNOWN({state_code})")

    def _get_start_type_name(self, start_type):
        """Convert start type code to name"""
        types = {
            0: "Boot",
            1: "System", 
            2: "Automatic",
            3: "Manual",
            4: "Disabled"
        }
        return types.get(start_type, f"UNKNOWN({start_type})")

    def _merge_service_data(self, services1, services2):
        """Merge service data from multiple sources"""
        merged = {}
        
        # Add services from first list
        for service in services1:
            name = service.get('name', '').lower()
            if name:
                merged[name] = service
        
        # Merge data from second list
        for service in services2:
            name = service.get('name', '').lower()
            if name:
                if name in merged:
                    # Merge additional fields
                    merged[name].update({k: v for k, v in service.items() if v and k not in merged[name]})
                else:
                    merged[name] = service
        
        return list(merged.values())

    def analyze_services(self, services):
        """Analyze services for security risks and provide recommendations"""
        analysis_results = {
            "critical_risks": [],
            "high_risks": [],
            "medium_risks": [],
            "suspicious_services": [],
            "unnecessary_services": [],
            "recommendations": []
        }
        
        for service in services:
            service_name = service.get('name', '').lower()
            display_name = service.get('display_name', '')
            state = service.get('state', '').upper()
            start_mode = service.get('start_mode', '').lower()
            path_name = service.get('path_name', '').lower()
            
            # Skip if no service name
            if not service_name:
                continue
            
            # Initialize analysis for this service
            service_analysis = {
                'service': service,
                'risk_level': 'LOW',
                'reasons': [],
                'recommendations': [],
                'category': 'Normal Service'
            }
            
            # Check against high-risk services database
            for risk_service, risk_info in self.high_risk_services.items():
                if risk_service.lower() in service_name or risk_service.lower() in display_name.lower():
                    if state == 'RUNNING' or start_mode == 'automatic':
                        service_analysis.update({
                            'risk_level': risk_info['risk_level'],
                            'reasons': [risk_info['reason']],
                            'recommendations': [risk_info['action']],
                            'category': risk_info['category']
                        })
                        break
            
            # Check for suspicious service characteristics
            suspicion_score = 0
            suspicious_flags = []
            
            # Check service path for suspicious locations
            for sus_path in self.suspicious_patterns['startup_paths']:
                if sus_path in path_name:
                    suspicion_score += 25
                    suspicious_flags.append(f"running_from_suspicious_path:{sus_path}")
            
            # Check for suspicious service names (possible impersonation)
            for sus_name in self.suspicious_patterns['suspicious_names']:
                if sus_name in service_name and service_name != sus_name:
                    suspicion_score += 20
                    suspicious_flags.append(f"suspicious_name_pattern:{sus_name}")
            
            # Check for services with no description or path
            if not display_name or display_name == service_name:
                suspicion_score += 10
                suspicious_flags.append("missing_description")
            
            if not path_name or path_name == "n/a":
                suspicion_score += 15
                suspicious_flags.append("missing_executable_path")
            
            # Check for services running from unusual extensions
            for ext in self.suspicious_patterns['malicious_extensions']:
                if path_name.endswith(ext):
                    suspicion_score += 30
                    suspicious_flags.append(f"suspicious_extension:{ext}")
            
            # Assign risk level based on suspicion score
            if suspicion_score >= 30:
                service_analysis['risk_level'] = 'HIGH'
                service_analysis['reasons'].append(f"High suspicion score: {suspicion_score}")
                service_analysis['recommendations'].append("Investigate service thoroughly")
                service_analysis['category'] = 'Suspicious Service'
            elif suspicion_score >= 15:
                service_analysis['risk_level'] = 'MEDIUM'
                service_analysis['reasons'].append(f"Medium suspicion score: {suspicion_score}")
                service_analysis['recommendations'].append("Monitor service behavior")
            
            service_analysis['suspicion_score'] = suspicion_score
            service_analysis['suspicious_flags'] = suspicious_flags
            
            # Categorize the analysis results
            risk_level = service_analysis['risk_level']
            if risk_level == 'CRITICAL':
                analysis_results['critical_risks'].append(service_analysis)
            elif risk_level == 'HIGH':
                analysis_results['high_risks'].append(service_analysis)
            elif risk_level == 'MEDIUM':
                analysis_results['medium_risks'].append(service_analysis)
            
            if suspicion_score > 0:
                analysis_results['suspicious_services'].append(service_analysis)
        
        # Generate comprehensive recommendations
        analysis_results['recommendations'] = self._generate_service_recommendations(analysis_results)
        
        return analysis_results

    def _generate_service_recommendations(self, analysis_results):
        """Generate detailed service recommendations"""
        recommendations = []
        
        # Critical risk services
        for analysis in analysis_results['critical_risks']:
            service = analysis['service']
            recommendations.append({
                'priority': 'CRITICAL',
                'service_name': service.get('name', 'Unknown'),
                'display_name': service.get('display_name', 'Unknown'),
                'action': f"IMMEDIATELY STOP AND DISABLE: {service.get('display_name', service.get('name', 'Unknown'))}",
                'reason': '; '.join(analysis['reasons']),
                'commands': [
                    f"sc stop \"{service.get('name', '')}\"",
                    f"sc config \"{service.get('name', '')}\" start= disabled"
                ],
                'risk_level': 'CRITICAL',
                'category': analysis['category']
            })
        
        # High risk services
        for analysis in analysis_results['high_risks']:
            service = analysis['service']
            state = service.get('state', '').upper()
            
            if state == 'RUNNING':
                action = f"STOP service: {service.get('display_name', service.get('name', 'Unknown'))}"
                commands = [f"sc stop \"{service.get('name', '')}\""]
            else:
                action = f"ENSURE DISABLED: {service.get('display_name', service.get('name', 'Unknown'))}"
                commands = [f"sc config \"{service.get('name', '')}\" start= disabled"]
            
            recommendations.append({
                'priority': 'HIGH',
                'service_name': service.get('name', 'Unknown'),
                'display_name': service.get('display_name', 'Unknown'),
                'action': action,
                'reason': '; '.join(analysis['reasons']),
                'commands': commands,
                'risk_level': 'HIGH',
                'category': analysis['category']
            })
        
        # Medium risk services
        for analysis in analysis_results['medium_risks']:
            service = analysis['service']
            recommendations.append({
                'priority': 'MEDIUM',
                'service_name': service.get('name', 'Unknown'),
                'display_name': service.get('display_name', 'Unknown'),
                'action': f"REVIEW service: {service.get('display_name', service.get('name', 'Unknown'))}",
                'reason': '; '.join(analysis['reasons']),
                'commands': [
                    f"sc query \"{service.get('name', '')}\"",
                    f"sc qc \"{service.get('name', '')}\""
                ],
                'risk_level': 'MEDIUM',
                'category': analysis['category']
            })
        
        # Suspicious services
        for analysis in analysis_results['suspicious_services']:
            if analysis not in analysis_results['critical_risks'] and analysis not in analysis_results['high_risks']:
                service = analysis['service']
                recommendations.append({
                    'priority': 'HIGH',
                    'service_name': service.get('name', 'Unknown'),
                    'display_name': service.get('display_name', 'Unknown'),
                    'action': f"INVESTIGATE suspicious service: {service.get('display_name', service.get('name', 'Unknown'))}",
                    'reason': f"Suspicious patterns detected: {', '.join(analysis['suspicious_flags'])}",
                    'commands': [
                        f"sc query \"{service.get('name', '')}\"",
                        f"wmic service where name=\"{service.get('name', '')}\" get *",
                        "Check file signature and location"
                    ],
                    'risk_level': 'HIGH',
                    'category': 'Suspicious Service'
                })
        
        # Sort recommendations by priority
        priority_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        recommendations.sort(key=lambda x: priority_order.get(x['priority'], 4))
        
        return recommendations

class SOCSecurityAnalyzer:
    """Main SOC-Ready Security Analysis Tool with Service Analysis"""
    
    def __init__(self):
        self.version = "4.1.1"
        self.vt_api_key = "0af097982ab18dd43e82486df7d2ed7ad483757fcecbb9ac05318a09b6449b4e" #input("Enter your VirusTotal API v3 Key: ")
        """Please update your API key here generate it from the Virustotal's official site"""
        self.vt_base_url = "https://www.virustotal.com/api/v3"
        
        # Initialize service analyzer
        self.service_analyzer = ServiceAnalyzer()
        
        # Analysis results
        self.system_data = {}
        self.suspicious_processes = []
        self.persistence_threats = []
        self.service_analysis = {}
        self.incident_report = {}
        
        # Configuration
        self.config = {
            "output_directory": "soc_reports",
            "encrypt_reports": CRYPTO_AVAILABLE,
            "email_reports": False,
            "soc_email": "",
            "smtp_server": "smtp.gmail.com",
            "smtp_port": 587,
            "smtp_user": "",
            "smtp_password": "",
            "max_vt_requests": 4,
            "compress_reports": True,
            "generate_pdf": REPORTLAB_AVAILABLE,
            "analyze_services": True
        }
        
        # Ensure output directory exists
        os.makedirs(self.config["output_directory"], exist_ok=True)
        
        # GUI components
        self.root = None
        self.progress_var = None
        self.status_var = None
        self.log_text = None

    def log_message(self, message):
        """Log message to console and GUI if available"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_line = f"[{timestamp}] {message}"
        print(log_line)
        
        if self.log_text:
            self.log_text.insert(tk.END, log_line + "\n")
            self.log_text.see(tk.END)
            if self.root:
                self.root.update_idletasks()

    def update_progress(self, value, status=""):
        """Update progress bar and status"""
        if self.progress_var:
            self.progress_var.set(value)
        if self.status_var and status:
            self.status_var.set(status)
        if self.root:
            self.root.update_idletasks()

    def run_full_analysis(self):
        """Run complete security analysis including services"""
        self.log_message("🚀 Starting Incident Responder")
        self.update_progress(5, "Initializing analysis...")
        
        # Collect system information
        self.log_message("📊 Collecting system information...")
        self.system_data = {
            "collection_timestamp": datetime.now().isoformat(),
            "phase": "Phase 4 - SOC Ready with Service Analysis",
            "version": self.version,
            "os_info": self.get_os_info(),
            "running_processes": self.get_running_processes()
        }
        
        self.update_progress(15, "Analyzing processes...")
        
        # Analyze processes for threats
        self.log_message("🔬 Analyzing processes for threats...")
        self.suspicious_processes = self.detect_process_anomalies(self.system_data['running_processes'])
        
        self.update_progress(35, "Analyzing Windows services...")
        
        # Analyze Windows services
        if platform.system().lower() == 'windows' and self.config.get("analyze_services", True):
            self.log_message("🔧 Analyzing Windows services for security risks...")
            services = self.service_analyzer.get_windows_services()
            self.system_data['windows_services'] = services
            
            if services:
                self.service_analysis = self.service_analyzer.analyze_services(services)
                self.log_message(f"📊 Service Analysis Complete:")
                self.log_message(f"   • Critical Risks: {len(self.service_analysis['critical_risks'])}")
                self.log_message(f"   • High Risks: {len(self.service_analysis['high_risks'])}")
                self.log_message(f"   • Medium Risks: {len(self.service_analysis['medium_risks'])}")
                self.log_message(f"   • Suspicious Services: {len(self.service_analysis['suspicious_services'])}")
        else:
            self.log_message("⚠️  Service analysis skipped (not Windows or disabled)")
            self.service_analysis = {}
        
        self.update_progress(55, "Checking persistence mechanisms...")
        
        # Get persistence mechanisms (Windows only)
        self.persistence_threats = []
        if platform.system().lower() == 'windows':
            self.log_message("🔒 Analyzing persistence mechanisms...")
            startup_programs = self.get_startup_programs()
            scheduled_tasks = self.get_scheduled_tasks_windows()
            
            self.system_data['startup_programs'] = startup_programs
            self.system_data['scheduled_tasks'] = scheduled_tasks
            
            self.persistence_threats = self.analyze_persistence_mechanisms(startup_programs, scheduled_tasks)
        
        self.update_progress(80, "Generating incident report...")
        
        # Generate incident report
        self.log_message("📋 Generating comprehensive incident report...")
        self.incident_report = self.create_incident_report()
        
        self.update_progress(100, "Analysis complete!")
        self.log_message("✅ Enhanced security analysis completed successfully!")

        # Log summary of findings
        self._log_analysis_summary()
        
        return True

    def _log_analysis_summary(self):
        """Log summary of analysis findings"""
        self.log_message("\n📊 ANALYSIS SUMMARY:")
        self.log_message("=" * 50)
        
        # Process findings
        malware_count = sum(1 for proc in self.suspicious_processes if proc.get('virustotal_result', {}).get('malicious', 0) > 0)
        self.log_message(f"🔬 Process Analysis:")
        self.log_message(f"   • Suspicious Processes: {len(self.suspicious_processes)}")
        self.log_message(f"   • Malware Detected: {malware_count}")
        
        # Service findings
        if self.service_analysis:
            self.log_message(f"🔧 Service Analysis:")
            self.log_message(f"   • Critical Service Risks: {len(self.service_analysis['critical_risks'])}")
            self.log_message(f"   • High Service Risks: {len(self.service_analysis['high_risks'])}")
            self.log_message(f"   • Service Recommendations: {len(self.service_analysis['recommendations'])}")
        
        # Overall risk
        risk_level = self.incident_report.get('summary', {}).get('risk_level', 'UNKNOWN')
        self.log_message(f"🎯 Overall Risk Level: {risk_level}")
        
        # Top recommendations
        recommendations = self.incident_report.get('recommendations', [])
        critical_recs = [r for r in recommendations if r.get('priority') == 'CRITICAL']
        if critical_recs:
            self.log_message(f"🚨 CRITICAL ACTIONS REQUIRED: {len(critical_recs)}")
            for i, rec in enumerate(critical_recs[:3], 1):
                self.log_message(f"   {i}. {rec.get('action', 'Unknown action')}")

    # [Include all previous methods from the original class - get_os_info, get_running_processes, etc.]
    def get_os_info(self):
        """Collect operating system information."""
        try:
            return {
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
        except Exception as e:
            return {"error": f"Failed to collect OS info: {str(e)}"}

    def get_running_processes(self):
        """Collect detailed information about running processes."""
        processes = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username', 'status', 'cpu_percent', 'memory_percent', 'exe', 'cmdline']):
                try:
                    proc_info = {
                        "pid": proc.info['pid'],
                        "name": proc.info['name'],
                        "user": proc.info['username'],
                        "status": proc.info['status'],
                        "cpu_percent": proc.info['cpu_percent'],
                        "memory_percent": round(proc.info['memory_percent'], 2) if proc.info['memory_percent'] else 0,
                        "executable_path": proc.info['exe'] if proc.info['exe'] else "N/A",
                        "command_line": ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else "N/A"
                    }
                    processes.append(proc_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            return processes
        except Exception as e:
            return [{"error": f"Failed to collect process info: {str(e)}"}]

    def calculate_file_hash(self, file_path, algorithm='sha256'):
        """Calculate hash of a file"""
        try:
            hash_algo = hashlib.new(algorithm)
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    hash_algo.update(chunk)
            return hash_algo.hexdigest()
        except (IOError, OSError, PermissionError) as e:
            return None

    def check_virustotal_v3(self, file_hash):
        """Check file hash against VirusTotal API v3"""
        if not self.vt_api_key:
            return {"error": "No VirusTotal API key provided"}
        
        try:
            url = f"{self.vt_base_url}/files/{file_hash}"
            headers = {
                "x-apikey": self.vt_api_key,
                "Accept": "application/json"
            }
            
            response = requests.get(url, headers=headers, timeout=15)
            
            if response.status_code == 200:
                result = response.json()
                data = result.get('data', {})
                attributes = data.get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})
                
                # Get threat names from engines that detected malware
                threat_names = []
                analysis_results = attributes.get('last_analysis_results', {})
                for engine, result_data in analysis_results.items():
                    if result_data.get('category') == 'malicious' and result_data.get('result'):
                        threat_names.append(f"{engine}: {result_data.get('result')}")
                
                return {
                    "found": True,
                    "malicious": stats.get('malicious', 0),
                    "suspicious": stats.get('suspicious', 0),
                    "undetected": stats.get('undetected', 0),
                    "harmless": stats.get('harmless', 0),
                    "timeout": stats.get('timeout', 0),
                    "total_engines": sum(stats.values()),
                    "detection_ratio": f"{stats.get('malicious', 0) + stats.get('suspicious', 0)}/{sum(stats.values())}",
                    "scan_date": datetime.fromtimestamp(attributes.get('last_analysis_date', 0)).strftime('%Y-%m-%d %H:%M:%S') if attributes.get('last_analysis_date') else 'Unknown',
                    "file_type": attributes.get('type_description', 'Unknown'),
                    "file_size": attributes.get('size', 0),
                    "threat_names": threat_names[:5],
                    "reputation": attributes.get('reputation', 0)
                }
            elif response.status_code == 404:
                return {"found": False, "message": "File not found in VirusTotal database"}
            elif response.status_code == 429:
                return {"error": "Rate limit exceeded. Please wait before making more requests."}
            else:
                return {"error": f"VirusTotal API error: {response.status_code}"}
                
        except Exception as e:
            return {"error": f"VirusTotal check failed: {str(e)}"}

    def detect_process_anomalies(self, processes):
        """Detect suspicious process behavior"""
        suspicious_processes = []
        
        # Suspicious and system paths
        suspicious_paths = [
            "temp", "tmp", "appdata\\local\\temp", "programdata",
            "users\\public", "windows\\temp", "recycle.bin", "downloads"
        ]
        
        vt_request_count = 0
        vt_last_request_time = time.time()
        
        total_processes = len([p for p in processes if isinstance(p, dict) and "error" not in p])
        self.log_message(f"📊 Analyzing {total_processes} processes...")
        
        for i, proc in enumerate(processes):
            if isinstance(proc, dict) and "error" not in proc:
                suspicion_score = 0
                flags = []
                
                if i % 10 == 0:  # Update progress every 10 processes
                    progress = 15 + (20 * i / total_processes)  # Between 15-35%
                    self.update_progress(progress, f"Analyzing process {i+1}/{total_processes}")
                
                exe_path = proc.get('executable_path', '')
                path_lower = exe_path.lower() if exe_path else ''
                
                # Check for suspicious paths
                for sus_path in suspicious_paths:
                    if sus_path in path_lower:
                        suspicion_score += 30
                        flags.append("running_from_suspicious_location")
                        break
                
                # Check for high resource usage
                if proc.get('cpu_percent', 0) > 80:
                    suspicion_score += 10
                    flags.append("high_cpu_usage")
                
                if proc.get('memory_percent', 0) > 50:
                    suspicion_score += 10
                    flags.append("high_memory_usage")
                
                # Calculate file hash and check VirusTotal (rate limited)
                if exe_path and os.path.exists(exe_path):
                    file_hash = self.calculate_file_hash(exe_path)
                    if file_hash:
                        proc['file_hash'] = file_hash
                        
                        # Rate limiting for VirusTotal API
                        current_time = time.time()
                        if current_time - vt_last_request_time >= 15:
                            vt_request_count = 0
                            vt_last_request_time = current_time
                        
                        if vt_request_count < self.config["max_vt_requests"]:
                            vt_result = self.check_virustotal_v3(file_hash)
                            proc['virustotal_result'] = vt_result
                            vt_request_count += 1
                            vt_last_request_time = time.time()
                            
                            if vt_result.get('found'):
                                malicious_count = vt_result.get('malicious', 0)
                                if malicious_count > 0:
                                    suspicion_score += min(50, malicious_count * 5)
                                    flags.append(f"virustotal_malicious:{malicious_count}")
                                    self.log_message(f"🚨 MALWARE DETECTED: {proc.get('name')} - {malicious_count} detections")
                
                if suspicion_score >= 25:
                    proc['suspicion_score'] = suspicion_score
                    proc['flags'] = flags
                    suspicious_processes.append(proc)
                    self.log_message(f"⚠️ Suspicious: {proc.get('name')} (Score: {suspicion_score})")
        
        return suspicious_processes

    def get_startup_programs(self):
        """Get startup programs from Windows Registry."""
        if not WIN32_AVAILABLE or platform.system().lower() != 'windows':
            return {"error": "Registry access only available on Windows"}
        
        startup_programs = {"current_user": [], "local_machine": []}
        
        startup_paths = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "current_user"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "local_machine"),
        ]
        
        for hkey, subkey_path, category in startup_paths:
            try:
                with winreg.OpenKey(hkey, subkey_path) as key:
                    i = 0
                    while True:
                        try:
                            value_name, value_data, value_type = winreg.EnumValue(key, i)
                            startup_info = {
                                "name": value_name,
                                "command": str(value_data),
                                "registry_path": subkey_path
                            }
                            startup_programs[category].append(startup_info)
                            i += 1
                        except OSError:
                            break
            except Exception as e:
                continue
        
        return startup_programs

    def get_scheduled_tasks_windows(self):
        """Get Windows scheduled tasks"""
        if platform.system().lower() != 'windows':
            return []
        
        try:
            cmd = 'schtasks /query /fo csv /v'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                tasks = []
                if len(lines) > 1:
                    headers = [h.strip('"') for h in lines[0].split(',')]
                    for line in lines[1:]:
                        if line.strip():
                            try:
                                values = [v.strip('"') for v in line.split(',')]
                                if len(values) >= len(headers):
                                    task = dict(zip(headers, values))
                                    tasks.append(task)
                            except:
                                continue
                return tasks
        except Exception as e:
            return []

    def analyze_persistence_mechanisms(self, startup_programs, scheduled_tasks):
        """Analyze persistence mechanisms for threats"""
        threats = []
        
        # Analyze startup programs
        if isinstance(startup_programs, dict):
            for location, programs in startup_programs.items():
                if isinstance(programs, list):
                    for program in programs:
                        command = program.get('command', '').lower()
                        suspicious_patterns = ['temp', 'tmp', 'appdata', 'powershell -enc']
                        
                        if any(pattern in command for pattern in suspicious_patterns):
                            threats.append({
                                "type": "suspicious_startup_program",
                                "name": program.get('name', 'Unknown'),
                                "command": command,
                                "risk_level": "medium"
                            })
        
        return threats

    def create_incident_report(self):
        """Create comprehensive incident report including service analysis"""
        total_processes = len([p for p in self.system_data.get('running_processes', []) if isinstance(p, dict)])
        
        # Calculate service statistics
        service_stats = {
            "total_services": len(self.system_data.get('windows_services', [])),
            "critical_service_risks": len(self.service_analysis.get('critical_risks', [])),
            "high_service_risks": len(self.service_analysis.get('high_risks', [])),
            "medium_service_risks": len(self.service_analysis.get('medium_risks', [])),
            "suspicious_services": len(self.service_analysis.get('suspicious_services', [])),
            "service_recommendations": len(self.service_analysis.get('recommendations', []))
        }
        
        return {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_processes_scanned": total_processes,
                "suspicious_processes_found": len(self.suspicious_processes),
                "persistence_threats_found": len(self.persistence_threats),
                "service_analysis": service_stats,
                "risk_level": self.calculate_risk_level(),
                "system_info": self.system_data.get('os_info', {})
            },
            "suspicious_processes": self.suspicious_processes,
            "persistence_threats": self.persistence_threats,
            "service_analysis": self.service_analysis,
            "recommendations": self.generate_comprehensive_recommendations()
        }

    def calculate_risk_level(self):
        """Calculate overall risk level including service risks"""
        malware_count = sum(1 for proc in self.suspicious_processes if proc.get('virustotal_result', {}).get('malicious', 0) > 0)
        critical_services = len(self.service_analysis.get('critical_risks', []))
        high_risk_services = len(self.service_analysis.get('high_risks', []))
        
        if malware_count > 0 or critical_services > 0:
            return "CRITICAL"
        elif len(self.suspicious_processes) >= 3 or high_risk_services >= 2:
            return "HIGH"
        elif len(self.suspicious_processes) >= 1 or high_risk_services >= 1:
            return "MEDIUM"
        else:
            return "LOW"

    def generate_comprehensive_recommendations(self):
        """Generate comprehensive security recommendations including services"""
        recommendations = []

        # Process-based recommendations
        for proc in self.suspicious_processes:
            vt_result = proc.get('virustotal_result', {})
            if vt_result.get('malicious', 0) > 0:
                recommendations.append({
                    'priority': 'CRITICAL',
                    'category': 'Process',
                    'action': f"Terminate process: {proc.get('name')} (PID: {proc.get('pid')})",
                    'reason': f"Malware detected by {vt_result.get('malicious')} antivirus engines",
                    'commands': [f"taskkill /PID {proc.get('pid')} /F"],
                    'type': 'process_termination'
                })
            elif proc.get('suspicion_score', 0) >= 40:
                recommendations.append({
                    'priority': 'HIGH',
                    'category': 'Process',
                    'action': f"Investigate process: {proc.get('name')} (PID: {proc.get('pid')})",
                    'reason': f"High suspicion score: {proc.get('suspicion_score')}",
                    'commands': [f"Examine file: {proc.get('executable_path', 'N/A')}"],
                    'type': 'process_investigation'
                })
        
        # Service-based recommendations
        service_recommendations = self.service_analysis.get('recommendations', [])
        for rec in service_recommendations:
            rec['category'] = 'Service'
            rec['type'] = 'service_action'
            recommendations.append(rec)
        
        # Sort by priority
        priority_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        recommendations.sort(key=lambda x: priority_order.get(x['priority'], 4))
        
        return recommendations

    def create_enhanced_pdf_report(self, output_path):
        """Generate enhanced PDF report with service analysis"""
        if not REPORTLAB_AVAILABLE:
            self.log_message("❌ PDF generation disabled - ReportLab not available")
            return False
        
        self.log_message("📄 Generating enhanced PDF report with service analysis...")
        
        try:
            doc = SimpleDocTemplate(output_path, pagesize=A4)
            styles = getSampleStyleSheet()
            story = []
            
            # Custom styles
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Title'],
                fontSize=24,
                spaceAfter=30,
                textColor=colors.darkblue
            )
            
            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading1'],
                fontSize=16,
                spaceAfter=20,
                textColor=colors.darkred
            )
            
            # Title page
            story.append(Paragraph("Enhanced SOC Security Analysis Report", title_style))
            story.append(Paragraph("with Service Analysis", ParagraphStyle('Subtitle', parent=styles['Normal'], fontSize=14, textColor=colors.grey, alignment=1)))
            story.append(Spacer(1, 12))
            
            # Executive summary
            story.append(Paragraph("Executive Summary", heading_style))
            
            summary = self.incident_report.get('summary', {})
            service_stats = summary.get('service_analysis', {})
            
            exec_data = [
                ['Metric', 'Value'],
                ['Scan Timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
                ['Hostname', summary.get('system_info', {}).get('hostname', 'Unknown')],
                ['Total Processes Scanned', str(summary.get('total_processes_scanned', 0))],
                ['Suspicious Processes', str(summary.get('suspicious_processes_found', 0))],
                ['Persistence Threats', str(summary.get('persistence_threats_found', 0))],
                ['Total Services Analyzed', str(service_stats.get('total_services', 0))],
                ['Critical Service Risks', str(service_stats.get('critical_service_risks', 0))],
                ['High Service Risks', str(service_stats.get('high_service_risks', 0))],
                ['Service Recommendations', str(service_stats.get('service_recommendations', 0))],
                ['Overall Risk Level', summary.get('risk_level', 'UNKNOWN')]
            ]
            
            exec_table = Table(exec_data, colWidths=[3*inch, 2*inch])
            exec_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(exec_table)
            story.append(Spacer(1, 20))
            
            # Service Risks Section
            if self.service_analysis.get('critical_risks') or self.service_analysis.get('high_risks'):
                story.append(Paragraph("Critical Service Security Risks", heading_style))
                
                service_data = [['Service Name', 'Display Name', 'Risk Level', 'Category', 'Reason']]
                
                # Add critical risks
                for analysis in self.service_analysis.get('critical_risks', [])[:5]:
                    service = analysis['service']
                    service_data.append([
                        service.get('name', 'Unknown')[:15],
                        service.get('display_name', 'Unknown')[:20],
                        analysis['risk_level'],
                        analysis['category'][:15],
                        analysis['reasons'][0][:30] if analysis['reasons'] else 'Unknown'
                    ])
                
                # Add high risks
                for analysis in self.service_analysis.get('high_risks', [])[:5]:
                    service = analysis['service']
                    service_data.append([
                        service.get('name', 'Unknown')[:15],
                        service.get('display_name', 'Unknown')[:20],
                        analysis['risk_level'],
                        analysis['category'][:15],
                        analysis['reasons'][0][:30] if analysis['reasons'] else 'Unknown'
                    ])
                
                service_table = Table(service_data, colWidths=[1.2*inch, 1.5*inch, 0.8*inch, 1*inch, 2*inch])
                service_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.darkred),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                
                story.append(service_table)
                story.append(Spacer(1, 20))
            
            # Suspicious processes table
            if self.suspicious_processes:
                story.append(Paragraph("Suspicious Processes", heading_style))
                
                proc_data = [['PID', 'Name', 'User', 'Suspicion Score', 'Flags']]
                for proc in self.suspicious_processes[:10]:  # Limit to top 10
                    flags_str = ', '.join(proc.get('flags', [])[:2])  # Limit flags
                    proc_data.append([
                        str(proc.get('pid', 'N/A')),
                        proc.get('name', 'Unknown')[:20],  # Truncate long names
                        proc.get('user', 'Unknown')[:15],
                        str(proc.get('suspicion_score', 0)),
                        flags_str[:30]  # Truncate flags
                    ])
                
                proc_table = Table(proc_data, colWidths=[0.8*inch, 1.5*inch, 1.2*inch, 1*inch, 2*inch])
                proc_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.darkred),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                
                story.append(proc_table)
                story.append(Spacer(1, 20))
            
            # Service Recommendations
            service_recommendations = [r for r in self.incident_report.get('recommendations', []) if r.get('category') == 'Service']
            if service_recommendations:
                story.append(Paragraph("Service Security Recommendations", heading_style))
                
                rec_data = [['Priority', 'Service Action', 'Reason']]
                for rec in service_recommendations[:8]:  # Limit to top 8
                    rec_data.append([
                        rec.get('priority', 'Unknown'),
                        rec.get('action', 'No action')[:35],
                        rec.get('reason', 'No reason')[:35]
                    ])
                
                rec_table = Table(rec_data, colWidths=[0.8*inch, 2.7*inch, 2.7*inch])
                rec_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.darkorange),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.lightyellow),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                
                story.append(rec_table)
                story.append(Spacer(1, 20))
            
            # Commands to Execute Section
            story.append(PageBreak())
            story.append(Paragraph("Service Commands to Execute", heading_style))
            
            cmd_text = "Execute these commands in an elevated command prompt:\n\n"
            
            critical_service_recs = [r for r in service_recommendations if r.get('priority') == 'CRITICAL']
            for rec in critical_service_recs[:5]:
                cmd_text += f"# {rec.get('action', 'Unknown Action')}\n"
                for cmd in rec.get('commands', []):
                    cmd_text += f"{cmd}\n"
                cmd_text += "\n"
            
            story.append(Paragraph(cmd_text.replace('\n', '<br/>'), styles['Code']))
            
            # Footer
            story.append(PageBreak())
            story.append(Paragraph("Report Generated by SOC Incident responder v4.1", styles['Normal']))
            story.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
            story.append(Paragraph("Includes comprehensive Windows service security analysis", styles['Normal']))
            
            doc.build(story)
            self.log_message(f"✅ Enhanced PDF report generated: {output_path}")
            return True
            
        except Exception as e:
            self.log_message(f"❌ PDF generation failed: {str(e)}")
            return False

    def save_reports(self):
        """Save all reports including service analysis"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        hostname = socket.gethostname()
        
        # Create output directory for this scan
        scan_dir = os.path.join(self.config["output_directory"], f"scan_{hostname}_{timestamp}")
        os.makedirs(scan_dir, exist_ok=True)
        
        file_paths = []
        
        # Save JSON data
        json_path = os.path.join(scan_dir, f"system_data_enhanced_{timestamp}.json")
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(self.system_data, f, indent=2, ensure_ascii=False)
        file_paths.append(json_path)
        
        # Save incident report
        incident_path = os.path.join(scan_dir, f"incident_report_enhanced_{timestamp}.json")
        with open(incident_path, 'w', encoding='utf-8') as f:
            json.dump(self.incident_report, f, indent=2, ensure_ascii=False)
        file_paths.append(incident_path)
        
        # Save service recommendations as separate file
        if self.service_analysis:
            service_path = os.path.join(scan_dir, f"service_recommendations_{timestamp}.json")
            with open(service_path, 'w', encoding='utf-8') as f:
                json.dump(self.service_analysis, f, indent=2, ensure_ascii=False)
            file_paths.append(service_path)
        
        # Generate enhanced PDF report if available
        if self.config.get("generate_pdf", False):
            pdf_path = os.path.join(scan_dir, f"security_report_enhanced_{timestamp}.pdf")
            if self.create_enhanced_pdf_report(pdf_path):
                file_paths.append(pdf_path)

        # Generate service commands batch file
        self._create_service_commands_batch(scan_dir, timestamp)
        
        # Encrypt files if enabled
        if self.config.get("encrypt_reports"):
            encrypted_paths = []
            for file_path in file_paths:
                encrypted_path = self.encrypt_file(file_path)
                encrypted_paths.append(encrypted_path)
            file_paths = encrypted_paths
        
        # Compress files if enabled
        if self.config.get("compress_reports"):
            zip_path = os.path.join(scan_dir, f"soc_report_enhanced_{timestamp}.zip")
            if self.compress_files(file_paths, zip_path):
                # Clean up individual files after compression
                for file_path in file_paths:
                    if os.path.exists(file_path):
                        os.remove(file_path)
                
                file_paths = [zip_path]
        
        self.log_message(f"📁 Enhanced reports saved to: {scan_dir}")
        return file_paths

    def _create_service_commands_batch(self, scan_dir, timestamp):
        """Create batch file with service commands"""
        batch_path = os.path.join(scan_dir, f"service_commands_{timestamp}.bat")
        
        try:
            with open(batch_path, 'w') as f:
                f.write("@echo off\n")
                f.write("REM SOC Incident responder - Service Commands\n")
                f.write(f"REM Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("REM Run as Administrator\n\n")
                
                f.write("echo ========================================\n")
                f.write("echo  SOC Security Analyzer Service Actions\n") 
                f.write("echo ========================================\n\n")
                
                service_recommendations = [r for r in self.incident_report.get('recommendations', []) if r.get('category') == 'Service']
                
                critical_recs = [r for r in service_recommendations if r.get('priority') == 'CRITICAL']
                if critical_recs:
                    f.write("REM CRITICAL SERVICE ACTIONS\n")
                    for rec in critical_recs:
                        f.write(f"REM {rec.get('action', 'Unknown')}\n")
                        for cmd in rec.get('commands', []):
                            f.write(f"{cmd}\n")
                        f.write("\n")
                
                high_recs = [r for r in service_recommendations if r.get('priority') == 'HIGH']
                if high_recs:
                    f.write("REM HIGH PRIORITY SERVICE ACTIONS\n")
                    for rec in high_recs:
                        f.write(f"REM {rec.get('action', 'Unknown')}\n")
                        for cmd in rec.get('commands', []):
                            f.write(f"{cmd}\n")
                        f.write("\n")
                
                f.write("echo Service security actions completed!\n")
                f.write("pause\n")
            
            self.log_message(f"✅ Service commands batch file created: {batch_path}")
            
        except Exception as e:
            self.log_message(f"❌ Failed to create batch file: {e}")

    # [Include encryption and other utility methods from the original class]
    def encrypt_file(self, file_path, password="SOC2024!"):
        """Encrypt file using AES encryption"""
        if not CRYPTO_AVAILABLE:
            self.log_message("❌ Encryption disabled - cryptography not available")
            return file_path
        
        self.log_message("🔐 Encrypting report...")

        try:
            # Generate key from password
            password_bytes = password.encode()
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
            
            # Encrypt file
            fernet = Fernet(key)

            with open(file_path, 'rb') as file:
                file_data = file.read()
            
            encrypted_data = fernet.encrypt(file_data)
            
            # Save encrypted file
            encrypted_path = file_path + '.encrypted'
            with open(encrypted_path, 'wb') as file:
                file.write(salt + encrypted_data)  # Prepend salt
            
            # Remove original file
            os.remove(file_path)
            
            self.log_message(f"🔐 File encrypted: {encrypted_path}")
            return encrypted_path
            
        except Exception as e:
            self.log_message(f"❌ Encryption failed: {str(e)}")
            return file_path

    def compress_files(self, file_paths, output_path):
        """Compress multiple files into a ZIP archive"""
        self.log_message("📦 Compressing reports...")
        
        try:
            with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for file_path in file_paths:
                    if os.path.exists(file_path):
                        zipf.write(file_path, os.path.basename(file_path))
            
            self.log_message(f"📦 Files compressed: {output_path}")
            return output_path
            
        except Exception as e:
            self.log_message(f"❌ Compression failed: {str(e)}")
            return None

    def create_gui(self):
        """Create enhanced GUI interface with service analysis options"""
        self.root = tk.Tk()
        self.root.title(f"SOC Incident responder v{self.version}")
        self.root.geometry("900x700")
        self.root.configure(bg='#f0f0f0')

        style = ttk.Style()
        style.theme_use("default")


        #progress bar color
        style.configure(
            "Blue.Horizontal.TProgressbar",
            troughcolor="#DADADA",   # background track color
            background="#1E88E5",    # BLUE progress color
            thickness=20
        )

        
        # Header
        header_frame = tk.Frame(self.root, bg="#3760c7", height=100)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)

        title_label = tk.Label(
            header_frame,
            text="SOC Incident responder",
            font=('Times New Roman', 20, 'bold'),
            # fg='white',
            # bg='#2c3e50'
        )
        title_label.pack(pady=15)
        
        subtitle_label = tk.Label(
            header_frame,
            text="with Windows Service Analysis",
            font=('Times New Roman', 12),
            # fg='#bdc3c7',
            # bg='#2c3e50'
        )
        subtitle_label.pack()
        
        # Main content frame
        main_frame = tk.Frame(self.root, bg='#f0f0f0')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Status frame
        status_frame = tk.LabelFrame(main_frame, text="System Status", font=('Arial', 12, 'bold'))
        status_frame.pack(fill=tk.X, pady=(0, 10))
        
        status_text = f"ReportLab: {'✅ Available' if REPORTLAB_AVAILABLE else '❌ Not Available'} | "
        status_text += f"Cryptography: {'✅ Available' if CRYPTO_AVAILABLE else '❌ Not Available'} | "
        status_text += f"Windows APIs: {'✅ Available' if WIN32_AVAILABLE else '❌ Not Available'}"
        
        tk.Label(status_frame, text=status_text, font=('Times New Roman', 9)).pack(pady=5)
        
        # Configuration frame
        config_frame = tk.LabelFrame(main_frame, text="Analysis Configuration", font=('Arial', 12, 'bold'))
        config_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Options frame
        options_frame = tk.Frame(config_frame)
        options_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.encrypt_var = tk.BooleanVar(value=self.config.get("encrypt_reports", CRYPTO_AVAILABLE))
        self.compress_var = tk.BooleanVar(value=self.config.get("compress_reports", True))
        self.pdf_var = tk.BooleanVar(value=self.config.get("generate_pdf", REPORTLAB_AVAILABLE))
        self.service_var = tk.BooleanVar(value=self.config.get("analyze_services", True))
        
        tk.Checkbutton(options_frame, text="Encrypt Reports", variable=self.encrypt_var, state='normal' if CRYPTO_AVAILABLE else 'disabled').pack(side=tk.LEFT)
        tk.Checkbutton(options_frame, text="Compress Reports", variable=self.compress_var).pack(side=tk.LEFT, padx=(20, 0))
        tk.Checkbutton(options_frame, text="Generate PDF", variable=self.pdf_var, state='normal' if REPORTLAB_AVAILABLE else 'disabled').pack(side=tk.LEFT, padx=(20, 0))
        tk.Checkbutton(options_frame, text="Analyze Services", variable=self.service_var, state='normal' if platform.system().lower() == 'windows' else 'disabled').pack(side=tk.LEFT, padx=(20, 0))
        
        # Control frame
        control_frame = tk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Start analysis button
        self.start_button = tk.Button(
            control_frame,
            text="🚀 Start Enhanced Security Analysis",
            font=('Times New Roman', 14, 'bold'),
            bg="#4486dd",
            fg='white',
            command=self.start_analysis_gui,
            height=2
        )
        self.start_button.pack(side=tk.LEFT, padx=(0, 10))
        
        # Open reports button
        self.reports_button = tk.Button(
            control_frame,
            text="📁 Open Reports Folder",
            font=('Times New Roman', 12),
            bg='#3498db',
            fg='white',
            command=self.open_reports_folder
        )
        self.reports_button.pack(side=tk.LEFT)
        
        # Progress frame
        progress_frame = tk.LabelFrame(main_frame, text="Analysis Progress", font=('Arial', 12, 'bold'))
        progress_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            progress_frame,
            variable=self.progress_var,
            maximum=100
        )
        self.progress_bar.pack(fill=tk.X, padx=10, pady=5)
        
        self.status_var = tk.StringVar(value="Ready to start enhanced analysis...")
        self.status_label = tk.Label(
            progress_frame,
            textvariable=self.status_var,
            font=('Arial', 10)
        )
        self.status_label.pack(pady=5)
        
        # Log frame
        log_frame = tk.LabelFrame(main_frame, text="Analysis Log", font=('Arial', 12, 'bold'))
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        # Log text with scrollbar
        log_scroll_frame = tk.Frame(log_frame)
        log_scroll_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.log_text = tk.Text(
            log_scroll_frame,
            wrap=tk.WORD,
            font=('Arial', 10),
            bg='#1e1e1e',
            fg='#ffffff'
        )

        scrollbar = tk.Scrollbar(log_scroll_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Status bar
        status_bar = tk.Frame(self.root, bg='#34495e', height=25)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        status_bar.pack_propagate(False)
        
        status_text = tk.Label(
            status_bar,
            text=f"SOC Incident responder v{self.version} | Ready",
            bg='#34495e',
            fg='white',
            font=('Times New Roman', 9)
        )
        status_text.pack(side=tk.LEFT, padx=10, pady=3)

    def start_analysis_gui(self):
        """Start enhanced analysis from GUI"""
        # Update configuration from GUI
        self.config["encrypt_reports"] = self.encrypt_var.get() and CRYPTO_AVAILABLE
        self.config["compress_reports"] = self.compress_var.get()
        self.config["generate_pdf"] = self.pdf_var.get() and REPORTLAB_AVAILABLE
        self.config["analyze_services"] = self.service_var.get()
        
        # Disable start button
        self.start_button.configure(state='disabled')
        
        # Clear log
        self.log_text.delete(1.0, tk.END)
        
        # Run analysis in separate thread
        def analysis_thread():
            try:
                self.run_full_analysis()
                file_paths = self.save_reports()
                
                self.update_progress(100, "Enhanced analysis complete!")
                
                # Show completion dialog with service info
                service_stats = self.incident_report.get('summary', {}).get('service_analysis', {})
                completion_msg = f"Enhanced security analysis completed successfully!\n\n"
                completion_msg += f"Risk Level: {self.incident_report.get('summary', {}).get('risk_level', 'UNKNOWN')}\n"
                completion_msg += f"Suspicious Processes: {len(self.suspicious_processes)}\n"
                completion_msg += f"Critical Service Risks: {service_stats.get('critical_service_risks', 0)}\n"
                completion_msg += f"Service Recommendations: {service_stats.get('service_recommendations', 0)}"
                
                self.root.after(100, lambda: messagebox.showinfo("Enhanced Analysis Complete", completion_msg))
                
            except Exception as e:
                self.log_message(f"❌ Analysis failed: {str(e)}")
                self.root.after(100, lambda: messagebox.showerror(
                    "Analysis Failed",
                    f"An error occurred during analysis:\n\n{str(e)}"
                ))
            finally:
                # Re-enable start button
                self.root.after(100, lambda: self.start_button.configure(state='normal'))
        
        threading.Thread(target=analysis_thread, daemon=True).start()

    def open_reports_folder(self):
        """Open reports folder in file explorer"""
        if os.path.exists(self.config["output_directory"]):
            if platform.system() == "Windows":
                os.startfile(self.config["output_directory"])
            elif platform.system() == "Darwin":  # macOS
                subprocess.run(["open", self.config["output_directory"]])
            else:  # Linux
                subprocess.run(["xdg-open", self.config["output_directory"]])

    def run_cli_mode(self, args):
        """Run in enhanced CLI mode with service analysis"""
        print(f"🔒 SOC Incident responder v{self.version} - CLI Mode")
        print("=" * 70)
        
        # Update configuration from CLI args
        if hasattr(args, 'no_encrypt') and args.no_encrypt:
            self.config["encrypt_reports"] = False
        
        if hasattr(args, 'no_compress') and args.no_compress:
            self.config["compress_reports"] = False
        
        if hasattr(args, 'no_services') and args.no_services:
            self.config["analyze_services"] = False
        
        # Show available features
        print(f"📊 Available Features:")
        print(f"   • VirusTotal Integration: ✅ Enabled")
        print(f"   • PDF Reports: {'✅ Available' if REPORTLAB_AVAILABLE else '❌ Disabled (install reportlab)'}")
        print(f"   • File Encryption: {'✅ Available' if CRYPTO_AVAILABLE else '❌ Disabled (install cryptography)'}")
        print(f"   • Windows APIs: {'✅ Available' if WIN32_AVAILABLE else '❌ Disabled (install pywin32)'}")
        print(f"   • Service Analysis: {'✅ Available' if platform.system().lower() == 'windows' else '❌ Windows Only'}")
        print()
        
        # Run analysis
        self.run_full_analysis()
        file_paths = self.save_reports()
        
        print(f"\n✅ Enhanced analysis completed successfully!")
        print(f"📊 Risk Level: {self.incident_report.get('summary', {}).get('risk_level', 'UNKNOWN')}")
        print(f"🚩 Suspicious Processes: {len(self.suspicious_processes)}")
        print(f"🔒 Persistence Threats: {len(self.persistence_threats)}")
        
        # Service statistics
        service_stats = self.incident_report.get('summary', {}).get('service_analysis', {})
        if service_stats:
            print(f"🔧 Service Analysis:")
            print(f"   • Total Services: {service_stats.get('total_services', 0)}")
            print(f"   • Critical Risks: {service_stats.get('critical_service_risks', 0)}")
            print(f"   • High Risks: {service_stats.get('high_service_risks', 0)}")
            print(f"   • Recommendations: {service_stats.get('service_recommendations', 0)}")
        
        print(f"📁 Reports saved to: {self.config['output_directory']}")
        
        # Show top service recommendations
        service_recommendations = [r for r in self.incident_report.get('recommendations', []) if r.get('category') == 'Service']
        critical_service_recs = [r for r in service_recommendations if r.get('priority') == 'CRITICAL']
        
        if critical_service_recs:
            print(f"\n🚨 CRITICAL SERVICE ACTIONS REQUIRED:")
            for i, rec in enumerate(critical_service_recs[:3], 1):
                print(f"   {i}. {rec.get('action', 'Unknown action')}")
                print(f"      Reason: {rec.get('reason', 'No reason')}")
                if rec.get('commands'):
                    print(f"      Command: {rec.get('commands')[0]}")
        
        return True

def main():
    """Main application entry point for enhanced analyzer"""
    parser = argparse.ArgumentParser(description="Enhanced SOC-Ready Security Analysis Tool with Service Analysis")
    parser.add_argument("--cli", action="store_true", help="Run in CLI mode (no GUI)")
    parser.add_argument("--no-encrypt", action="store_true", help="Don't encrypt reports")
    parser.add_argument("--no-compress", action="store_true", help="Don't compress reports")
    parser.add_argument("--no-services", action="store_true", help="Skip Windows service analysis")
    parser.add_argument("--output-dir", type=str, help="Output directory for reports")
    
    args = parser.parse_args()
    
    # Check Python version
    if sys.version_info < (3, 6):
        print("❌ Python 3.6+ required")
        sys.exit(1)
    
    # Create enhanced analyzer instance
    analyzer = SOCSecurityAnalyzer()
    
    # Set output directory if specified
    if args.output_dir:
        analyzer.config["output_directory"] = args.output_dir
        os.makedirs(analyzer.config["output_directory"], exist_ok=True)
    
    if args.cli or len(sys.argv) > 1:
        # CLI mode
        try:
            analyzer.run_cli_mode(args)
        except KeyboardInterrupt:
            print("\n⚠️  Analysis interrupted by user.")
        except Exception as e:
            print(f"\n❌ Analysis failed: {str(e)}")
            import traceback
            traceback.print_exc()
            sys.exit(1)
    else:
        # GUI mode
        try:
            analyzer.create_gui()
            analyzer.log_message("🚀 SOC Incident responder started in GUI mode")
            analyzer.log_message("📋 Configure settings and click 'Start Enhanced Security Analysis' to begin")
            analyzer.log_message("🔧 Service analysis will identify which services to stop and why")
            analyzer.root.mainloop()
        except Exception as e:
            print(f"GUI Error: {str(e)}")
            # Fallback to CLI mode
            print("Falling back to CLI mode...")
            analyzer.run_cli_mode(args)

if __name__ == "__main__":
    main()