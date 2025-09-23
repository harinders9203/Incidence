"""
System Information Gathering Script - Phase 3: Intelligence & Detection
Updated with VirusTotal API v3 integration and enhanced threat detection.
"""

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
from datetime import datetime, timedelta
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# Windows-specific imports
try:
    import win32evtlog
    import win32evtlogutil
    import winreg
    import pywintypes
    import win32api
    import win32security
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False
    print("Warning: pywin32 not available. Install with: pip install pywin32")

class ThreatDetector:
    """Main class for threat detection and analysis with VirusTotal API v3"""
    
    def __init__(self, virustotal_api_key="0af097982ab18dd43e82486df7d2ed7ad483757fcecbb9ac05318a09b6449b4e"):
        self.vt_api_key = virustotal_api_key
        self.vt_base_url = "https://www.virustotal.com/api/v3"
        self.suspicious_findings = []
        self.incident_report = {
            "timestamp": datetime.now().isoformat(),
            "summary": {},
            "critical_findings": [],
            "warnings": [],
            "recommendations": []
        }
        
        # Known suspicious paths
        self.suspicious_paths = [
            "temp", "tmp", "appdata\\local\\temp", "programdata",
            "users\\public", "windows\\temp", "recycle.bin",
            "system volume information", "$recycle.bin", "downloads"
        ]
        
        # Legitimate system directories
        self.system_paths = [
            "windows\\system32", "windows\\syswow64", "program files",
            "program files (x86)", "windows\\microsoft.net", "windows\\winsxs"
        ]

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
                    "threat_names": threat_names[:5],  # Top 5 threat detections
                    "reputation": attributes.get('reputation', 0),
                    "meaningful_name": attributes.get('meaningful_name', 'Unknown'),
                    "magic": attributes.get('magic', 'Unknown'),
                    "first_seen": datetime.fromtimestamp(attributes.get('first_submission_date', 0)).strftime('%Y-%m-%d %H:%M:%S') if attributes.get('first_submission_date') else 'Unknown'
                }
            elif response.status_code == 404:
                return {"found": False, "message": "File not found in VirusTotal database"}
            elif response.status_code == 429:
                return {"error": "Rate limit exceeded. Please wait before making more requests."}
            else:
                return {"error": f"VirusTotal API error: {response.status_code} - {response.text[:200]}"}
                
        except requests.exceptions.Timeout:
            return {"error": "VirusTotal API request timed out"}
        except requests.exceptions.ConnectionError:
            return {"error": "Failed to connect to VirusTotal API"}
        except Exception as e:
            return {"error": f"VirusTotal check failed: {str(e)}"}

    def check_ip_reputation(self, ip_address):
        """Check IP reputation using VirusTotal API v3"""
        if not self.vt_api_key:
            return {"error": "No VirusTotal API key provided"}
            
        try:
            url = f"{self.vt_base_url}/ip_addresses/{ip_address}"
            headers = {
                "x-apikey": self.vt_api_key,
                "Accept": "application/json"
            }
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                data = result.get('data', {})
                attributes = data.get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})
                
                return {
                    "found": True,
                    "malicious": stats.get('malicious', 0),
                    "suspicious": stats.get('suspicious', 0),
                    "harmless": stats.get('harmless', 0),
                    "undetected": stats.get('undetected', 0),
                    "country": attributes.get('country', 'Unknown'),
                    "asn": attributes.get('asn', 'Unknown'),
                    "as_owner": attributes.get('as_owner', 'Unknown'),
                    "reputation": attributes.get('reputation', 0),
                    "network": attributes.get('network', 'Unknown')
                }
            elif response.status_code == 404:
                return {"found": False, "message": "IP not found in VirusTotal database"}
            else:
                return {"error": f"IP check error: {response.status_code}"}
                
        except Exception as e:
            return {"error": f"IP reputation check failed: {str(e)}"}

    def check_url_reputation(self, url):
        """Check URL reputation using VirusTotal API v3"""
        if not self.vt_api_key:
            return {"error": "No VirusTotal API key provided"}
            
        try:
            # First, submit URL for analysis
            submit_url = f"{self.vt_base_url}/urls"
            headers = {
                "x-apikey": self.vt_api_key,
                "Accept": "application/json"
            }
            data = {"url": url}
            
            response = requests.post(submit_url, headers=headers, data=data, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                url_id = result.get('data', {}).get('id')
                
                # Wait a moment then check results
                time.sleep(2)
                
                check_url = f"{self.vt_base_url}/analyses/{url_id}"
                check_response = requests.get(check_url, headers=headers, timeout=10)
                
                if check_response.status_code == 200:
                    check_result = check_response.json()
                    attributes = check_result.get('data', {}).get('attributes', {})
                    stats = attributes.get('stats', {})
                    
                    return {
                        "found": True,
                        "malicious": stats.get('malicious', 0),
                        "suspicious": stats.get('suspicious', 0),
                        "harmless": stats.get('harmless', 0),
                        "undetected": stats.get('undetected', 0),
                        "status": attributes.get('status', 'Unknown')
                    }
                    
            return {"error": "Unable to analyze URL"}
            
        except Exception as e:
            return {"error": f"URL reputation check failed: {str(e)}"}

    def is_process_signed(self, executable_path):
        """Check if executable is digitally signed (Windows only)"""
        if not WIN32_AVAILABLE or platform.system().lower() != 'windows':
            return None
        
        try:
            cmd = f'powershell -command "Get-AuthenticodeSignature \'{executable_path}\' | Select-Object Status"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                output = result.stdout.strip()
                return "Valid" in output
            return False
            
        except Exception as e:
            return None

    def analyze_process_path(self, executable_path):
        """Analyze if process is running from suspicious location"""
        if not executable_path or executable_path == "N/A":
            return "unknown_path"
        
        path_lower = executable_path.lower()
        
        # Check for suspicious paths
        for sus_path in self.suspicious_paths:
            if sus_path in path_lower:
                return "suspicious_path"
        
        # Check for system paths (legitimate)
        for sys_path in self.system_paths:
            if sys_path in path_lower:
                return "system_path"
        
        return "user_path"

    def detect_process_anomalies(self, processes):
        """Detect suspicious process behavior with enhanced VirusTotal integration"""
        suspicious_processes = []
        
        print("🔍 Analyzing processes for anomalies...")
        print(f"📊 Total processes to analyze: {len([p for p in processes if isinstance(p, dict) and 'error' not in p])}")
        
        # Rate limiting for VirusTotal API (4 requests per minute for free tier)
        vt_request_count = 0
        vt_last_request_time = time.time()
        
        for i, proc in enumerate(processes):
            if isinstance(proc, dict) and "error" not in proc:
                suspicion_score = 0
                flags = []
                
                print(f"Analyzing process {i+1}: {proc.get('name', 'Unknown')} (PID: {proc.get('pid', 'Unknown')})")
                
                # Check executable path
                exe_path = proc.get('executable_path', '')
                path_analysis = self.analyze_process_path(exe_path)
                
                if path_analysis == "suspicious_path":
                    suspicion_score += 30
                    flags.append("running_from_suspicious_location")
                
                # Check if process is signed (Windows)
                is_signed = self.is_process_signed(exe_path)
                if is_signed is False:
                    suspicion_score += 20
                    flags.append("unsigned_executable")
                elif is_signed is None:
                    suspicion_score += 5
                    flags.append("signature_check_failed")
                
                # Check for processes with no executable path
                if not exe_path or exe_path == "N/A":
                    suspicion_score += 15
                    flags.append("no_executable_path")
                
                # Check for high resource usage
                cpu_percent = proc.get('cpu_percent', 0)
                memory_percent = proc.get('memory_percent', 0)
                
                if cpu_percent > 80:
                    suspicion_score += 10
                    flags.append("high_cpu_usage")
                
                if memory_percent > 50:
                    suspicion_score += 10
                    flags.append("high_memory_usage")
                
                # Calculate file hash and check VirusTotal
                file_hash = None
                vt_result = None
                
                if exe_path and os.path.exists(exe_path):
                    print(f"  📝 Calculating hash for: {os.path.basename(exe_path)}")
                    file_hash = self.calculate_file_hash(exe_path)
                    
                    if file_hash:
                        proc['file_hash'] = file_hash
                        
                        # Rate limiting for VirusTotal API
                        current_time = time.time()
                        if current_time - vt_last_request_time >= 15:  # 15 seconds between requests
                            vt_request_count = 0
                            vt_last_request_time = current_time
                        
                        if vt_request_count < 4:  # Max 4 requests per minute
                            print(f"  🔍 Checking VirusTotal for hash: {file_hash[:16]}...")
                            vt_result = self.check_virustotal_v3(file_hash)
                            proc['virustotal_result'] = vt_result
                            vt_request_count += 1
                            vt_last_request_time = time.time()
                            
                            if vt_result.get('found'):
                                malicious_count = vt_result.get('malicious', 0)
                                suspicious_count = vt_result.get('suspicious', 0)
                                total_detections = malicious_count + suspicious_count
                                
                                if malicious_count > 0:
                                    suspicion_score += min(50, malicious_count * 5)  # Cap at 50 points
                                    flags.append(f"virustotal_malicious:{malicious_count}")
                                    
                                if suspicious_count > 0:
                                    suspicion_score += min(20, suspicious_count * 2)  # Cap at 20 points
                                    flags.append(f"virustotal_suspicious:{suspicious_count}")
                                
                                print(f"    ✅ VirusTotal result: {total_detections} detections ({malicious_count} malicious, {suspicious_count} suspicious)")
                            else:
                                print(f"    ℹ️  File not found in VirusTotal database")
                        else:
                            print(f"    ⏳ Rate limit reached, skipping VirusTotal check")
                            proc['virustotal_result'] = {"skipped": "Rate limit reached"}
                
                # Flag as suspicious if score is high enough
                if suspicion_score >= 25:
                    proc['suspicion_score'] = suspicion_score
                    proc['flags'] = flags
                    proc['path_analysis'] = path_analysis
                    suspicious_processes.append(proc)
                    print(f"    🚨 SUSPICIOUS: Score {suspicion_score}, Flags: {', '.join(flags)}")
                else:
                    print(f"    ✅ Clean: Score {suspicion_score}")
        
        print(f"\n🎯 Found {len(suspicious_processes)} suspicious processes out of {len(processes)} analyzed")
        return suspicious_processes

    def get_scheduled_tasks_windows(self):
        """Get Windows scheduled tasks for persistence analysis"""
        if platform.system().lower() != 'windows':
            return []
        
        scheduled_tasks = []
        
        try:
            print("📅 Collecting Windows scheduled tasks...")
            cmd = 'schtasks /query /fo csv /v'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                if len(lines) > 1:
                    headers = [h.strip('"') for h in lines[0].split(',')]
                    
                    for line in lines[1:]:
                        if line.strip():
                            try:
                                values = [v.strip('"') for v in line.split(',')]
                                if len(values) >= len(headers):
                                    task = dict(zip(headers, values))
                                    
                                    # Enhanced suspicious task detection
                                    task_name = task.get('TaskName', '').lower()
                                    task_command = task.get('Task To Run', '').lower()
                                    task_author = task.get('Author', '').lower()
                                    
                                    suspicious_indicators = [
                                        'temp', 'tmp', 'appdata', 'programdata', 'downloads',
                                        'powershell -enc', 'powershell -e', 'powershell.exe -w hidden',
                                        'cmd.exe /c', 'cmd /c', 'wscript', 'cscript',
                                        'regsvr32', 'rundll32', 'certutil', 'bitsadmin'
                                    ]
                                    
                                    suspicious_names = [
                                        'update', 'check', 'adobe', 'java', 'windows',
                                        'microsoft', 'system', 'security'
                                    ]
                                    
                                    is_suspicious = any(indicator in task_command or indicator in task_name 
                                                      for indicator in suspicious_indicators)
                                    
                                    # Additional check for generic names (possible impersonation)
                                    has_generic_name = any(name in task_name for name in suspicious_names)
                                    if has_generic_name and ('temp' in task_command or 'appdata' in task_command):
                                        is_suspicious = True
                                    
                                    task['is_suspicious'] = is_suspicious
                                    task['risk_level'] = 'high' if is_suspicious else 'low'
                                    scheduled_tasks.append(task)
                                    
                            except Exception as parse_error:
                                continue
            
            print(f"📊 Found {len(scheduled_tasks)} scheduled tasks ({len([t for t in scheduled_tasks if t.get('is_suspicious')])} suspicious)")
            return scheduled_tasks
            
        except Exception as e:
            return [{"error": f"Failed to get scheduled tasks: {str(e)}"}]

    def analyze_persistence_mechanisms(self, startup_programs, scheduled_tasks):
        """Analyze persistence mechanisms for threats"""
        persistence_threats = []
        
        print("🔒 Analyzing persistence mechanisms...")
        
        # Analyze startup programs
        if isinstance(startup_programs, dict):
            for location, programs in startup_programs.items():
                if isinstance(programs, list):
                    for program in programs:
                        if isinstance(program, dict) and "error" not in program:
                            command = program.get('command', '').lower()
                            name = program.get('name', '').lower()
                            
                            # Enhanced suspicious pattern detection
                            suspicious_patterns = [
                                'temp\\', 'tmp\\', 'appdata\\local\\temp\\',
                                'powershell -enc', 'powershell -e', '-windowstyle hidden',
                                'cmd /c', 'wscript', 'cscript', '%temp%',
                                'regsvr32', 'rundll32', 'certutil', 'bitsadmin',
                                'programdata\\', 'users\\public\\', '$recycle.bin'
                            ]
                            
                            suspicion_score = 0
                            threat_flags = []
                            
                            for pattern in suspicious_patterns:
                                if pattern in command:
                                    suspicion_score += 15
                                    threat_flags.append(f"suspicious_pattern:{pattern}")
                            
                            # Check for obfuscation
                            if any(char in command for char in ['&', '|', '^', '%']):
                                suspicion_score += 10
                                threat_flags.append("command_obfuscation")
                            
                            # Check for unsigned executables in startup
                            if command and os.path.exists(command.split()[0]):
                                is_signed = self.is_process_signed(command.split()[0])
                                if is_signed is False:
                                    suspicion_score += 15
                                    threat_flags.append("unsigned_startup_executable")
                            
                            is_suspicious = suspicion_score >= 15
                            
                            if is_suspicious:
                                threat = {
                                    "type": "suspicious_startup_program",
                                    "location": location,
                                    "name": program.get('name', 'Unknown'),
                                    "command": program.get('command', ''),
                                    "registry_path": program.get('registry_path', ''),
                                    "suspicion_score": suspicion_score,
                                    "flags": threat_flags,
                                    "risk_level": "high" if suspicion_score >= 30 else "medium"
                                }
                                persistence_threats.append(threat)
        
        # Analyze scheduled tasks
        if isinstance(scheduled_tasks, list):
            for task in scheduled_tasks:
                if isinstance(task, dict) and task.get('is_suspicious', False):
                    threat = {
                        "type": "suspicious_scheduled_task",
                        "task_name": task.get('TaskName', 'Unknown'),
                        "command": task.get('Task To Run', ''),
                        "status": task.get('Status', ''),
                        "author": task.get('Author', ''),
                        "next_run_time": task.get('Next Run Time', ''),
                        "risk_level": task.get('risk_level', 'medium')
                    }
                    persistence_threats.append(threat)
        
        print(f"🎯 Found {len(persistence_threats)} persistence threats")
        return persistence_threats

    def generate_recommendations(self, suspicious_processes, persistence_threats):
        """Generate enhanced actionable recommendations"""
        recommendations = []
        
        print("💡 Generating security recommendations...")
        
        # Process-based recommendations
        for proc in suspicious_processes:
            pid = proc.get('pid', 'Unknown')
            name = proc.get('name', 'Unknown')
            flags = proc.get('flags', [])
            score = proc.get('suspicion_score', 0)
            vt_result = proc.get('virustotal_result', {})
            
            # Critical - VirusTotal detections
            if any('virustotal_malicious' in str(flag) for flag in flags):
                malicious_count = vt_result.get('malicious', 0)
                threat_names = vt_result.get('threat_names', [])
                
                recommendations.append({
                    "priority": "CRITICAL",
                    "action": f"🚨 TERMINATE IMMEDIATELY: {name} (PID: {pid})",
                    "reason": f"Malware detected by {malicious_count} antivirus engines",
                    "details": f"Threats: {', '.join(threat_names[:3]) if threat_names else 'Multiple detections'}",
                    "command": f"taskkill /PID {pid} /F" if platform.system().lower() == 'windows' else f"kill -9 {pid}",
                    "follow_up": f"Delete file: {proc.get('executable_path', 'N/A')}"
                })
            
            # High - Suspicious location + other factors
            elif 'running_from_suspicious_location' in flags and score >= 40:
                recommendations.append({
                    "priority": "HIGH",
                    "action": f"⚠️  INVESTIGATE IMMEDIATELY: {name} (PID: {pid})",
                    "reason": "Process running from suspicious location with multiple red flags",
                    "details": f"Path: {proc.get('executable_path', 'N/A')}, Score: {score}",
                    "command": f"Isolate and analyze file: {proc.get('executable_path', 'N/A')}",
                    "follow_up": "Consider terminating if investigation confirms threat"
                })
            
            # Medium - Unsigned or suspicious patterns
            elif 'unsigned_executable' in flags or score >= 30:
                recommendations.append({
                    "priority": "MEDIUM",
                    "action": f"🔍 VERIFY PROCESS: {name} (PID: {pid})",
                    "reason": "Unsigned executable or suspicious behavior pattern",
                    "details": f"Flags: {', '.join(flags)}, Score: {score}",
                    "command": f"Check process legitimacy and digital signature",
                    "follow_up": "Monitor for additional suspicious activity"
                })
        
        # Persistence-based recommendations
        for threat in persistence_threats:
            if threat['risk_level'] == 'high':
                if threat['type'] == 'suspicious_scheduled_task':
                    recommendations.append({
                        "priority": "HIGH",
                        "action": f"🗓️ DISABLE TASK: {threat['task_name']}",
                        "reason": "Highly suspicious scheduled task detected",
                        "details": f"Command: {threat['command'][:100]}...",
                        "command": f"schtasks /change /tn \"{threat['task_name']}\" /disable",
                        "follow_up": f"Delete task: schtasks /delete /tn \"{threat['task_name']}\" /f"
                    })
                
                elif threat['type'] == 'suspicious_startup_program':
                    recommendations.append({
                        "priority": "HIGH",
                        "action": f"🚀 REMOVE STARTUP: {threat['name']}",
                        "reason": "Highly suspicious startup program detected",
                        "details": f"Command: {threat['command'][:100]}...",
                        "command": f"Remove from {threat['registry_path']}",
                        "follow_up": "Verify removal and check for file deletion"
                    })
            
            elif threat['risk_level'] == 'medium':
                recommendations.append({
                    "priority": "MEDIUM",
                    "action": f"📋 REVIEW: {threat.get('task_name', threat.get('name', 'Unknown'))}",
                    "reason": "Potentially suspicious persistence mechanism",
                    "details": f"Type: {threat['type']}",
                    "command": "Manual review required",
                    "follow_up": "Monitor for changes or unexpected behavior"
                })
        
        # General system hardening recommendations
        if len(suspicious_processes) > 0 or len(persistence_threats) > 0:
            recommendations.append({
                "priority": "MEDIUM",
                "action": "🛡️ ENHANCE SYSTEM SECURITY",
                "reason": "Multiple suspicious activities detected",
                "details": "System shows signs of compromise or suspicious activity",
                "command": "Run full antivirus scan, update all software, check Windows Updates",
                "follow_up": "Consider system restore to known good state if threats confirmed"
            })
        
        print(f"📋 Generated {len(recommendations)} recommendations")
        return recommendations

    def create_incident_report(self, system_data, suspicious_processes, persistence_threats):
        """Create comprehensive incident report with enhanced details"""
        
        print("📄 Creating comprehensive incident report...")
        
        # Enhanced summary statistics
        total_processes = len([p for p in system_data.get('running_processes', []) if isinstance(p, dict) and 'error' not in p])
        total_connections = len([c for c in system_data.get('network_connections', []) if isinstance(c, dict) and 'error' not in c])
        
        # VirusTotal statistics
        vt_checked = len([p for p in suspicious_processes if p.get('virustotal_result', {}).get('found')])
        vt_malicious = len([p for p in suspicious_processes if p.get('virustotal_result', {}).get('malicious', 0) > 0])
        
        self.incident_report['summary'] = {
            "scan_timestamp": datetime.now().isoformat(),
            "system_info": {
                "hostname": system_data.get('os_info', {}).get('hostname', 'Unknown'),
                "platform": system_data.get('os_info', {}).get('platform', 'Unknown'),
                "uptime": system_data.get('os_info', {}).get('uptime_readable', 'Unknown')
            },
            "analysis_stats": {
                "total_processes_scanned": total_processes,
                "suspicious_processes_found": len(suspicious_processes),
                "persistence_threats_found": len(persistence_threats),
                "total_network_connections": total_connections,
                "virustotal_checks_performed": vt_checked,
                "malware_detections": vt_malicious
            },
            "risk_assessment": {
                "overall_risk_level": self._calculate_overall_risk_level(suspicious_processes, persistence_threats),
                "confidence_level": self._calculate_confidence_level(suspicious_processes, persistence_threats),
                "threat_severity": self._assess_threat_severity(suspicious_processes, persistence_threats)
            }
        }
        
        # Enhanced critical findings
        critical_findings = []
        
        for proc in suspicious_processes:
            vt_result = proc.get('virustotal_result', {})

            if proc.get('suspicion_score', 0) >= 50 or vt_result.get('malicious', 0) > 0:
                finding = {
                    "finding_id": f"PROC-{proc.get('pid', 'UNK')}",
                    "type": "malicious_process",
                    "severity": "CRITICAL" if vt_result.get('malicious', 0) > 0 else "HIGH",
                    "process_details": {
                        "name": proc.get('name', 'Unknown'),
                        "pid": proc.get('pid', 'Unknown'),
                        "executable_path": proc.get('executable_path', 'N/A'),
                        "user": proc.get('user', 'Unknown'),
                        "command_line": proc.get('command_line', 'N/A')
                    },
                    "threat_analysis": {
                        "suspicion_score": proc.get('suspicion_score', 0),
                        "flags": proc.get('flags', []),
                        "file_hash": proc.get('file_hash', 'N/A')
                    },
                    "virustotal_analysis": vt_result if vt_result.get('found') else None,
                    "timestamp": datetime.now().isoformat()
                }
                critical_findings.append(finding)
        
        for i, threat in enumerate(persistence_threats):
            if threat['risk_level'] == 'high':
                finding = {
                    "finding_id": f"PERS-{i+1:03d}",
                    "type": "persistence_mechanism",
                    "severity": "HIGH",
                    "threat_details": {
                        "type": threat['type'],
                        "name": threat.get('task_name', threat.get('name', 'Unknown')),
                        "command": threat.get('command', ''),
                        "location": threat.get('registry_path', threat.get('location', 'Unknown'))
                    },
                    "risk_analysis": {
                        "risk_level": threat['risk_level'],
                        "flags": threat.get('flags', []),
                        "suspicion_score": threat.get('suspicion_score', 0)
                    },
                    "timestamp": datetime.now().isoformat()
                }
                critical_findings.append(finding)
        
        self.incident_report['critical_findings'] = critical_findings
        
        # Generate enhanced recommendations
        recommendations = self.generate_recommendations(suspicious_processes, persistence_threats)
        self.incident_report['recommendations'] = recommendations
        
        # Detailed analysis with full context
        self.incident_report['detailed_analysis'] = {
            "suspicious_processes": suspicious_processes,
            "persistence_threats": persistence_threats,
            "analysis_metadata": {
                "analysis_timestamp": datetime.now().isoformat(),
                "analyzer_version": "Phase 3 v1.0",
                "virustotal_api_used": bool(self.vt_api_key),
                "analysis_duration": "Calculated at runtime"
            }
        }
        
        # Executive summary for management
        self.incident_report['executive_summary'] = self._create_executive_summary(critical_findings, recommendations)
        
        return self.incident_report

    def _calculate_overall_risk_level(self, suspicious_processes, persistence_threats):
        """Calculate overall system risk level with enhanced logic"""
        critical_count = sum(1 for proc in suspicious_processes if proc.get('suspicion_score', 0) >= 70)
        high_risk_count = sum(1 for proc in suspicious_processes if proc.get('suspicion_score', 0) >= 50)
        malware_count = sum(1 for proc in suspicious_processes if proc.get('virustotal_result', {}).get('malicious', 0) > 0)
        high_persist_count = sum(1 for threat in persistence_threats if threat['risk_level'] == 'high')
        
        if malware_count > 0 or critical_count > 0:
            return "CRITICAL"
        elif high_risk_count >= 2 or high_persist_count >= 2:
            return "HIGH"
        elif high_risk_count >= 1 or high_persist_count >= 1 or len(suspicious_processes) >= 3:
            return "MEDIUM"
        elif len(suspicious_processes) > 0 or len(persistence_threats) > 0:
            return "LOW"
        else:
            return "MINIMAL"

    def _calculate_confidence_level(self, suspicious_processes, persistence_threats):
        """Calculate confidence level in the analysis"""
        vt_checked = sum(1 for proc in suspicious_processes if proc.get('virustotal_result', {}).get('found'))
        total_suspicious = len(suspicious_processes)
        
        if total_suspicious == 0:
            return "HIGH"
        elif vt_checked / max(total_suspicious, 1) >= 0.8:
            return "HIGH"
        elif vt_checked / max(total_suspicious, 1) >= 0.5:
            return "MEDIUM"
        else:
            return "LOW"

    def _assess_threat_severity(self, suspicious_processes, persistence_threats):
        """Assess overall threat severity"""
        max_vt_detections = max([proc.get('virustotal_result', {}).get('malicious', 0) for proc in suspicious_processes] + [0])
        max_suspicion_score = max([proc.get('suspicion_score', 0) for proc in suspicious_processes] + [0])
        
        if max_vt_detections >= 5:
            return "SEVERE"
        elif max_vt_detections >= 2 or max_suspicion_score >= 70:
            return "HIGH"
        elif max_vt_detections >= 1 or max_suspicion_score >= 50:
            return "MODERATE"
        else:
            return "LOW"

    def _create_executive_summary(self, critical_findings, recommendations):
        """Create executive summary for management"""
        critical_recs = [r for r in recommendations if r.get('priority') == 'CRITICAL']
        high_recs = [r for r in recommendations if r.get('priority') == 'HIGH']
        
        return {
            "overview": f"Security analysis completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "key_findings": f"{len(critical_findings)} critical security findings identified",
            "immediate_actions_required": len(critical_recs),
            "high_priority_actions": len(high_recs),
            "business_impact": "Potential system compromise detected" if critical_recs else "System security concerns identified",
            "next_steps": [
                "Review all critical and high-priority recommendations",
                "Execute recommended actions in priority order",
                "Monitor system for changes after remediation",
                "Consider engaging incident response team if threats confirmed"
            ]
        }

# [Rest of the helper functions remain the same as previous version]
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

def get_startup_programs():
    """Get startup programs from Windows Registry."""
    if not WIN32_AVAILABLE or platform.system().lower() != 'windows':
        return {"error": "Registry access only available on Windows with pywin32"}
    
    startup_programs = {
        "current_user": [],
        "local_machine": []
    }
    
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
                        break
                        
        except Exception as e:
            print(f"Error accessing startup registry path {subkey_path}: {str(e)}")
    
    return startup_programs

def save_incident_report(incident_report, filename):
    """Save incident report to JSON file"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(incident_report, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"Error saving incident report: {str(e)}")
        return False

def print_incident_summary(incident_report):
    """Print enhanced incident report summary"""
    print("\n" + "="*90)
    print("🚨 SECURITY INCIDENT REPORT - PHASE 3 ENHANCED ANALYSIS")
    print("="*90)
    
    summary = incident_report.get('summary', {})
    risk_assessment = summary.get('risk_assessment', {})
    analysis_stats = summary.get('analysis_stats', {})
    
    print(f"🎯 RISK LEVEL: {risk_assessment.get('overall_risk_level', 'UNKNOWN')}")
    print(f"🔍 CONFIDENCE: {risk_assessment.get('confidence_level', 'UNKNOWN')}")
    print(f"⚡ SEVERITY: {risk_assessment.get('threat_severity', 'UNKNOWN')}")
    print(f"📊 PROCESSES SCANNED: {analysis_stats.get('total_processes_scanned', 0)}")
    print(f"🚩 SUSPICIOUS: {analysis_stats.get('suspicious_processes_found', 0)}")
    print(f"🦠 MALWARE DETECTED: {analysis_stats.get('malware_detections', 0)}")
    print(f"🔒 PERSISTENCE THREATS: {analysis_stats.get('persistence_threats_found', 0)}")
    print(f"🔍 VIRUSTOTAL CHECKS: {analysis_stats.get('virustotal_checks_performed', 0)}")
    
    # Critical findings
    critical_findings = incident_report.get('critical_findings', [])
    if critical_findings:
        print(f"\n🚨 CRITICAL FINDINGS ({len(critical_findings)}):")
        for i, finding in enumerate(critical_findings[:5], 1):
            severity_emoji = "🔥" if finding.get('severity') == 'CRITICAL' else "⚠️"
            name = finding.get('process_details', {}).get('name') or finding.get('threat_details', {}).get('name', 'Unknown')
            print(f"  {severity_emoji} {i}. [{finding.get('severity', 'UNK')}] {finding.get('type', 'Unknown')}: {name}")
    
    # Top recommendations
    recommendations = incident_report.get('recommendations', [])
    if recommendations:
        print(f"\n💡 IMMEDIATE ACTIONS REQUIRED:")
        critical_recs = [r for r in recommendations if r.get('priority') == 'CRITICAL']
        high_recs = [r for r in recommendations if r.get('priority') == 'HIGH']
        
        for rec in (critical_recs + high_recs)[:5]:
            priority_emoji = "🔥" if rec.get('priority') == 'CRITICAL' else "⚠️" if rec.get('priority') == 'HIGH' else "ℹ️"
            print(f"  {priority_emoji} [{rec.get('priority', 'UNK')}] {rec.get('action', 'No action specified')}")
            print(f"    └─ {rec.get('reason', 'No reason provided')}")
            if rec.get('command', '').strip():
                print(f"    └─ Command: {rec.get('command', '')}")
    
    # Executive summary
    exec_summary = incident_report.get('executive_summary', {})
    if exec_summary:
        print(f"\n📋 EXECUTIVE SUMMARY:")
        print(f"   • {exec_summary.get('key_findings', 'No findings')}")
        print(f"   • Immediate Actions: {exec_summary.get('immediate_actions_required', 0)}")
        print(f"   • Business Impact: {exec_summary.get('business_impact', 'Unknown')}")
    
    print("="*90)

def main():
    """Enhanced main function for Phase 3 threat detection"""
    print("🔒 SYSTEM SECURITY ANALYZER - PHASE 3: INTELLIGENCE & DETECTION")
    print("="*90)
    print("🛡️  Enhanced with VirusTotal API v3 Integration")
    print("🔍 Real-time Threat Intelligence & Advanced Detection")
    print("="*90)
    
    # Initialize threat detector with pre-configured API key
    detector = ThreatDetector()
    print("✅ VirusTotal API v3 configured and ready")
    
    start_time = time.time()
    print(f"\n🚀 Starting comprehensive threat analysis at {datetime.now().strftime('%H:%M:%S')}")
    
    # Collect system information
    system_data = {
        "collection_timestamp": datetime.now().isoformat(),
        "phase": "Phase 3 - Intelligence & Detection Enhanced",
        "os_info": get_os_info(),
        "running_processes": get_running_processes()
    }
    
    print(f"📊 System info collected: {system_data['os_info'].get('hostname', 'Unknown')} - {system_data['os_info'].get('platform', 'Unknown')}")
    
    # Analyze processes for threats
    print(f"\n🔬 PHASE 1: Process Analysis & VirusTotal Integration")
    suspicious_processes = detector.detect_process_anomalies(system_data['running_processes'])
    
    # Get persistence mechanisms
    persistence_threats = []
    if platform.system().lower() == 'windows':
        print(f"\n🔒 PHASE 2: Persistence Mechanism Analysis")
        startup_programs = get_startup_programs()
        scheduled_tasks = detector.get_scheduled_tasks_windows()
        
        system_data['startup_programs'] = startup_programs
        system_data['scheduled_tasks'] = scheduled_tasks
        
        persistence_threats = detector.analyze_persistence_mechanisms(startup_programs, scheduled_tasks)
    else:
        print(f"\n⚠️  Windows-specific analysis skipped (OS: {platform.system()})")
    
    # Generate incident report
    print(f"\n📋 PHASE 3: Incident Report Generation")
    incident_report = detector.create_incident_report(system_data, suspicious_processes, persistence_threats)
    
    # Calculate analysis duration
    analysis_duration = time.time() - start_time
    incident_report['detailed_analysis']['analysis_metadata']['analysis_duration'] = f"{analysis_duration:.2f} seconds"
    
    # Save reports with enhanced naming
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    hostname = system_data['os_info'].get('hostname', 'unknown')
    
    # Save detailed system data
    system_filename = f"system_analysis_enhanced_{hostname}_{timestamp}.json"
    with open(system_filename, 'w', encoding='utf-8') as f:
        json.dump(system_data, f, indent=2, ensure_ascii=False)
    
    # Save incident report
    incident_filename = f"incident_report_enhanced_{hostname}_{timestamp}.json"
    save_incident_report(incident_report, incident_filename)
    
    # Print comprehensive summary
    print_incident_summary(incident_report)
    
    # Final status and recommendations
    risk_level = incident_report['summary']['risk_assessment']['overall_risk_level']
    print(f"\n✅ ANALYSIS COMPLETED in {analysis_duration:.2f} seconds")
    print(f"📁 System data: {system_filename}")
    print(f"📋 Incident report: {incident_filename}")
    
    if risk_level in ['CRITICAL', 'HIGH']:
        print(f"\n🚨 URGENT ACTION REQUIRED!")
        print(f"   System risk level: {risk_level}")
        print(f"   Review incident report immediately and execute recommended actions.")
        if incident_report['summary']['analysis_stats']['malware_detections'] > 0:
            print(f"   🦠 MALWARE DETECTED - Consider immediate system isolation!")
    elif risk_level == 'MEDIUM':
        print(f"\n⚠️  Security concerns identified (Risk: {risk_level})")
        print(f"   Review recommendations and take appropriate action.")
    else:
        print(f"\n✅ System appears clean (Risk: {risk_level})")
        print(f"   Continue monitoring and maintain security best practices.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n⚠️  Analysis interrupted by user.")
    except Exception as e:
        print(f"\n❌ Unexpected error: {str(e)}")
        import traceback
        traceback.print_exc()
