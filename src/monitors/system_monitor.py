"""
System Monitor Module

This module monitors system-level activities:
- Running processes
- CPU and memory usage
- Process creation/termination
- Suspicious process detection

Uses psutil library for cross-platform system monitoring.
"""

import psutil
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
import time


class SystemMonitor:
    """
    Monitors system processes and resource usage.
    
    Explanation:
    - Uses psutil to get system information
    - Tracks running processes
    - Detects suspicious process names
    - Monitors CPU/memory usage
    
    Why it matters:
    - Malware often appears as suspicious processes
    - Resource abuse can indicate cryptominers or DoS
    - Process monitoring is first line of defense
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize system monitor.
        
        Args:
            config: Configuration dictionary with monitoring settings
        """
        self.config = config
        self.logger = logging.getLogger('CyberAdvisor.SystemMonitor')
        
        # Get suspicious process names from config
        self.suspicious_names = config.get('monitoring', {}).get('system', {}).get(
            'suspicious_process_names', []
        )
        
        # Thresholds
        self.cpu_threshold = config.get('monitoring', {}).get('system', {}).get(
            'cpu_threshold', 90
        )
        self.memory_threshold = config.get('monitoring', {}).get('system', {}).get(
            'memory_threshold', 85
        )
        
        # Track processes for change detection
        self.previous_processes = set()
        
        self.logger.info("System Monitor initialized")
    
    def get_running_processes(self) -> List[Dict[str, Any]]:
        """
        Get list of currently running processes.
        
        Returns:
            List of process dictionaries with name, pid, cpu%, memory%
        """
        processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'username']):
            try:
                pinfo = proc.info
                processes.append({
                    'pid': pinfo['pid'],
                    'name': pinfo['name'],
                    'cpu_percent': pinfo['cpu_percent'],
                    'memory_percent': pinfo['memory_percent'],
                    'username': pinfo['username']
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        return processes
    
    def check_system_resources(self) -> Dict[str, Any]:
        """
        Check overall system resource usage.
        
        Returns:
            Dictionary with CPU, memory, disk usage
        """
        return {
            'timestamp': datetime.now().isoformat(),
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_percent': psutil.disk_usage('/').percent,
            'network_connections': len(psutil.net_connections())
        }
    
    def detect_suspicious_processes(self) -> List[Dict[str, Any]]:
        """
        Detect processes with suspicious names.
        
        Explanation:
        Checks if any running process name matches known hacking tools.
        This is a simple signature-based detection.
        
        Returns:
            List of suspicious process events
        """
        suspicious_events = []
        processes = self.get_running_processes()
        
        for proc in processes:
            proc_name_lower = proc['name'].lower()
            
            # Check against suspicious names list
            for suspicious_name in self.suspicious_names:
                if suspicious_name.lower() in proc_name_lower:
                    event = {
                        'timestamp': datetime.now().isoformat(),
                        'event_type': 'process_start',
                        'source': 'system_monitor',
                        'severity': 'high',
                        'data': {
                            'process_name': proc['name'],
                            'pid': proc['pid'],
                            'cpu_percent': proc['cpu_percent'],
                            'memory_percent': proc['memory_percent'],
                            'username': proc['username'],
                            'reason': f"Matches suspicious pattern: {suspicious_name}"
                        }
                    }
                    suspicious_events.append(event)
                    self.logger.warning(f"Suspicious process detected: {proc['name']} (PID: {proc['pid']})")
        
        return suspicious_events
    
    def detect_high_resource_usage(self) -> List[Dict[str, Any]]:
        """
        Detect processes using excessive CPU or memory.
        
        Explanation:
        High resource usage can indicate:
        - Cryptomining malware
        - Denial of service attacks
        - Runaway processes
        
        Returns:
            List of high resource usage events
        """
        high_usage_events = []
        processes = self.get_running_processes()
        
        for proc in processes:
            # Check CPU usage
            if proc['cpu_percent'] and proc['cpu_percent'] > self.cpu_threshold:
                event = {
                    'timestamp': datetime.now().isoformat(),
                    'event_type': 'high_cpu',
                    'source': 'system_monitor',
                    'severity': 'medium',
                    'data': {
                        'process_name': proc['name'],
                        'pid': proc['pid'],
                        'cpu_percent': proc['cpu_percent'],
                        'threshold': self.cpu_threshold,
                        'username': proc['username']
                    }
                }
                high_usage_events.append(event)
            
            # Check memory usage
            if proc['memory_percent'] and proc['memory_percent'] > self.memory_threshold:
                event = {
                    'timestamp': datetime.now().isoformat(),
                    'event_type': 'high_memory',
                    'source': 'system_monitor',
                    'severity': 'medium',
                    'data': {
                        'process_name': proc['name'],
                        'pid': proc['pid'],
                        'memory_percent': proc['memory_percent'],
                        'threshold': self.memory_threshold,
                        'username': proc['username']
                    }
                }
                high_usage_events.append(event)
        
        return high_usage_events
    
    def detect_new_processes(self) -> List[Dict[str, Any]]:
        """
        Detect newly started processes since last check.
        
        Explanation:
        Tracking new processes helps identify:
        - Process injection
        - Malware spawning child processes
        - Unexpected program launches
        
        Returns:
            List of new process events
        """
        new_process_events = []
        current_processes = {(p['pid'], p['name']) for p in self.get_running_processes()}
        
        # Find new processes
        new_processes = current_processes - self.previous_processes
        
        for pid, name in new_processes:
            event = {
                'timestamp': datetime.now().isoformat(),
                'event_type': 'process_start',
                'source': 'system_monitor',
                'severity': 'info',
                'data': {
                    'process_name': name,
                    'pid': pid
                }
            }
            new_process_events.append(event)
        
        # Update previous processes
        self.previous_processes = current_processes
        
        return new_process_events
    
    def scan_system(self) -> Dict[str, Any]:
        """
        Perform a complete system scan.
        
        This is the main method called periodically to check system status.
        
        Returns:
            Dictionary with all monitoring results
        """
        self.logger.debug("Starting system scan...")
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'resource_usage': self.check_system_resources(),
            'suspicious_processes': self.detect_suspicious_processes(),
            'high_resource_usage': self.detect_high_resource_usage(),
            'new_processes': self.detect_new_processes()
        }
        
        # Count events
        total_events = (
            len(results['suspicious_processes']) +
            len(results['high_resource_usage']) +
            len(results['new_processes'])
        )
        
        self.logger.debug(f"System scan complete. Found {total_events} events.")
        
        return results
    
    def get_process_details(self, pid: int) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a specific process.
        
        Args:
            pid: Process ID
        
        Returns:
            Process details or None if not found
        """
        try:
            proc = psutil.Process(pid)
            return {
                'pid': proc.pid,
                'name': proc.name(),
                'exe': proc.exe(),
                'cwd': proc.cwd(),
                'cmdline': proc.cmdline(),
                'username': proc.username(),
                'create_time': datetime.fromtimestamp(proc.create_time()).isoformat(),
                'cpu_percent': proc.cpu_percent(interval=0.1),
                'memory_percent': proc.memory_percent(),
                'status': proc.status(),
                'num_threads': proc.num_threads(),
                'connections': len(proc.connections())
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            self.logger.warning(f"Cannot access process {pid}")
            return None


# Example usage and testing
if __name__ == "__main__":
    # Simple test
    logging.basicConfig(level=logging.INFO)
    
    # Mock config
    test_config = {
        'monitoring': {
            'system': {
                'suspicious_process_names': ['mimikatz', 'nmap', 'netcat'],
                'cpu_threshold': 80,
                'memory_threshold': 80
            }
        }
    }
    
    monitor = SystemMonitor(test_config)
    results = monitor.scan_system()
    
    print(f"Resource Usage: {results['resource_usage']}")
    print(f"Suspicious Processes: {len(results['suspicious_processes'])}")
    print(f"High Resource Usage: {len(results['high_resource_usage'])}")
    print(f"New Processes: {len(results['new_processes'])}")
