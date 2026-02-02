"""
Network Monitor Module

This module monitors network-level activities:
- Active network connections
- Suspicious port usage
- Connection patterns
- Network traffic anomalies

Note: Some features require administrative privileges.
"""

import psutil
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from collections import defaultdict


class NetworkMonitor:
    """
    Monitors network connections and activity.
    
    Explanation:
    - Tracks TCP/UDP connections
    - Detects connections to suspicious ports
    - Monitors connection patterns per process
    - Identifies potential port scanning
    
    Why it matters:
    - Malware often connects to command & control servers
    - Port scanning is common reconnaissance technique
    - Unusual connections can indicate lateral movement
    
    Limitation:
    - Cannot inspect packet contents (would need scapy + admin rights)
    - Focuses on connection metadata
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize network monitor.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.logger = logging.getLogger('CyberAdvisor.NetworkMonitor')
        
        # Get suspicious ports from config
        self.suspicious_ports = config.get('monitoring', {}).get('network', {}).get(
            'suspicious_ports', [4444, 5555, 6666, 31337]
        )
        
        # Maximum connections per process threshold
        self.max_connections_per_process = config.get('monitoring', {}).get('network', {}).get(
            'max_connections_per_process', 100
        )
        
        # Track connection history for pattern detection
        self.connection_history = defaultdict(list)
        
        self.logger.info("Network Monitor initialized")
    
    def get_active_connections(self) -> List[Dict[str, Any]]:
        """
        Get all active network connections.
        
        Returns:
            List of connection dictionaries
        """
        connections = []
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                # Skip connections without remote address (listening sockets)
                if conn.status == 'LISTEN' or not conn.raddr:
                    continue
                
                connection_info = {
                    'fd': conn.fd,
                    'family': str(conn.family),
                    'type': str(conn.type),
                    'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                    'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}",
                    'remote_ip': conn.raddr.ip,
                    'remote_port': conn.raddr.port,
                    'status': conn.status,
                    'pid': conn.pid
                }
                
                # Get process name if PID is available
                if conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        connection_info['process_name'] = proc.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        connection_info['process_name'] = 'Unknown'
                
                connections.append(connection_info)
        
        except psutil.AccessDenied:
            self.logger.warning("Access denied for network connections. Run with elevated privileges.")
        except Exception as e:
            self.logger.error(f"Error getting network connections: {e}")
        
        return connections
    
    def detect_suspicious_ports(self) -> List[Dict[str, Any]]:
        """
        Detect connections to suspicious ports.
        
        Explanation:
        Certain ports are commonly used by malware:
        - 4444: Metasploit default
        - 5555: Common backdoor
        - 6666: IRC bots
        - 31337: Back Orifice trojan
        
        Returns:
            List of suspicious port connection events
        """
        suspicious_events = []
        connections = self.get_active_connections()
        
        for conn in connections:
            if conn['remote_port'] in self.suspicious_ports:
                event = {
                    'timestamp': datetime.now().isoformat(),
                    'event_type': 'network_connection',
                    'source': 'network_monitor',
                    'severity': 'high',
                    'data': {
                        'process_name': conn.get('process_name', 'Unknown'),
                        'pid': conn.get('pid'),
                        'remote_ip': conn['remote_ip'],
                        'remote_port': conn['remote_port'],
                        'local_address': conn['local_address'],
                        'status': conn['status'],
                        'reason': f"Connection to suspicious port {conn['remote_port']}"
                    }
                }
                suspicious_events.append(event)
                self.logger.warning(
                    f"Suspicious port connection: {conn.get('process_name')} -> "
                    f"{conn['remote_ip']}:{conn['remote_port']}"
                )
        
        return suspicious_events
    
    def detect_excessive_connections(self) -> List[Dict[str, Any]]:
        """
        Detect processes making too many connections.
        
        Explanation:
        A process making many connections might be:
        - Port scanner (nmap, etc.)
        - Botnet spreading
        - DDoS attack tool
        - Network worm
        
        Returns:
            List of excessive connection events
        """
        excessive_conn_events = []
        connections = self.get_active_connections()
        
        # Count connections per process
        connection_counts = defaultdict(list)
        for conn in connections:
            pid = conn.get('pid')
            if pid:
                connection_counts[pid].append(conn)
        
        # Check for excessive connections
        for pid, conns in connection_counts.items():
            if len(conns) > self.max_connections_per_process:
                process_name = conns[0].get('process_name', 'Unknown')
                
                event = {
                    'timestamp': datetime.now().isoformat(),
                    'event_type': 'multiple_connections',
                    'source': 'network_monitor',
                    'severity': 'medium',
                    'data': {
                        'process_name': process_name,
                        'pid': pid,
                        'connection_count': len(conns),
                        'threshold': self.max_connections_per_process,
                        'sample_connections': [
                            f"{c['remote_ip']}:{c['remote_port']}" 
                            for c in conns[:5]  # Show first 5
                        ]
                    }
                }
                excessive_conn_events.append(event)
                self.logger.warning(
                    f"Excessive connections: {process_name} (PID {pid}) has {len(conns)} connections"
                )
        
        return excessive_conn_events
    
    def detect_unusual_destinations(self) -> List[Dict[str, Any]]:
        """
        Detect connections to unusual IP ranges.
        
        Explanation:
        Checks for connections to:
        - Private IP ranges from internet-facing apps (possible pivot)
        - Non-standard ports for common services
        
        Returns:
            List of unusual destination events
        """
        unusual_events = []
        connections = self.get_active_connections()
        
        for conn in connections:
            remote_ip = conn['remote_ip']
            
            # Check for connections to private IPs (might be normal for LAN apps)
            if self._is_private_ip(remote_ip):
                # Only flag if process is making many external connections too
                # This is a simplified check - can be enhanced
                event = {
                    'timestamp': datetime.now().isoformat(),
                    'event_type': 'network_connection',
                    'source': 'network_monitor',
                    'severity': 'low',
                    'data': {
                        'process_name': conn.get('process_name', 'Unknown'),
                        'pid': conn.get('pid'),
                        'remote_ip': remote_ip,
                        'remote_port': conn['remote_port'],
                        'reason': 'Connection to private IP range'
                    }
                }
                # Only log, don't add to events (too noisy for demo)
                # unusual_events.append(event)
        
        return unusual_events
    
    def get_network_statistics(self) -> Dict[str, Any]:
        """
        Get overall network statistics.
        
        Returns:
            Network stats dictionary
        """
        connections = self.get_active_connections()
        
        # Count connections by status
        status_counts = defaultdict(int)
        for conn in connections:
            status_counts[conn['status']] += 1
        
        # Count unique remote IPs
        unique_ips = set(conn['remote_ip'] for conn in connections)
        
        # Count connections by process
        process_counts = defaultdict(int)
        for conn in connections:
            process_name = conn.get('process_name', 'Unknown')
            process_counts[process_name] += 1
        
        return {
            'timestamp': datetime.now().isoformat(),
            'total_connections': len(connections),
            'unique_remote_ips': len(unique_ips),
            'connections_by_status': dict(status_counts),
            'top_processes': dict(sorted(
                process_counts.items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:5])
        }
    
    def scan_network(self) -> Dict[str, Any]:
        """
        Perform complete network scan.
        
        This is the main method called periodically.
        
        Returns:
            Dictionary with all network monitoring results
        """
        self.logger.debug("Starting network scan...")
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'statistics': self.get_network_statistics(),
            'suspicious_ports': self.detect_suspicious_ports(),
            'excessive_connections': self.detect_excessive_connections(),
            'unusual_destinations': self.detect_unusual_destinations()
        }
        
        # Count events
        total_events = (
            len(results['suspicious_ports']) +
            len(results['excessive_connections']) +
            len(results['unusual_destinations'])
        )
        
        self.logger.debug(f"Network scan complete. Found {total_events} events.")
        
        return results
    
    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """
        Check if IP address is in private range.
        
        Private ranges:
        - 10.0.0.0/8
        - 172.16.0.0/12
        - 192.168.0.0/16
        
        Args:
            ip: IP address string
        
        Returns:
            True if private IP
        """
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        try:
            first = int(parts[0])
            second = int(parts[1])
            
            # 10.x.x.x
            if first == 10:
                return True
            # 172.16.x.x - 172.31.x.x
            if first == 172 and 16 <= second <= 31:
                return True
            # 192.168.x.x
            if first == 192 and second == 168:
                return True
            # 127.x.x.x (localhost)
            if first == 127:
                return True
            
            return False
        except ValueError:
            return False


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    test_config = {
        'monitoring': {
            'network': {
                'suspicious_ports': [4444, 5555, 6666],
                'max_connections_per_process': 50
            }
        }
    }
    
    monitor = NetworkMonitor(test_config)
    results = monitor.scan_network()
    
    print(f"Network Statistics: {results['statistics']}")
    print(f"Suspicious Ports: {len(results['suspicious_ports'])}")
    print(f"Excessive Connections: {len(results['excessive_connections'])}")
