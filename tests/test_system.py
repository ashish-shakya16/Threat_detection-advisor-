"""
Test System - Simulates threats for testing purposes

This script helps you test the threat detection system by:
1. Simulating various types of security events
2. Generating test data
3. Verifying all modules work correctly

IMPORTANT: This is for TESTING ONLY in a safe environment!
"""

import sys
import time
import random
from pathlib import Path
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from src.utils import Config, Logger, load_rules
from src.database import DatabaseManager
from src.detection import RuleEngine
from src.risk_assessment import RiskScorer
from src.advisory import SecurityAdvisor


class ThreatSimulator:
    """
    Simulates various threat scenarios for testing.
    
    This is an educational tool to demonstrate how the system works!
    """
    
    def __init__(self):
        """Initialize simulator."""
        print("=" * 70)
        print("🧪 Cybersecurity Threat Advisor - Test Suite")
        print("=" * 70)
        print()
        
        # Load configuration
        self.config = Config()
        
        # Load rules
        rules_data = load_rules()
        
        # Initialize modules
        self.rule_engine = RuleEngine(rules_data)
        self.risk_scorer = RiskScorer(self.config.config)
        self.advisor = SecurityAdvisor(rules_data.get('advisory_templates', {}), self.config.config)
        self.db = DatabaseManager()
        
        print("✓ All modules initialized")
        print()
    
    def generate_suspicious_process_event(self):
        """Generate a suspicious process event."""
        suspicious_processes = ['mimikatz.exe', 'nmap.exe', 'netcat.exe', 'metasploit.exe']
        
        return {
            'timestamp': datetime.now().isoformat(),
            'event_type': 'process_start',
            'source': 'system_monitor',
            'severity': 'high',
            'data': {
                'process_name': random.choice(suspicious_processes),
                'pid': random.randint(1000, 9999),
                'cpu_percent': random.uniform(5, 20),
                'memory_percent': random.uniform(2, 10),
                'username': 'test_user',
                'reason': 'Matches suspicious pattern'
            }
        }
    
    def generate_brute_force_event(self):
        """Generate a brute force attack event."""
        return {
            'timestamp': datetime.now().isoformat(),
            'event_type': 'auth_failure',
            'source': 'auth_monitor',
            'severity': 'medium',
            'data': {
                'username': 'admin',
                'count': random.randint(5, 15),
                'source_ip': f"192.168.1.{random.randint(1, 254)}",
                'time_window': 60
            }
        }
    
    def generate_suspicious_port_event(self):
        """Generate a suspicious port connection event."""
        suspicious_ports = [4444, 5555, 6666, 31337]
        
        return {
            'timestamp': datetime.now().isoformat(),
            'event_type': 'network_connection',
            'source': 'network_monitor',
            'severity': 'high',
            'data': {
                'process_name': 'unknown_app.exe',
                'pid': random.randint(1000, 9999),
                'remote_ip': f"10.0.0.{random.randint(1, 254)}",
                'remote_port': random.choice(suspicious_ports),
                'local_address': f"192.168.1.100:{random.randint(50000, 60000)}",
                'status': 'ESTABLISHED',
                'reason': f'Connection to suspicious port'
            }
        }
    
    def generate_high_cpu_event(self):
        """Generate a high CPU usage event."""
        return {
            'timestamp': datetime.now().isoformat(),
            'event_type': 'high_cpu',
            'source': 'system_monitor',
            'severity': 'medium',
            'data': {
                'process_name': 'crypto_miner.exe',
                'pid': random.randint(1000, 9999),
                'cpu_percent': random.uniform(90, 100),
                'threshold': 90,
                'username': 'test_user'
            }
        }
    
    def generate_file_tampering_event(self):
        """Generate a file tampering event."""
        return {
            'timestamp': datetime.now().isoformat(),
            'event_type': 'file_modified',
            'source': 'file_monitor',
            'severity': 'high',
            'data': {
                'file_path': 'C:\\Windows\\System32\\important.dll',
                'operation': 'modified',
                'process_name': 'malware.exe',
                'reason': 'Critical system file modified'
            }
        }
    
    def run_test_scenario(self, scenario_name: str, event_generator):
        """
        Run a test scenario.
        
        Args:
            scenario_name: Name of the test
            event_generator: Function that generates test event
        """
        print(f"Testing: {scenario_name}")
        print("-" * 70)
        
        # Generate event
        event = event_generator()
        print(f"Generated Event: {event['event_type']}")
        
        # Detect threat
        threat = self.rule_engine.check_event(event)
        
        if not threat:
            print("❌ No threat detected (rule didn't match)")
            print()
            return
        
        print(f"✓ Threat Detected: {threat['threat_name']}")
        
        # Calculate risk
        threat = self.risk_scorer.calculate_risk(threat)
        print(f"✓ Risk Calculated: {threat['risk_level']} ({threat['risk_score']:.2f})")
        
        # Generate advisory
        advisory = self.advisor.generate_advisory(threat)
        print(f"✓ Advisory Generated: {advisory['title']}")
        
        # Log to database
        threat_id = self.db.log_threat(threat)
        self.db.log_advisory(threat_id, advisory)
        print(f"✓ Logged to Database (ID: {threat_id})")
        
        # Display advisory
        print()
        print(self.advisor.format_for_display(advisory))
        
        print()
    
    def run_all_tests(self):
        """Run all test scenarios."""
        print("Running all test scenarios...")
        print()
        
        scenarios = [
            ("Suspicious Process Detection", self.generate_suspicious_process_event),
            ("Brute Force Attack", self.generate_brute_force_event),
            ("Suspicious Port Connection", self.generate_suspicious_port_event),
            ("High CPU Usage", self.generate_high_cpu_event),
            ("File Tampering", self.generate_file_tampering_event),
        ]
        
        for name, generator in scenarios:
            self.run_test_scenario(name, generator)
            time.sleep(1)  # Small delay between tests
        
        print("=" * 70)
        print("✓ All tests completed!")
        print("=" * 70)
        print()
        
        # Show statistics
        stats = self.db.get_threat_statistics(hours=1)
        print(f"Threats in Database: {stats['total_threats']}")
        print(f"By Severity: {stats['by_severity']}")
        print()
    
    def test_individual_modules(self):
        """Test individual modules separately."""
        print("Testing Individual Modules")
        print("=" * 70)
        print()
        
        # Test Rule Engine
        print("1. Testing Rule Engine...")
        test_event = self.generate_suspicious_process_event()
        threat = self.rule_engine.check_event(test_event)
        if threat:
            print(f"   ✓ Rule Engine working: {threat['threat_name']}")
        else:
            print("   ❌ Rule Engine: No detection")
        print()
        
        # Test Risk Scorer
        print("2. Testing Risk Scorer...")
        if threat:
            threat = self.risk_scorer.calculate_risk(threat)
            print(f"   ✓ Risk Scorer working: {threat['risk_level']} ({threat['risk_score']:.2f})")
        print()
        
        # Test Advisory Generator
        print("3. Testing Advisory Generator...")
        if threat:
            advisory = self.advisor.generate_advisory(threat)
            print(f"   ✓ Advisory Generator working: {advisory['title']}")
        print()
        
        # Test Database
        print("4. Testing Database...")
        if threat:
            threat_id = self.db.log_threat(threat)
            print(f"   ✓ Database working: Threat logged (ID: {threat_id})")
        print()
        
        print("=" * 70)
        print("✓ Module tests completed!")
        print()


def main():
    """Main test function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Test the Threat Advisor system")
    parser.add_argument('--all', action='store_true', help='Run all test scenarios')
    parser.add_argument('--modules', action='store_true', help='Test individual modules')
    parser.add_argument('--scenario', type=int, help='Run specific scenario (1-5)')
    
    args = parser.parse_args()
    
    simulator = ThreatSimulator()
    
    if args.modules:
        simulator.test_individual_modules()
    elif args.scenario:
        scenarios = [
            ("Suspicious Process Detection", simulator.generate_suspicious_process_event),
            ("Brute Force Attack", simulator.generate_brute_force_event),
            ("Suspicious Port Connection", simulator.generate_suspicious_port_event),
            ("High CPU Usage", simulator.generate_high_cpu_event),
            ("File Tampering", simulator.generate_file_tampering_event),
        ]
        if 1 <= args.scenario <= len(scenarios):
            name, generator = scenarios[args.scenario - 1]
            simulator.run_test_scenario(name, generator)
        else:
            print(f"Invalid scenario number. Choose 1-{len(scenarios)}")
    else:
        # Default: run all tests
        simulator.run_all_tests()


if __name__ == "__main__":
    main()
