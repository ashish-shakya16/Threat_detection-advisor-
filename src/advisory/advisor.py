"""
Advisory Generation Module

This module generates human-readable security advisories:
- Converts technical threats to plain language
- Provides step-by-step remediation advice
- Offers context-aware recommendations
- Explains the risk in simple terms

This is a KEY differentiator of our system - we don't just detect,
we advise the user in language they can understand.
"""

import logging
from typing import Dict, Any, List, Optional


class SecurityAdvisor:
    """
    Generates human-readable security advisories for detected threats.
    
    Explanation:
    Traditional security tools show technical alerts like:
    "Rule 001 triggered: process.name=mimikatz.exe, action=blocked"
    
    Our advisor translates to:
    "A dangerous hacking tool was detected on your system. Here's what to do..."
    
    Why this matters:
    - Non-experts can understand the threat
    - Provides actionable steps, not just alerts
    - Reduces alert fatigue
    - Empowers users to respond appropriately
    
    Process:
    1. Take threat + advisory template
    2. Fill in specific details from threat
    3. Customize advice based on risk level
    4. Add remediation steps
    5. Include references for learning
    """
    
    def __init__(self, advisory_templates: Dict[str, Any], config: Dict[str, Any]):
        """
        Initialize security advisor.
        
        Args:
            advisory_templates: Templates for different threat types
            config: Configuration dictionary
        """
        self.templates = advisory_templates
        self.config = config
        self.logger = logging.getLogger('CyberAdvisor.SecurityAdvisor')
        
        # Advisory settings
        advisory_config = config.get('advisory', {})
        self.language = advisory_config.get('language', 'simple')
        self.include_remediation = advisory_config.get('include_remediation', True)
        self.include_examples = advisory_config.get('include_examples', True)
        
        self.logger.info(f"Security Advisor initialized (language: {self.language})")
    
    def generate_advisory(self, threat: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate complete advisory for a threat.
        
        Args:
            threat: Threat dictionary with detection details
        
        Returns:
            Advisory dictionary with title, description, advice, etc.
        """
        # Get template name from threat
        template_name = threat.get('advisory_template')
        
        if not template_name or template_name not in self.templates:
            # Use generic template
            return self._generate_generic_advisory(threat)
        
        template = self.templates[template_name]
        
        # Build advisory from template
        advisory = {
            'threat_id': threat.get('threat_id'),
            'threat_name': threat.get('threat_name'),
            'timestamp': threat.get('timestamp'),
            'risk_level': threat.get('risk_level', 'Unknown'),
            'risk_score': threat.get('risk_score', 0),
            'title': template.get('title', 'Security Alert'),
            'description': template.get('description', ''),
            'advice': template.get('advice', []),
            'remediation': template.get('remediation', '') if self.include_remediation else '',
            'references': template.get('references', []),
            'details': self._format_threat_details(threat)
        }
        
        # Customize based on language preference
        if self.language == 'technical':
            advisory = self._make_technical(advisory, threat)
        elif self.language == 'detailed':
            advisory = self._make_detailed(advisory, threat)
        # 'simple' is default, no changes needed
        
        self.logger.info(f"Advisory generated for {threat.get('threat_name')}")
        
        return advisory
    
    def _generate_generic_advisory(self, threat: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate generic advisory when no template is available.
        
        Args:
            threat: Threat dictionary
        
        Returns:
            Generic advisory
        """
        risk_level = threat.get('risk_level', 'Unknown')
        severity = threat.get('severity', 'medium')
        category = threat.get('category', 'Unknown')
        threat_name = threat.get('threat_name', 'Unknown Threat')
        
        # Enhanced advisories based on threat category and severity
        if category == 'Resource Abuse' or 'CPU' in threat_name or 'Memory' in threat_name:
            summary = f"Your system is experiencing {threat_name.lower()}, which may indicate resource-intensive applications or potential malware activity."
            
            explanation = ("High CPU or memory usage can be caused by legitimate applications, but it can also indicate malicious activity such as cryptomining malware, "
                          "denial-of-service attacks, or system compromise. Sustained high resource usage can degrade system performance and affect other applications.")
            
            recommendations = ("1. Identify the process causing high resource usage using Task Manager\n"
                             "2. Research the process name online to verify if it's legitimate\n"
                             "3. Check if the process corresponds to applications you're actively using\n"
                             "4. Monitor resource usage patterns over time for abnormalities\n"
                             "5. Consider updating or reinstalling applications that consistently consume excessive resources")
            
            remediation_steps = ("• Open Task Manager (Ctrl+Shift+Esc) and sort by CPU or Memory usage\n"
                               "• Right-click suspicious processes and select 'Open File Location' to verify legitimacy\n"
                               "• Terminate suspicious processes and check if they restart automatically\n"
                               "• Run a full system antivirus and anti-malware scan\n"
                               "• Update all software and operating system patches\n"
                               "• Consider using Process Explorer for detailed process analysis\n"
                               "• Review startup programs and disable unnecessary items\n"
                               "• If issue persists, backup data and perform system restore or clean installation")
            
            reference_links = ("Microsoft Process Explorer: https://docs.microsoft.com/en-us/sysinternals/downloads/process-explorer\n"
                             "How to identify malware: https://www.cisa.gov/malware\n"
                             "System performance monitoring: https://support.microsoft.com/windows")
        
        elif category == 'Network Attack' or 'Network' in threat_name or 'Port' in threat_name:
            summary = f"Suspicious network activity detected: {threat_name}. This could indicate unauthorized access attempts or network reconnaissance."
            
            explanation = ("Unusual network connections may indicate port scanning, brute force attacks, data exfiltration, or communication with command-and-control servers. "
                          "These activities are often precursors to more serious security breaches and should be investigated immediately.")
            
            recommendations = ("1. Identify which application or process is making the network connections\n"
                             "2. Verify if the destination IP addresses and ports are legitimate\n"
                             "3. Check firewall logs for patterns of suspicious activity\n"
                             "4. Temporarily disconnect from the network if compromise is suspected\n"
                             "5. Scan for malware and rootkits that may be controlling network traffic")
            
            remediation_steps = ("• Use 'netstat -ano' command to view active network connections and associated processes\n"
                               "• Check firewall settings and enable logging for all blocked connections\n"
                               "• Block suspicious IP addresses and ports in your firewall\n"
                               "• Run network security scanner (nmap, Wireshark) to identify vulnerabilities\n"
                               "• Change all passwords if unauthorized access is confirmed\n"
                               "• Enable two-factor authentication on all accounts\n"
                               "• Monitor network traffic for data exfiltration attempts\n"
                               "• Consider isolating affected systems in a separate network segment")
            
            reference_links = ("NIST Cybersecurity Framework: https://www.nist.gov/cyberframework\n"
                             "Network security best practices: https://www.cisa.gov/network-security\n"
                             "Wireshark documentation: https://www.wireshark.org/docs/")
        
        elif severity == 'high' or risk_level == 'High' or risk_level == 'Critical':
            summary = f"CRITICAL: {threat_name} detected. This is a serious security threat that requires immediate attention to prevent system compromise."
            
            explanation = ("High-severity threats pose significant risk to your system's security, data integrity, and privacy. "
                          "These threats may already have gained unauthorized access or are actively attempting to exploit vulnerabilities. "
                          "Immediate action is required to prevent data loss, system damage, or unauthorized access.")
            
            recommendations = ("1. Immediately isolate the affected system from the network to prevent spread\n"
                             "2. Do not continue using the system for sensitive operations\n"
                             "3. Document all observed symptoms and error messages\n"
                             "4. Run comprehensive malware scans from a clean bootable media\n"
                             "5. Contact your IT security team or a cybersecurity professional\n"
                             "6. Preserve forensic evidence if needed for investigation")
            
            remediation_steps = ("• IMMEDIATE: Disconnect network cable or disable Wi-Fi\n"
                               "• Boot into Safe Mode with Networking\n"
                               "• Run full system scan with updated antivirus and anti-malware tools\n"
                               "• Check for unauthorized user accounts and scheduled tasks\n"
                               "• Review system logs for signs of compromise (Event Viewer)\n"
                               "• Change all passwords from a different, secure device\n"
                               "• Enable Windows Defender or install reputable security software\n"
                               "• Apply all pending security updates and patches\n"
                               "• Consider professional forensic analysis if sensitive data is involved\n"
                               "• Backup critical data before attempting remediation\n"
                               "• If remediation fails, perform clean OS reinstallation")
            
            reference_links = ("CISA Incident Response: https://www.cisa.gov/incident-response\n"
                             "SANS Incident Handler's Handbook: https://www.sans.org/reading-room/whitepapers/incident/incident-handlers-handbook-33901\n"
                             "Microsoft Security Response: https://www.microsoft.com/security")
        
        elif severity == 'medium' or risk_level == 'Medium':
            summary = f"WARNING: {threat_name} requires investigation. This activity is potentially suspicious and may indicate a security concern."
            
            explanation = ("Medium-severity threats may not pose immediate danger but should be investigated to determine if they represent "
                          "legitimate activity or early stages of an attack. These threats could escalate if not addressed properly.")
            
            recommendations = ("1. Verify if this activity corresponds to your normal system usage\n"
                             "2. Review recent software installations and system changes\n"
                             "3. Check for unauthorized modifications to system files or registry\n"
                             "4. Monitor the situation for escalation or repeated occurrences\n"
                             "5. Run routine security scans to ensure no compromise has occurred")
            
            remediation_steps = ("• Review the threat details and identify the source application/process\n"
                               "• Check if recent software updates or installations caused this alert\n"
                               "• Verify system integrity using 'sfc /scannow' command\n"
                               "• Update antivirus definitions and run a full scan\n"
                               "• Review installed programs and remove any unfamiliar software\n"
                               "• Check browser extensions and remove suspicious ones\n"
                               "• Enable real-time protection and automatic updates\n"
                               "• Document the incident for future reference")
            
            reference_links = ("Windows System File Checker: https://support.microsoft.com/sfc\n"
                             "Security baseline recommendations: https://docs.microsoft.com/security\n"
                             "Threat detection guide: https://www.cisa.gov/cybersecurity-best-practices")
        
        else:
            summary = f"INFORMATIONAL: {threat_name} detected. This is a low-priority alert for your awareness."
            
            explanation = ("Low-severity alerts are informational and typically indicate minor anomalies or behaviors that deviate slightly from normal patterns. "
                          "While they don't require immediate action, it's good practice to be aware of these events.")
            
            recommendations = ("1. Review the activity details to understand what triggered this alert\n"
                             "2. Verify that this behavior is expected for your system usage\n"
                             "3. No immediate action required unless you notice patterns of suspicious activity\n"
                             "4. Continue normal operations while maintaining security awareness\n"
                             "5. Keep your security software updated for ongoing protection")
            
            remediation_steps = ("• Review the technical details of this alert in the dashboard\n"
                               "• Ensure all security software is up-to-date and functioning\n"
                               "• Perform regular system maintenance and updates\n"
                               "• Monitor for any escalation or repeated occurrences\n"
                               "• Maintain good security hygiene (strong passwords, regular backups)\n"
                               "• No immediate remediation required")
            
            reference_links = ("Security awareness training: https://www.cisa.gov/cybersecurity-training\n"
                             "Best practices guide: https://www.nist.gov/cybersecurity\n"
                             "Stay informed: https://us-cert.cisa.gov/ncas/tips")
        
        return {
            'threat_id': threat.get('threat_id'),
            'threat_name': threat_name,
            'timestamp': threat.get('timestamp'),
            'risk_level': risk_level,
            'risk_score': threat.get('risk_score', 0),
            'summary': summary,
            'explanation': explanation,
            'recommendations': recommendations,
            'remediation_steps': remediation_steps,
            'reference_links': reference_links
        }
    
    def _format_threat_details(self, threat: Dict[str, Any]) -> str:
        """
        Format threat details into readable text.
        
        Args:
            threat: Threat dictionary
        
        Returns:
            Formatted details string
        """
        details = []
        
        # Basic info
        details.append(f"Threat Type: {threat.get('category', 'Unknown')}")
        details.append(f"Severity: {threat.get('severity', 'Unknown')}")
        details.append(f"Confidence: {threat.get('confidence', 0) * 100:.0f}%")
        
        # Event data
        event_data = threat.get('event_data', {})
        if 'process_name' in event_data:
            details.append(f"Process: {event_data['process_name']}")
        if 'pid' in event_data:
            details.append(f"Process ID: {event_data['pid']}")
        if 'remote_ip' in event_data:
            details.append(f"Remote IP: {event_data['remote_ip']}")
        if 'remote_port' in event_data:
            details.append(f"Remote Port: {event_data['remote_port']}")
        if 'file_path' in event_data:
            details.append(f"File: {event_data['file_path']}")
        
        # Source
        details.append(f"Detected by: {threat.get('source', 'Unknown')}")
        
        return "\n".join(details)
    
    def _make_technical(self, advisory: Dict[str, Any], threat: Dict[str, Any]) -> Dict[str, Any]:
        """
        Add technical details to advisory.
        
        Args:
            advisory: Base advisory
            threat: Threat data
        
        Returns:
            Enhanced advisory with technical details
        """
        # Add rule ID and detection method
        tech_info = f"\n\nTechnical Details:\n"
        tech_info += f"- Detection Rule: {threat.get('rule_matched', 'N/A')}\n"
        tech_info += f"- Detection Method: Rule-based matching\n"
        tech_info += f"- Event Type: {threat.get('event_data', {}).get('event_type', 'Unknown')}\n"
        
        advisory['description'] += tech_info
        
        return advisory
    
    def _make_detailed(self, advisory: Dict[str, Any], threat: Dict[str, Any]) -> Dict[str, Any]:
        """
        Add detailed explanations to advisory.
        
        Args:
            advisory: Base advisory
            threat: Threat data
        
        Returns:
            Enhanced advisory with detailed explanations
        """
        # Add "What this means" section
        explanations = {
            'Malware': "Malware (malicious software) is any program designed to harm your computer or steal your data.",
            'Brute Force': "A brute force attack tries many passwords rapidly to break into your account.",
            'Network Attack': "Network attacks target your internet connection to gain unauthorized access.",
            'Resource Abuse': "Resource abuse occurs when programs consume excessive CPU or memory, possibly for cryptocurrency mining.",
            'File Tampering': "File tampering means critical system files have been modified, potentially compromising security.",
            'Network Scan': "Network scanning is a reconnaissance technique used to find vulnerable systems.",
            'Privilege Escalation': "Privilege escalation is when a program tries to gain higher-level access than it should have.",
            'Script Attack': "Script attacks use automated scripts to exploit system vulnerabilities.",
            'Data Theft': "Data theft involves unauthorized copying or transfer of sensitive information.",
            'Code Injection': "Code injection is an advanced attack where malicious code is inserted into running programs."
        }
        
        category = threat.get('category', '')
        if category in explanations:
            advisory['description'] += f"\n\nWhat this means: {explanations[category]}"
        
        return advisory
    
    def format_for_display(self, advisory: Dict[str, Any]) -> str:
        """
        Format advisory as readable text for console/dashboard.
        
        Args:
            advisory: Advisory dictionary
        
        Returns:
            Formatted advisory text
        """
        output = []
        
        # Header
        output.append("=" * 70)
        output.append(f"🚨 {advisory['title']}")
        output.append(f"Risk Level: {advisory['risk_level']} (Score: {advisory['risk_score']:.2f})")
        output.append("=" * 70)
        output.append("")
        
        # Description
        output.append("What happened:")
        output.append(advisory['description'])
        output.append("")
        
        # Advice
        output.append("What you should do:")
        for i, advice_item in enumerate(advisory['advice'], 1):
            output.append(f"  {i}. {advice_item}")
        output.append("")
        
        # Remediation
        if advisory.get('remediation'):
            output.append("Technical Remediation:")
            output.append(f"  {advisory['remediation']}")
            output.append("")
        
        # Details
        if advisory.get('details'):
            output.append("Technical Details:")
            for line in advisory['details'].split('\n'):
                output.append(f"  {line}")
            output.append("")
        
        # References
        if advisory.get('references'):
            output.append("References:")
            for ref in advisory['references']:
                output.append(f"  - {ref}")
            output.append("")
        
        output.append("=" * 70)
        
        return "\n".join(output)
    
    def generate_summary_advisory(self, threats: List[Dict[str, Any]]) -> str:
        """
        Generate summary advisory for multiple threats.
        
        Args:
            threats: List of threat dictionaries
        
        Returns:
            Summary advisory text
        """
        if not threats:
            return "No threats detected. System appears secure."
        
        # Count by severity
        high = sum(1 for t in threats if t.get('risk_level') == 'High' or t.get('risk_level') == 'Critical')
        medium = sum(1 for t in threats if t.get('risk_level') == 'Medium')
        low = sum(1 for t in threats if t.get('risk_level') == 'Low')
        
        summary = []
        summary.append("=" * 70)
        summary.append("🛡️  SECURITY SUMMARY")
        summary.append("=" * 70)
        summary.append(f"Total Threats Detected: {len(threats)}")
        summary.append(f"  - High/Critical Risk: {high}")
        summary.append(f"  - Medium Risk: {medium}")
        summary.append(f"  - Low Risk: {low}")
        summary.append("")
        
        if high > 0:
            summary.append("⚠️  URGENT: High-risk threats require immediate attention!")
            summary.append("   Review high-severity threats first.")
        elif medium > 0:
            summary.append("⚠️  WARNING: Medium-risk threats detected.")
            summary.append("   Investigation recommended.")
        else:
            summary.append("✓  Only low-risk threats detected.")
            summary.append("   System is relatively secure.")
        
        summary.append("=" * 70)
        
        return "\n".join(summary)


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    test_templates = {
        'suspicious_process': {
            'title': 'Suspicious Program Detected',
            'description': 'A potentially harmful program was found running on your system.',
            'advice': [
                'Immediately close the suspicious program',
                'Run a full antivirus scan',
                'Check if this was intentionally installed'
            ],
            'remediation': 'Terminate process and remove executable',
            'references': ['MITRE ATT&CK: T1059']
        }
    }
    
    test_config = {
        'advisory': {
            'language': 'simple',
            'include_remediation': True,
            'include_examples': True
        }
    }
    
    advisor = SecurityAdvisor(test_templates, test_config)
    
    test_threat = {
        'threat_id': 'RULE_001',
        'threat_name': 'Suspicious Process',
        'category': 'Malware',
        'severity': 'high',
        'risk_level': 'High',
        'risk_score': 0.85,
        'advisory_template': 'suspicious_process',
        'event_data': {
            'process_name': 'mimikatz.exe',
            'pid': 1234
        }
    }
    
    advisory = advisor.generate_advisory(test_threat)
    print(advisor.format_for_display(advisory))
