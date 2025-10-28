#!/usr/bin/env python3
"""
Web Security Monitoring Dashboard
A legitimate security monitoring tool for your own web applications
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import requests
import ssl
import socket
import smtplib
import json
import threading
import time
from datetime import datetime
from urllib.parse import urlparse
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import certifi
import urllib3

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SecurityMonitor:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Web Security Monitoring Dashboard")
        self.root.geometry("1200x800")
        self.root.configure(bg='#1e1e1e')
        
        # Style configuration
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.configure_styles()
        
        self.results = []
        self.stats = {'passed': 0, 'failed': 0, 'warnings': 0}
        self.is_scanning = False
        
        self.create_widgets()
        
    def configure_styles(self):
        """Configure custom styles"""
        self.style.configure('Title.TLabel', 
                           font=('Arial', 16, 'bold'), 
                           foreground='#00ff88',
                           background='#1e1e1e')
        
        self.style.configure('Header.TLabel',
                           font=('Arial', 12, 'bold'),
                           foreground='#ffffff',
                           background='#1e1e1e')
        
        self.style.configure('Success.TLabel',
                           foreground='#00ff88',
                           background='#1e1e1e')
        
        self.style.configure('Warning.TLabel',
                           foreground='#ffaa00',
                           background='#1e1e1e')
        
        self.style.configure('Error.TLabel',
                           foreground='#ff4444',
                           background='#1e1e1e')
        
        self.style.configure('Custom.TButton',
                           font=('Arial', 10, 'bold'),
                           padding=10)
    
    def create_widgets(self):
        """Create the main GUI widgets"""
        # Title
        title_label = ttk.Label(self.root, 
                               text="🛡️ Web Security Monitoring Dashboard", 
                               style='Title.TLabel')
        title_label.pack(pady=10)
        
        # Main notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Create tabs
        self.create_scan_tab()
        self.create_results_tab()
        self.create_settings_tab()
        self.create_reports_tab()
    
    def create_scan_tab(self):
        """Create the main scanning tab"""
        scan_frame = ttk.Frame(self.notebook)
        self.notebook.add(scan_frame, text="Security Scan")
        
        # URL input section
        url_frame = ttk.LabelFrame(scan_frame, text="Target Configuration", padding=10)
        url_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(url_frame, text="Target URL:").grid(row=0, column=0, sticky='w', pady=5)
        self.url_entry = ttk.Entry(url_frame, width=50, font=('Arial', 11))
        self.url_entry.grid(row=0, column=1, padx=10, pady=5)
        self.url_entry.insert(0, "https://example.com")
        
        # Scan options
        options_frame = ttk.LabelFrame(scan_frame, text="Scan Options", padding=10)
        options_frame.pack(fill='x', padx=10, pady=5)
        
        self.check_vars = {}
        checks = [
            ('ssl_tls', 'SSL/TLS Security'),
            ('headers', 'Security Headers'),
            ('server_info', 'Server Information'),
            ('cookies', 'Cookie Security'),
            ('redirects', 'Redirect Chains'),
            ('cors', 'CORS Configuration')
        ]
        
        for i, (key, label) in enumerate(checks):
            var = tk.BooleanVar(value=True)
            self.check_vars[key] = var
            ttk.Checkbutton(options_frame, text=label, variable=var).grid(
                row=i//2, column=i%2, sticky='w', padx=10, pady=2
            )
        
        # Control buttons
        control_frame = ttk.Frame(scan_frame)
        control_frame.pack(fill='x', padx=10, pady=10)
        
        self.scan_button = ttk.Button(control_frame, text="🔍 Start Scan", 
                                     command=self.start_scan, style='Custom.TButton')
        self.scan_button.pack(side='left', padx=5)
        
        self.stop_button = ttk.Button(control_frame, text="⏹️ Stop Scan", 
                                     command=self.stop_scan, style='Custom.TButton', state='disabled')
        self.stop_button.pack(side='left', padx=5)
        
        # Progress bar
        self.progress = ttk.Progressbar(scan_frame, mode='indeterminate')
        self.progress.pack(fill='x', padx=10, pady=5)
        
        # Status display
        status_frame = ttk.LabelFrame(scan_frame, text="Scan Status", padding=10)
        status_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.status_text = scrolledtext.ScrolledText(status_frame, height=15, 
                                                   bg='#2d2d2d', fg='#ffffff',
                                                   font=('Consolas', 10))
        self.status_text.pack(fill='both', expand=True)
        
    def create_results_tab(self):
        """Create the results tab"""
        results_frame = ttk.Frame(self.notebook)
        self.notebook.add(results_frame, text="Scan Results")
        
        # Statistics frame
        stats_frame = ttk.LabelFrame(results_frame, text="Security Statistics", padding=10)
        stats_frame.pack(fill='x', padx=10, pady=5)
        
        self.stats_labels = {}
        stats_items = [('passed', '✅ Passed', '#00ff88'), 
                      ('warnings', '⚠️ Warnings', '#ffaa00'), 
                      ('failed', '❌ Failed', '#ff4444')]
        
        for i, (key, label, color) in enumerate(stats_items):
            frame = ttk.Frame(stats_frame)
            frame.grid(row=0, column=i, padx=20)
            
            ttk.Label(frame, text=label, font=('Arial', 12, 'bold')).pack()
            self.stats_labels[key] = ttk.Label(frame, text="0", 
                                              font=('Arial', 16, 'bold'))
            self.stats_labels[key].pack()
        
        # Results tree
        tree_frame = ttk.LabelFrame(results_frame, text="Detailed Results", padding=10)
        tree_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Treeview with scrollbars
        tree_container = ttk.Frame(tree_frame)
        tree_container.pack(fill='both', expand=True)
        
        self.results_tree = ttk.Treeview(tree_container, columns=('Status', 'Category', 'Check', 'Details'), show='headings')
        self.results_tree.heading('#1', text='Status')
        self.results_tree.heading('#2', text='Category')
        self.results_tree.heading('#3', text='Check')
        self.results_tree.heading('#4', text='Details')
        
        self.results_tree.column('#1', width=80)
        self.results_tree.column('#2', width=150)
        self.results_tree.column('#3', width=200)
        self.results_tree.column('#4', width=400)
        
        # Scrollbars for treeview
        tree_scroll_y = ttk.Scrollbar(tree_container, orient='vertical', command=self.results_tree.yview)
        tree_scroll_x = ttk.Scrollbar(tree_container, orient='horizontal', command=self.results_tree.xview)
        self.results_tree.configure(yscrollcommand=tree_scroll_y.set, xscrollcommand=tree_scroll_x.set)
        
        self.results_tree.pack(side='left', fill='both', expand=True)
        tree_scroll_y.pack(side='right', fill='y')
        tree_scroll_x.pack(side='bottom', fill='x')
    
    def create_settings_tab(self):
        """Create the settings tab"""
        settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(settings_frame, text="Email Settings")
        
        # Email configuration
        email_frame = ttk.LabelFrame(settings_frame, text="Email Alert Configuration", padding=10)
        email_frame.pack(fill='x', padx=10, pady=5)
        
        self.email_enabled = tk.BooleanVar()
        ttk.Checkbutton(email_frame, text="Enable Email Alerts", 
                       variable=self.email_enabled).grid(row=0, column=0, columnspan=2, sticky='w', pady=5)
        
        # Email settings
        settings = [
            ('Alert Email:', 'alert_email'),
            ('SMTP Server:', 'smtp_server'),
            ('SMTP Port:', 'smtp_port'),
            ('Username:', 'smtp_username'),
            ('Password:', 'smtp_password')
        ]
        
        self.email_entries = {}
        for i, (label, key) in enumerate(settings, 1):
            ttk.Label(email_frame, text=label).grid(row=i, column=0, sticky='w', pady=2)
            entry = ttk.Entry(email_frame, width=40)
            if key == 'smtp_password':
                entry.configure(show='*')
            elif key == 'smtp_port':
                entry.insert(0, '587')
            entry.grid(row=i, column=1, padx=10, pady=2)
            self.email_entries[key] = entry
        
        # Test email button
        ttk.Button(email_frame, text="📧 Test Email Configuration", 
                  command=self.test_email).grid(row=len(settings)+1, column=0, columnspan=2, pady=10)
        
        # Alert thresholds
        threshold_frame = ttk.LabelFrame(settings_frame, text="Alert Thresholds", padding=10)
        threshold_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(threshold_frame, text="Send alert when failed checks exceed:").grid(row=0, column=0, sticky='w')
        self.threshold_var = tk.StringVar(value="5")
        threshold_spin = ttk.Spinbox(threshold_frame, from_=1, to=50, width=10, textvariable=self.threshold_var)
        threshold_spin.grid(row=0, column=1, padx=10)
    
    def create_reports_tab(self):
        """Create the reports tab"""
        reports_frame = ttk.Frame(self.notebook)
        self.notebook.add(reports_frame, text="Reports")
        
        # Report generation
        report_frame = ttk.LabelFrame(reports_frame, text="Generate Reports", padding=10)
        report_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(report_frame, text="📊 Generate HTML Report", 
                  command=self.generate_html_report).pack(side='left', padx=5)
        ttk.Button(report_frame, text="📋 Generate CSV Report", 
                  command=self.generate_csv_report).pack(side='left', padx=5)
        ttk.Button(report_frame, text="📄 Generate JSON Report", 
                  command=self.generate_json_report).pack(side='left', padx=5)
        
        # Report preview
        preview_frame = ttk.LabelFrame(reports_frame, text="Report Preview", padding=10)
        preview_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.report_text = scrolledtext.ScrolledText(preview_frame, bg='#2d2d2d', fg='#ffffff',
                                                   font=('Consolas', 10))
        self.report_text.pack(fill='both', expand=True)
    
    def log_status(self, message, level='INFO'):
        """Add message to status log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        colors = {'INFO': '#ffffff', 'SUCCESS': '#00ff88', 'WARNING': '#ffaa00', 'ERROR': '#ff4444'}
        color = colors.get(level, '#ffffff')
        
        self.status_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.status_text.see(tk.END)
        self.root.update()
    
    def start_scan(self):
        """Start the security scan"""
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a target URL")
            return
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        self.is_scanning = True
        self.scan_button.configure(state='disabled')
        self.stop_button.configure(state='normal')
        self.progress.start()
        
        # Clear previous results
        self.results.clear()
        self.stats = {'passed': 0, 'failed': 0, 'warnings': 0}
        
        # Clear results tree
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # Start scan in separate thread
        scan_thread = threading.Thread(target=self.run_scan, args=(url,))
        scan_thread.daemon = True
        scan_thread.start()
    
    def stop_scan(self):
        """Stop the security scan"""
        self.is_scanning = False
        self.scan_button.configure(state='normal')
        self.stop_button.configure(state='disabled')
        self.progress.stop()
        self.log_status("Scan stopped by user", 'WARNING')
    
    def run_scan(self, url):
        """Run the security scan"""
        self.log_status(f"Starting security scan for: {url}", 'INFO')
        
        try:
            # Parse URL
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # Run selected checks
            if self.check_vars['ssl_tls'].get() and self.is_scanning:
                self.check_ssl_tls(url, domain)
            
            if self.check_vars['headers'].get() and self.is_scanning:
                self.check_security_headers(url)
            
            if self.check_vars['server_info'].get() and self.is_scanning:
                self.check_server_info(url)
            
            if self.check_vars['cookies'].get() and self.is_scanning:
                self.check_cookies(url)
            
            if self.check_vars['redirects'].get() and self.is_scanning:
                self.check_redirects(url)
            
            if self.check_vars['cors'].get() and self.is_scanning:
                self.check_cors(url)
            
            if self.is_scanning:
                self.log_status("Security scan completed", 'SUCCESS')
                self.update_results_display()
                self.check_alert_threshold()
            
        except Exception as e:
            self.log_status(f"Scan error: {str(e)}", 'ERROR')
        finally:
            self.scan_button.configure(state='normal')
            self.stop_button.configure(state='disabled')
            self.progress.stop()
    
    def check_ssl_tls(self, url, domain):
        """Check SSL/TLS configuration"""
        self.log_status("Checking SSL/TLS security...", 'INFO')
        
        try:
            # Check if HTTPS is used
            if url.startswith('https://'):
                self.add_result('SSL/TLS', 'HTTPS Protocol', 'PASS', 'Site uses HTTPS protocol')
            else:
                self.add_result('SSL/TLS', 'HTTPS Protocol', 'FAIL', 'Site does not use HTTPS')
                return
            
            # Get SSL certificate info
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate validity
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.now()).days
                    
                    if days_until_expiry > 30:
                        self.add_result('SSL/TLS', 'Certificate Validity', 'PASS', 
                                      f'Certificate valid for {days_until_expiry} more days')
                    elif days_until_expiry > 0:
                        self.add_result('SSL/TLS', 'Certificate Validity', 'WARNING', 
                                      f'Certificate expires in {days_until_expiry} days')
                    else:
                        self.add_result('SSL/TLS', 'Certificate Validity', 'FAIL', 
                                      'Certificate has expired')
                    
                    # Check TLS version
                    tls_version = ssock.version()
                    if tls_version in ['TLSv1.2', 'TLSv1.3']:
                        self.add_result('SSL/TLS', 'TLS Version', 'PASS', f'Using {tls_version}')
                    else:
                        self.add_result('SSL/TLS', 'TLS Version', 'FAIL', f'Using insecure {tls_version}')
        
        except Exception as e:
            self.add_result('SSL/TLS', 'SSL/TLS Check', 'ERROR', f'SSL check failed: {str(e)}')
    
    def check_security_headers(self, url):
        """Check security headers"""
        self.log_status("Checking security headers...", 'INFO')
        
        try:
            response = requests.get(url, timeout=10, verify=False)
            headers = response.headers
            
            # Define security headers to check
            security_headers = {
                'Content-Security-Policy': 'Prevents XSS and data injection attacks',
                'X-Frame-Options': 'Prevents clickjacking attacks',
                'X-Content-Type-Options': 'Prevents MIME type sniffing',
                'Strict-Transport-Security': 'Forces HTTPS connections',
                'X-XSS-Protection': 'Enables browser XSS filtering',
                'Referrer-Policy': 'Controls referrer information',
                'Permissions-Policy': 'Controls browser feature access'
            }
            
            for header, description in security_headers.items():
                if header in headers:
                    self.add_result('Security Headers', header, 'PASS', 
                                  f'Header present: {headers[header][:100]}')
                else:
                    self.add_result('Security Headers', header, 'FAIL', f'Header missing: {description}')
        
        except Exception as e:
            self.add_result('Security Headers', 'Headers Check', 'ERROR', f'Headers check failed: {str(e)}')
    
    def check_server_info(self, url):
        """Check server information disclosure"""
        self.log_status("Checking server information...", 'INFO')
        
        try:
            response = requests.get(url, timeout=10, verify=False)
            headers = response.headers
            
            # Check server header
            if 'Server' in headers:
                server_info = headers['Server']
                if any(version in server_info.lower() for version in ['apache/2', 'nginx/1', 'iis/']):
                    self.add_result('Server Info', 'Server Banner', 'WARNING', 
                                  f'Server version disclosed: {server_info}')
                else:
                    self.add_result('Server Info', 'Server Banner', 'PASS', 
                                  'Server information properly masked')
            else:
                self.add_result('Server Info', 'Server Banner', 'PASS', 'Server header not disclosed')
            
            # Check for common debug headers
            debug_headers = ['X-Debug', 'X-Debug-Token', 'X-Powered-By']
            for header in debug_headers:
                if header in headers:
                    self.add_result('Server Info', f'{header} Header', 'WARNING', 
                                  f'Debug header present: {headers[header]}')
        
        except Exception as e:
            self.add_result('Server Info', 'Server Info Check', 'ERROR', f'Server check failed: {str(e)}')
    
    def check_cookies(self, url):
        """Check cookie security"""
        self.log_status("Checking cookie security...", 'INFO')
        
        try:
            response = requests.get(url, timeout=10, verify=False)
            cookies = response.cookies
            
            if not cookies:
                self.add_result('Cookies', 'Cookie Security', 'INFO', 'No cookies set by server')
                return
            
            for cookie in cookies:
                cookie_name = cookie.name
                
                # Check Secure flag
                if cookie.secure:
                    self.add_result('Cookies', f'{cookie_name} - Secure', 'PASS', 'Cookie has Secure flag')
                else:
                    self.add_result('Cookies', f'{cookie_name} - Secure', 'FAIL', 'Cookie missing Secure flag')
                
                # Check HttpOnly flag
                if hasattr(cookie, 'httponly') and cookie.httponly:
                    self.add_result('Cookies', f'{cookie_name} - HttpOnly', 'PASS', 'Cookie has HttpOnly flag')
                else:
                    self.add_result('Cookies', f'{cookie_name} - HttpOnly', 'FAIL', 'Cookie missing HttpOnly flag')
        
        except Exception as e:
            self.add_result('Cookies', 'Cookie Check', 'ERROR', f'Cookie check failed: {str(e)}')
    
    def check_redirects(self, url):
        """Check redirect chains"""
        self.log_status("Checking redirect chains...", 'INFO')
        
        try:
            response = requests.get(url, timeout=10, verify=False, allow_redirects=False)
            
            if response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get('Location', '')
                if location.startswith('https://'):
                    self.add_result('Redirects', 'HTTPS Redirect', 'PASS', f'Redirects to HTTPS: {location}')
                elif location.startswith('http://'):
                    self.add_result('Redirects', 'HTTPS Redirect', 'FAIL', f'Redirects to HTTP: {location}')
                else:
                    self.add_result('Redirects', 'HTTPS Redirect', 'WARNING', f'Relative redirect: {location}')
            else:
                self.add_result('Redirects', 'Redirect Check', 'INFO', 'No redirects detected')
        
        except Exception as e:
            self.add_result('Redirects', 'Redirect Check', 'ERROR', f'Redirect check failed: {str(e)}')
    
    def check_cors(self, url):
        """Check CORS configuration"""
        self.log_status("Checking CORS configuration...", 'INFO')
        
        try:
            # Test CORS with OPTIONS request
            headers = {'Origin': 'https://evil.com'}
            response = requests.options(url, headers=headers, timeout=10, verify=False)
            
            cors_headers = response.headers
            
            if 'Access-Control-Allow-Origin' in cors_headers:
                origin = cors_headers['Access-Control-Allow-Origin']
                if origin == '*':
                    self.add_result('CORS', 'Access-Control-Allow-Origin', 'WARNING', 
                                  'CORS allows all origins (*)' )
                elif origin == 'https://evil.com':
                    self.add_result('CORS', 'Access-Control-Allow-Origin', 'FAIL', 
                                  'CORS reflects arbitrary origins')
                else:
                    self.add_result('CORS', 'Access-Control-Allow-Origin', 'PASS', 
                                  f'CORS properly configured: {origin}')
            else:
                self.add_result('CORS', 'Access-Control-Allow-Origin', 'INFO', 'CORS not configured')
        
        except Exception as e:
            self.add_result('CORS', 'CORS Check', 'ERROR', f'CORS check failed: {str(e)}')
    
    def add_result(self, category, check, status, details):
        """Add a result to the results list"""
        result = {
            'category': category,
            'check': check,
            'status': status,
            'details': details,
            'timestamp': datetime.now().isoformat()
        }
        
        self.results.append(result)
        
        # Update statistics
        if status == 'PASS':
            self.stats['passed'] += 1
        elif status == 'FAIL' or status == 'ERROR':
            self.stats['failed'] += 1
        elif status == 'WARNING':
            self.stats['warnings'] += 1
    
    def update_results_display(self):
        """Update the results display"""
        # Update statistics
        for key, label in self.stats_labels.items():
            label.configure(text=str(self.stats[key]))
        
        # Update results tree
        for result in self.results:
            # Color coding
            if result['status'] == 'PASS':
                tag = 'success'
            elif result['status'] in ['FAIL', 'ERROR']:
                tag = 'error'
            elif result['status'] == 'WARNING':
                tag = 'warning'
            else:
                tag = 'info'
            
            self.results_tree.insert('', 'end', values=(
                result['status'],
                result['category'],
                result['check'],
                result['details']
            ), tags=(tag,))
        
        # Configure tags
        self.results_tree.tag_configure('success', foreground='green')
        self.results_tree.tag_configure('error', foreground='red')
        self.results_tree.tag_configure('warning', foreground='orange')
        self.results_tree.tag_configure('info', foreground='blue')
        
        # Generate report preview
        self.generate_report_preview()
    
    def generate_report_preview(self):
        """Generate report preview"""
        self.report_text.delete(1.0, tk.END)
        
        report = f"""
SECURITY MONITORING REPORT
==========================

Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Target: {self.url_entry.get()}

SUMMARY:
--------
✅ Passed: {self.stats['passed']}
⚠️  Warnings: {self.stats['warnings']}  
❌ Failed: {self.stats['failed']}

DETAILED RESULTS:
-----------------
"""
        
        for result in self.results:
            status_symbol = {'PASS': '✅', 'FAIL': '❌', 'WARNING': '⚠️', 'ERROR': '❌', 'INFO': 'ℹ️'}.get(result['status'], '?')
            report += f"\n{status_symbol} {result['category']} - {result['check']}\n"
            report += f"   Status: {result['status']}\n"
            report += f"   Details: {result['details']}\n"
        
        self.report_text.insert(1.0, report)
    
    def check_alert_threshold(self):
        """Check if alert threshold is exceeded"""
        if self.email_enabled.get():
            threshold = int(self.threshold_var.get())
            if self.stats['failed'] >= threshold:
                self.send_email_alert()
    
    def test_email(self):
        """Test email configuration"""
        try:
            email = self.email_entries['alert_email'].get()
            if not email:
                messagebox.showerror("Error", "Please enter an alert email address")
                return
            
            # Create test message
            msg = MIMEText("This is a test email from Web Security Monitor.")
            msg['Subject'] = "Test Alert - Web Security Monitor"
            msg['From'] = self.email_entries['smtp_username'].get()
            msg['To'] = email
            
            # Send email
            server = smtplib.SMTP(self.email_entries['smtp_server'].get(), 
                                int(self.email_entries['smtp_port'].get()))
            server.starttls()
            server.login(self.email_entries['smtp_username'].get(), 
                        self.email_entries['smtp_password'].get())
            server.send_message(msg)
            server.quit()
            
            messagebox.showinfo("Success", "Test email sent successfully!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Email test failed: {str(e)}")
    
    def send_email_alert(self):
        """Send email alert"""
        try:
            if not all(self.email_entries[key].get() for key in ['alert_email', 'smtp_server', 'smtp_username', 'smtp_password']):
                return
            
            # Create alert message
            subject = f"🚨 Security Alert - {self.stats['failed']} issues found"
            
            body = f"""
Security Alert from Web Security Monitor

Target: {self.url_entry.get()}
Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

CRITICAL FINDINGS:
✅ Passed: {self.stats['passed']}
⚠