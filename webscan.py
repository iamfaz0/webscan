#!/usr/bin/env python3
"""
WEBSCAN - Advanced Website Security Scanner
Version 3.0 - With JS Recon, Subdomain Enumeration, and Advanced Features
"""

import os
import sys
import requests
from bs4 import BeautifulSoup
import socket
import whois
import dns.resolver
import argparse
from datetime import datetime
import time
import json
from urllib.parse import urlparse, urljoin
import nmap
import sqlite3
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
from colorama import init, Fore, Style
import readline
import jsbeautifier
import hashlib
from tldextract import extract
import urllib3
from collections import defaultdict
import threading

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama
init(autoreset=True)

# Global variables
nm = nmap.PortScanner()
scan_lock = threading.Lock()

# ============================================
# BANNER & UI
# ============================================

def banner():
    print(Fore.CYAN + r"""
     __      __   _______   _______   _______   _______   __   __ 
    |  |    |  | |       | |       | |       | |       | |  | |  |
    |  |    |  | |  _____| |  _____| |    ___| |    ___| |  |_|  |
    |  |    |  | | |_____  | |_____  |   |___  |   |___  |       |
    |  |    |  | |_____  | |_____  | |    ___| |    ___| |       |
    |  |___ |  |  _____| |  _____| | |   |___  |   |___  |   _   |
    |_______||__| |_______| |_______| |_______| |_______| |__| |__|
    """)
    print(Fore.YELLOW + " " * 15 + "WEBSCAN - Advanced Website Scanner")
    print(Fore.YELLOW + " " * 20 + "Developed By iamfazo")
    print(Fore.RED + " " * 20 + "[!] For authorized security testing only\n")

# ============================================
# DATABASE INITIALIZATION (UPDATED)
# ============================================

def init_db():
    """Initialize database with new tables"""
    conn = sqlite3.connect('webscan.db')
    c = conn.cursor()
    
    # Main scans table
    c.execute('''CREATE TABLE IF NOT EXISTS scans
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  url TEXT,
                  ip TEXT,
                  cms TEXT,
                  database TEXT,
                  estimated_users INTEGER,
                  scan_date TEXT,
                  ports TEXT,
                  vulnerabilities TEXT,
                  risk_score INTEGER)''')
    
    # JS findings table
    c.execute('''CREATE TABLE IF NOT EXISTS js_findings
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  scan_id INTEGER,
                  js_url TEXT,
                  finding_type TEXT,
                  finding_value TEXT,
                  severity TEXT)''')
    
    # Subdomains table
    c.execute('''CREATE TABLE IF NOT EXISTS subdomains
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  scan_id INTEGER,
                  subdomain TEXT,
                  ip TEXT,
                  status TEXT)''')
    
    # Technologies table
    c.execute('''CREATE TABLE IF NOT EXISTS technologies
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  scan_id INTEGER,
                  category TEXT,
                  tech_name TEXT)''')
    
    conn.commit()
    conn.close()

def save_scan(url, ip, cms, database, estimated_users, ports, vulnerabilities, risk_score=0):
    """Save scan results to database"""
    conn = sqlite3.connect('webscan.db')
    c = conn.cursor()
    c.execute("INSERT INTO scans (url, ip, cms, database, estimated_users, scan_date, ports, vulnerabilities, risk_score) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
              (url, ip, cms, database, estimated_users, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ports, vulnerabilities, risk_score))
    scan_id = c.lastrowid
    conn.commit()
    conn.close()
    return scan_id

def save_js_finding(scan_id, js_url, finding_type, finding_value, severity):
    """Save JS findings to database"""
    conn = sqlite3.connect('webscan.db')
    c = conn.cursor()
    c.execute("INSERT INTO js_findings (scan_id, js_url, finding_type, finding_value, severity) VALUES (?, ?, ?, ?, ?)",
              (scan_id, js_url, finding_type, finding_value, severity))
    conn.commit()
    conn.close()

def save_subdomain(scan_id, subdomain, ip, status):
    """Save subdomain to database"""
    conn = sqlite3.connect('webscan.db')
    c = conn.cursor()
    c.execute("INSERT INTO subdomains (scan_id, subdomain, ip, status) VALUES (?, ?, ?, ?)",
              (scan_id, subdomain, ip, status))
    conn.commit()
    conn.close()

def save_technology(scan_id, category, tech_name):
    """Save technology to database"""
    conn = sqlite3.connect('webscan.db')
    c = conn.cursor()
    c.execute("INSERT INTO technologies (scan_id, category, tech_name) VALUES (?, ?, ?)",
              (scan_id, category, tech_name))
    conn.commit()
    conn.close()

# ============================================
# JS RECONNAISSANCE CLASS
# ============================================

class JSRecon:
    def __init__(self, url, scan_id=None):
        self.url = url
        self.domain = urlparse(url).netloc
        self.js_files = []
        self.scan_id = scan_id
        self.findings = {
            'api_keys': [],
            'endpoints': [],
            'secrets': [],
            'tokens': [],
            'aws_keys': [],
            'google_keys': [],
            'firebase_configs': [],
            'jwt_secrets': [],
            'webhooks': [],
            'database_urls': []
        }
    
    # Enhanced patterns for detecting sensitive data
    PATTERNS = {
        'api_keys': [
            r'api[_-]?key[\s]*[:=][\s]*["\']([a-zA-Z0-9_\-]{16,64})["\']',
            r'apikey[\s]*[:=][\s]*["\']([a-zA-Z0-9_\-]{16,64})["\']',
            r'API_KEY[\s]*[:=][\s]*["\']([^"\'\s]{16,})["\']',
            r'["\']key["\']\s*:\s*["\']([a-zA-Z0-9]{32,})["\']',
        ],
        'aws_keys': [
            r'AKIA[0-9A-Z]{16}',
            r'AWS[\s]*ACCESS[\s]*KEY[\s]*[:=][\s]*["\']([A-Z0-9]{20})["\']',
            r'aws_access_key_id[\s]*=[\s]*["\']([A-Z0-9]{20})["\']',
            r'AWS_SECRET_ACCESS_KEY[\s]*[:=][\s]*["\']([^"\'\s]{40})["\']',
        ],
        'google_keys': [
            r'AIza[0-9A-Za-z\-_]{35}',
            r'google[\s]*api[\s]*key[\s]*[:=][\s]*["\']([\w\-]{39})["\']',
            r'GOOGLE_API_KEY[\s]*[:=][\s]*["\']([^"\'\s]{39})["\']',
        ],
        'firebase_configs': [
            r'firebase\.initializeApp\({[^}]*apiKey:\s*"([^"]+)"',
            r'FIREBASE_API_KEY[\s]*[:=][\s]*["\']([^"\']+)["\']',
            r'firebaseConfig\s*=\s*{[^}]*apiKey:\s*"([^"]+)"',
            r'projectId:\s*"([^"]+)"[^}]*authDomain:\s*"([^"]+)"',
        ],
        'jwt_secrets': [
            r'eyJ[a-zA-Z0-9\-_]{10,}\.eyJ[a-zA-Z0-9\-_]{10,}\.[a-zA-Z0-9\-_]{10,}',
            r'secret[\s]*[:=][\s]*["\']([a-zA-Z0-9]{32,})["\']',
            r'JWT_SECRET[\s]*[:=][\s]*["\']([^"\'\s]{32,})["\']',
        ],
        'endpoints': [
            r'["\'](/api/[a-zA-Z0-9/_-]{3,})["\']',
            r'["\'](https?://[^"\']*api[^"\']*)["\']',
            r'["\'](/v\d/[a-zA-Z0-9/_-]{3,})["\']',
            r'["\'](https?://[^"\']*graphql[^"\']*)["\']',
            r'["\'](/rest/[a-zA-Z0-9/_-]{3,})["\']',
            r'\.get\(["\']([^"\']+)["\']\)',
            r'\.post\(["\']([^"\']+)["\']\)',
        ],
        'webhooks': [
            r'webhook[_\s]*url[\s]*[:=][\s]*["\'](https?://[^"\']+)["\']',
            r'discord\.com/api/webhooks/[a-zA-Z0-9_-]+',
            r'slack\.com/services/[A-Z0-9]+',
            r'webhook\.site/[a-zA-Z0-9]+',
        ],
        'database_urls': [
            r'mongodb(?:\+srv)?://[^"\'\s]+',
            r'postgresql://[^"\'\s]+',
            r'mysql://[^"\'\s]+',
            r'redis://[^"\'\s]+',
            r'sqlite:///[^"\'\s]+',
            r'DATABASE_URL[\s]*[:=][\s]*["\']([^"\']+)["\']',
        ],
        'access_tokens': [
            r'access_token[\s]*[:=][\s]*["\']([a-zA-Z0-9_\-]{20,})["\']',
            r'token[\s]*[:=][\s]*["\']([a-zA-Z0-9_\-]{20,})["\']',
            r'Authorization[\s]*:[\s]*["\']Bearer\s+([a-zA-Z0-9_\-\.]+)["\']',
        ],
        'private_keys': [
            r'-----BEGIN RSA PRIVATE KEY-----',
            r'-----BEGIN DSA PRIVATE KEY-----',
            r'-----BEGIN EC PRIVATE KEY-----',
            r'-----BEGIN OPENSSH PRIVATE KEY-----',
        ],
        'email_addresses': [
            r'[\w\.-]+@[\w\.-]+\.\w+',
        ]
    }
    
    def discover_js_files(self):
        """Discover JS files from HTML and common paths"""
        js_files = set()
        
        try:
            # Get HTML and parse script tags
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            resp = requests.get(self.url, timeout=15, headers=headers, verify=False)
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            # Find all script tags
            for script in soup.find_all('script', src=True):
                js_url = urljoin(self.url, script['src'])
                if js_url.endswith('.js'):
                    js_files.add(js_url)
            
            # Find inline JS blocks
            for script in soup.find_all('script'):
                if script.string:
                    self.analyze_inline_js(script.string, self.url)
            
            # Common JS file paths to check
            common_paths = [
                'static/js/main.js', 'assets/js/app.js', 'js/app.js',
                'build/static/js/main.js', 'dist/bundle.js', 'js/main.js',
                'javascript/app.js', 'scripts/main.js', 'assets/index.js',
                'static/js/bundle.js', 'js/scripts.js', 'js/custom.js',
                'wp-content/themes/*/js/*.js', 'assets/javascripts/*.js'
            ]
            
            for path in common_paths:
                test_url = urljoin(self.url, path)
                try:
                    r = requests.head(test_url, timeout=5, headers=headers, verify=False)
                    if r.status_code == 200:
                        js_files.add(test_url)
                except:
                    pass
            
            # Check for source maps
            source_map_patterns = ['js.map', 'map.js', '.map']
            for js_file in list(js_files):
                for pattern in source_map_patterns:
                    map_url = js_file + '.map'
                    try:
                        r = requests.head(map_url, timeout=3)
                        if r.status_code == 200:
                            js_files.add(map_url)
                    except:
                        pass
                    
        except Exception as e:
            print(Fore.RED + f"[!] Error discovering JS: {e}")
        
        self.js_files = list(js_files)
        return self.js_files
    
    def analyze_inline_js(self, js_content, source_url):
        """Analyze inline JavaScript code"""
        self._apply_patterns(js_content, source_url)
    
    def analyze_js_file(self, js_url):
        """Analyze a single JS file for sensitive data"""
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            resp = requests.get(js_url, timeout=20, headers=headers, verify=False)
            if resp.status_code != 200:
                return
            
            content = resp.text
            
            # Beautify JS for better analysis
            try:
                beautified = jsbeautifier.beautify(content)
                content = beautified
            except:
                pass
            
            self._apply_patterns(content, js_url)
            
            # Check for source map reference
            source_map_match = re.search(r'//# sourceMappingURL=(.+\.map)', content)
            if source_map_match:
                map_url = urljoin(js_url, source_map_match.group(1))
                try:
                    map_resp = requests.get(map_url, timeout=10)
                    if map_resp.status_code == 200:
                        self._apply_patterns(map_resp.text, map_url)
                except:
                    pass
                    
        except Exception as e:
            pass  # Silent fail to avoid clutter
    
    def _apply_patterns(self, content, source_url):
        """Apply all regex patterns to content"""
        for category, patterns in self.PATTERNS.items():
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    # Handle tuple matches
                    if isinstance(match, tuple):
                        match = ' | '.join([str(m) for m in match if m])
                    if match and len(str(match)) > 3:
                        # Filter out false positives
                        if self._is_valid_finding(str(match), category):
                            finding = {
                                'url': source_url,
                                'value': str(match)[:200],
                                'category': category
                            }
                            if category in self.findings:
                                self.findings[category].append(finding)
                            
                            # Save to database if scan_id exists
                            if self.scan_id:
                                severity = self._get_severity(category)
                                save_js_finding(self.scan_id, source_url, category, str(match)[:200], severity)
    
    def _is_valid_finding(self, value, category):
        """Filter out false positives"""
        invalid_patterns = [
            r'^function', r'^var ', r'^const ', r'^let ', r'^return',
            r'^console\.', r'^document\.', r'^window\.', r'^alert\(',
            r'^if\(', r'^for\(', r'^while\(', r'^switch\(', r'^try{',
            r'^null$', r'^undefined$', r'^true$', r'^false$', r'^\[\]$',
            r'^\{\}$', r'^$'
        ]
        
        for pattern in invalid_patterns:
            if re.match(pattern, value, re.IGNORECASE):
                return False
        
        # Specific category filters
        if category == 'email_addresses' and len(value) > 50:
            return False
        
        if category == 'endpoints' and len(value) < 5:
            return False
        
        return True
    
    def _get_severity(self, category):
        """Get severity level for finding category"""
        severity_map = {
            'private_keys': 'CRITICAL',
            'aws_keys': 'CRITICAL',
            'database_urls': 'CRITICAL',
            'jwt_secrets': 'HIGH',
            'access_tokens': 'HIGH',
            'api_keys': 'HIGH',
            'google_keys': 'HIGH',
            'webhooks': 'MEDIUM',
            'firebase_configs': 'MEDIUM',
            'endpoints': 'LOW',
            'email_addresses': 'LOW'
        }
        return severity_map.get(category, 'MEDIUM')
    
    def run_full_recon(self):
        """Execute full JS reconnaissance"""
        print(Fore.CYAN + "\n" + "="*60)
        print(Fore.CYAN + " JAVASCRIPT RECONNAISSANCE")
        print(Fore.CYAN + "="*60)
        
        # Discover JS files
        self.discover_js_files()
        print(Fore.GREEN + f"[+] Found {len(self.js_files)} JavaScript files")
        
        if self.js_files:
            print(Fore.YELLOW + "[~] Analyzing JavaScript files...")
            
            # Analyze each JS file
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(self.analyze_js_file, js_url) for js_url in self.js_files]
                for future in as_completed(futures):
                    try:
                        future.result()
                    except:
                        pass
        
        return self.generate_report()
    
    def generate_report(self):
        """Generate detailed report of findings"""
        report = {
            'total_js_files': len(self.js_files),
            'sensitive_findings': {},
            'api_endpoints': [],
            'risk_score': 0,
            'findings_by_severity': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        }
        
        # Count findings by category
        for category, findings in self.findings.items():
            if findings:
                unique_values = list(set([f['value'] for f in findings]))
                report['sensitive_findings'][category] = {
                    'count': len(findings),
                    'unique_count': len(unique_values),
                    'examples': unique_values[:5]
                }
                
                # Update severity counts
                for finding in findings[:10]:
                    severity = self._get_severity(category)
                    report['findings_by_severity'][severity] += 1
        
        # Calculate risk score
        risk_weights = {
            'private_keys': 10,
            'aws_keys': 10,
            'database_urls': 10,
            'jwt_secrets': 9,
            'access_tokens': 8,
            'api_keys': 7,
            'google_keys': 8,
            'webhooks': 5,
            'firebase_configs': 6,
            'endpoints': 2,
            'email_addresses': 1
        }
        
        total_risk = 0
        for category, data in report['sensitive_findings'].items():
            weight = risk_weights.get(category, 3)
            total_risk += data['count'] * weight
        
        report['risk_score'] = min(100, total_risk)
        
        return report
    
    def display_results(self):
        """Display JS recon results"""
        report = self.generate_report()
        
        print(Fore.CYAN + "\n" + "="*60)
        print(Fore.CYAN + " JS RECON RESULTS")
        print(Fore.CYAN + "="*60)
        
        print(Fore.GREEN + f"[+] JS Files Analyzed: {report['total_js_files']}")
        print(Fore.GREEN + f"[+] Risk Score: {report['risk_score']}/100")
        
        # Severity breakdown
        print(Fore.YELLOW + "\n[~] Findings by Severity:")
        for severity, count in report['findings_by_severity'].items():
            color = Fore.RED if severity == 'CRITICAL' else Fore.YELLOW if severity == 'HIGH' else Fore.CYAN
            print(color + f"    {severity}: {count}")
        
        if report['sensitive_findings']:
            print(Fore.RED + "\n[!] SENSITIVE DATA FOUND:")
            for category, data in report['sensitive_findings'].items():
                color = Fore.RED if data['count'] > 0 else Fore.GREEN
                print(color + f"\n    [{category.upper()}] - {data['count']} occurrences")
                for example in data['examples'][:3]:
                    print(Fore.YELLOW + f"      → {example[:100]}")
        else:
            print(Fore.GREEN + "\n[+] No sensitive data found in JavaScript files")
        
        return report

# ============================================
# SUBDOMAIN ENUMERATION
# ============================================

def enumerate_subdomains(domain, scan_id=None):
    """Enumerate subdomains using multiple sources"""
    print(Fore.CYAN + "\n" + "="*60)
    print(Fore.CYAN + " SUBDOMAIN ENUMERATION")
    print(Fore.CYAN + "="*60)
    
    subdomains = set()
    
    # Common subdomain wordlist (expanded)
    common_subdomains = [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
        'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'api', 'blog', 'docs',
        'shop', 'test', 'dev', 'staging', 'admin', 'portal', 'app', 'secure', 'vpn',
        'cdn', 'static', 'media', 'assets', 'img', 'video', 'download', 'support',
        'status', 'dashboard', 'accounts', 'auth', 'login', 'signup', 'register',
        'm', 'mobile', 'partner', 'gateway', 'remote', 'backend', 'database', 'sql',
        'redis', 'cache', 'monitor', 'logs', 'backup', 'archive', 'old', 'new',
        'demo', 'stage', 'prod', 'production', 'development', 'test2', 'sandbox',
        'beta', 'alpha', 'edge', 'preview', 'web', 'site', 'server', 'cloud',
        'storage', 'files', 'upload', 'image', 'images', 'css', 'js', 'fonts',
        'analytics', 'metrics', 'stats', 'report', 'reports', 'jenkins', 'gitlab',
        'github', 'bitbucket', 'jira', 'confluence', 'wiki', 'kb', 'knowledge',
        'docs', 'documentation', 'api2', 'api3', 'rest', 'soap', 'graphql'
    ]
    
    # DNS brute force
    print(Fore.YELLOW + "[~] Performing DNS brute force...")
    
    def check_subdomain(sub):
        test_domain = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(test_domain)
            if scan_id:
                save_subdomain(scan_id, test_domain, ip, 'resolved')
            return test_domain
        except:
            return None
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(check_subdomain, sub) for sub in common_subdomains]
        for future in as_completed(futures):
            result = future.result()
            if result:
                subdomains.add(result)
                print(Fore.GREEN + f"[+] Found: {result}")
    
    # Try to get from crt.sh
    print(Fore.YELLOW + "[~] Checking certificate transparency logs...")
    try:
        resp = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                name = entry.get('name_value', '')
                if name and name.endswith(domain):
                    for sub in name.split('\n'):
                        sub = sub.strip()
                        if sub and sub.endswith(domain):
                            subdomains.add(sub)
                            if scan_id:
                                save_subdomain(scan_id, sub, 'unknown', 'certificate')
    except Exception as e:
        print(Fore.RED + f"[!] crt.sh lookup failed: {e}")
    
    # Try SecurityTrails (if API key available - you can add yours)
    # securitytrails_api_key = os.getenv('SECURITYTRAILS_API_KEY')
    # if securitytrails_api_key:
    #     try:
    #         headers = {'APIKEY': securitytrails_api_key}
    #         resp = requests.get(f"https://api.securitytrails.com/v1/domain/{domain}/subdomains", headers=headers)
    #         if resp.status_code == 200:
    #             data = resp.json()
    #             for sub in data.get('subdomains', []):
    #                 subdomains.add(f"{sub}.{domain}")
    #     except:
    #         pass
    
    print(Fore.GREEN + f"\n[+] Total subdomains found: {len(subdomains)}")
    return list(subdomains)

# ============================================
# TECHNOLOGY STACK DETECTION
# ============================================

def detect_technologies(url, scan_id=None):
    """Detect frameworks, libraries, and technologies"""
    print(Fore.CYAN + "\n" + "="*60)
    print(Fore.CYAN + " TECHNOLOGY STACK DETECTION")
    print(Fore.CYAN + "="*60)
    
    tech_stack = {
        'frontend': set(),
        'backend': set(),
        'databases': set(),
        'analytics': set(),
        'cdn': set(),
        'security': set(),
        'hosting': set(),
        'cms': set()
    }
    
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        resp = requests.get(url, timeout=15, headers=headers, verify=False)
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        # Check headers
        server = resp.headers.get('Server', '')
        if server:
            tech_stack['backend'].add(f"Server: {server}")
            print(Fore.GREEN + f"[+] Server: {server}")
        
        x_powered = resp.headers.get('X-Powered-By', '')
        if x_powered:
            tech_stack['backend'].add(f"X-Powered-By: {x_powered}")
            print(Fore.GREEN + f"[+] X-Powered-By: {x_powered}")
        
        # Check for JS libraries
        scripts = soup.find_all('script', src=True)
        for script in scripts:
            src = script['src'].lower()
            if 'jquery' in src:
                tech_stack['frontend'].add('jQuery')
            elif 'react' in src:
                tech_stack['frontend'].add('React')
            elif 'angular' in src:
                tech_stack['frontend'].add('Angular')
            elif 'vue' in src:
                tech_stack['frontend'].add('Vue.js')
            elif 'bootstrap' in src:
                tech_stack['frontend'].add('Bootstrap')
            elif 'tailwind' in src:
                tech_stack['frontend'].add('Tailwind CSS')
            elif 'fontawesome' in src:
                tech_stack['frontend'].add('FontAwesome')
        
        # Check meta tags
        generator = soup.find('meta', attrs={'name': 'generator'})
        if generator:
            tech_stack['cms'].add(generator.get('content', ''))
        
        # Check for CDN
        cdn_patterns = {
            'cloudflare': ['cloudflare', 'cf-ray'],
            'cloudfront': ['cloudfront', 'amazonaws.com/cloudfront'],
            'fastly': ['fastly'],
            'akamai': ['akamai', 'akamaiedge'],
            'incapsula': ['incapsula']
        }
        
        for cdn, patterns in cdn_patterns.items():
            for pattern in patterns:
                if pattern in resp.text.lower() or pattern in str(resp.headers).lower():
                    tech_stack['cdn'].add(cdn)
        
        # Check for analytics
        analytics_patterns = {
            'Google Analytics': ['google-analytics', 'ga.js', 'gtag'],
            'Facebook Pixel': ['facebook.com/tr', 'fbq'],
            'Hotjar': ['hotjar'],
            'Mixpanel': ['mixpanel'],
            'Segment': ['segment']
        }
        
        for analytic, patterns in analytics_patterns.items():
            for pattern in patterns:
                if pattern in resp.text.lower():
                    tech_stack['analytics'].add(analytic)
        
        # Display results
        for category, techs in tech_stack.items():
            if techs:
                print(Fore.GREEN + f"\n[{category.upper()}]")
                for tech in techs:
                    print(Fore.CYAN + f"  → {tech}")
                if scan_id:
                    for tech in techs:
                        save_technology(scan_id, category, tech)
        
    except Exception as e:
        print(Fore.RED + f"[!] Error detecting technologies: {e}")
    
    return {k: list(v) for k, v in tech_stack.items()}

# ============================================
# WAYBACK MACHINE INTEGRATION
# ============================================

def get_historical_data(domain):
    """Fetch historical endpoints from Wayback Machine"""
    print(Fore.CYAN + "\n" + "="*60)
    print(Fore.CYAN + " HISTORICAL DATA (Wayback Machine)")
    print(Fore.CYAN + "="*60)
    
    endpoints = set()
    
    try:
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey"
        resp = requests.get(url, timeout=20)
        
        if resp.status_code == 200:
            data = resp.json()
            if len(data) > 1:
                for entry in data[1:100]:  # Limit to 100 entries
                    if len(entry) > 2:
                        endpoint = entry[2]
                        # Filter interesting extensions
                        interesting_extensions = ['.js', '.json', '.xml', '.php', '.asp', '.jsp', '.py', '.rb', '.env', '.config', '.yaml', '.yml']
                        if any(ext in endpoint.lower() for ext in interesting_extensions):
                            endpoints.add(endpoint)
        
        print(Fore.GREEN + f"[+] Found {len(endpoints)} historical endpoints")
        for endpoint in list(endpoints)[:15]:
            print(Fore.YELLOW + f"  → {endpoint}")
            
    except Exception as e:
        print(Fore.RED + f"[!] Wayback Machine lookup failed: {e}")
    
    return list(endpoints)

# ============================================
# EXISTING FUNCTIONS (UPDATED)
# ============================================

def get_ip(url):
    """Get website IP address"""
    try:
        domain = urlparse(url).netloc
        ip = socket.gethostbyname(domain)
        return ip
    except Exception as e:
        print(Fore.RED + f"[!] Error getting IP: {e}")
        return None

def get_whois(url):
    """Get WHOIS information"""
    try:
        domain = urlparse(url).netloc
        w = whois.whois(domain)
        return w
    except Exception as e:
        print(Fore.RED + f"[!] Error getting WHOIS: {e}")
        return None

def is_valid_url(url):
    """Check if URL is valid"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

def get_headers(url):
    """Get server headers"""
    try:
        response = requests.head(url, timeout=10, allow_redirects=True, verify=False)
        return response.headers
    except Exception as e:
        print(Fore.RED + f"[!] Error getting headers: {e}")
        return None

# CMS Fingerprints
CMS_FINGERPRINTS = {
    "WordPress": {
        "meta_generator": "WordPress",
        "login_page": "/wp-login.php",
        "files": ["/wp-content/", "/wp-includes/", "/wp-admin/"]
    },
    "Joomla": {
        "meta_generator": "Joomla",
        "login_page": "/administrator",
        "files": ["/media/com_", "/components/com_"]
    },
    "Drupal": {
        "meta_generator": "Drupal",
        "login_page": "/user/login",
        "files": ["/sites/all/", "/misc/drupal.js"]
    },
    "Magento": {
        "meta_generator": "Magento",
        "login_page": "/admin",
        "files": ["/js/mage/", "/skin/frontend/"]
    },
    "Laravel": {
        "meta_generator": "",
        "login_page": "/login",
        "files": ["/css/app.css", "/js/app.js"]
    }
}

def detect_cms(url):
    """Detect CMS platform"""
    try:
        response = requests.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Check meta generator tag
        meta_generator = soup.find('meta', attrs={'name': 'generator'})
        if meta_generator:
            for cms, data in CMS_FINGERPRINTS.items():
                if data['meta_generator'] and data['meta_generator'].lower() in meta_generator.get('content', '').lower():
                    return cms
        
        # Check for specific files
        for cms, data in CMS_FINGERPRINTS.items():
            for path in data['files']:
                check_url = urljoin(url, path)
                try:
                    r = requests.head(check_url, timeout=5, verify=False)
                    if r.status_code == 200:
                        return cms
                except:
                    continue
        
        return "Unknown"
    except Exception as e:
        return "Unknown"

# Database patterns
DATABASE_PATTERNS = {
    "MySQL": ["mysql_", "mysqli_", "PDO::MYSQL", "MySQL server"],
    "PostgreSQL": ["postgres", "pg_", "PDO::PGSQL", "PostgreSQL"],
    "SQLite": ["sqlite", ".db", ".sqlite", "SQLite"],
    "MongoDB": ["mongodb", "MongoClient", "MongoDB"],
    "Microsoft SQL Server": ["sqlsrv_", "mssql_", "PDO::SQLSRV", "SQL Server"]
}

def detect_database(url):
    """Detect database type"""
    try:
        response = requests.get(url, timeout=10, verify=False)
        content = response.text.lower()
        
        for db_type, patterns in DATABASE_PATTERNS.items():
            for pattern in patterns:
                if pattern.lower() in content:
                    return db_type
        
        return "Unknown"
    except Exception as e:
        return "Unknown"

def estimate_users(url, cms):
    """Estimate registered users"""
    try:
        if cms == "WordPress":
            # Try to access author pages
            low = 1
            high = 1000
            last_valid = 0
            
            for i in range(min(50, high)):  # Limit to 50 attempts
                check_url = urljoin(url, f"?author={i+1}")
                try:
                    r = requests.get(check_url, allow_redirects=False, timeout=5, verify=False)
                    if r.status_code == 301 or r.status_code == 302:
                        last_valid = i + 1
                except:
                    break
            
            return last_valid if last_valid > 0 else "Unknown"
        else:
            return "Unknown"
    except Exception as e:
        return "Unknown"

def scan_ports(ip, ports="80,443,21,22,3306,5432,8080,8443,3000,5000,8000,27017"):
    """Scan common ports"""
    try:
        print(Fore.YELLOW + f"\n[~] Scanning ports on {ip}...")
        nm.scan(hosts=ip, ports=ports, arguments='-sS -T4')
        open_ports = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in sorted(lport):
                    if nm[host][proto][port]['state'] == 'open':
                        service = nm[host][proto][port].get('name', 'unknown')
                        open_ports.append(f"{port}/{proto} ({service})")
        
        return ", ".join(open_ports) if open_ports else "No open ports found"
    except Exception as e:
        return f"Port scan failed: {e}"

def check_vulnerabilities(url, cms):
    """Check for common vulnerabilities"""
    vulnerabilities = []
    try:
        if cms == "WordPress":
            # Check for readme.html
            check_url = urljoin(url, "readme.html")
            try:
                r = requests.get(check_url, timeout=10, verify=False)
                if r.status_code == 200 and "WordPress" in r.text:
                    vulnerabilities.append("WordPress version exposed in readme.html")
            except:
                pass
            
            # Check for XML-RPC
            check_url = urljoin(url, "xmlrpc.php")
            try:
                r = requests.get(check_url, timeout=10, verify=False)
                if r.status_code == 200:
                    vulnerabilities.append("XML-RPC enabled (potential DDoS vulnerability)")
            except:
                pass
            
            # Check for wp-config.php backup
            backup_files = ["wp-config.php.bak", "wp-config.old", "wp-config.save"]
            for backup in backup_files:
                check_url = urljoin(url, backup)
                try:
                    r = requests.get(check_url, timeout=5, verify=False)
                    if r.status_code == 200:
                        vulnerabilities.append(f"Backup file exposed: {backup}")
                except:
                    pass
        
        # Check for common sensitive files
        sensitive_files = [
            "/.env", "/.git/config", "/.htaccess", "/phpinfo.php",
            "/test.php", "/config.php", "/backup.zip", "/.gitignore",
            "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/clientaccesspolicy.xml"
        ]
        
        for file in sensitive_files:
            check_url = urljoin(url, file)
            try:
                r = requests.get(check_url, timeout=5, verify=False)
                if r.status_code == 200:
                    vulnerabilities.append(f"Sensitive file exposed: {file}")
            except:
                continue
        
        return ", ".join(vulnerabilities) if vulnerabilities else "No obvious vulnerabilities found"
    except Exception as e:
        return f"Vulnerability check failed: {e}"

# Admin paths
ADMIN_PATHS = [
    "/admin", "/administrator", "/wp-admin", "/login", "/admin/login",
    "/backend", "/manager", "/panel", "/cpanel", "/webadmin", "/dashboard",
    "/admincp", "/adm", "/cp", "/controlpanel", "/adminarea"
]

def check_admin_panels(url):
    """Check for admin panels"""
    found = []
    try:
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for path in ADMIN_PATHS:
                check_url = urljoin(url, path)
                futures.append(executor.submit(check_admin_panel, check_url))
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
        
        return ", ".join(found) if found else "No admin panels found"
    except Exception as e:
        return f"Admin panel check failed: {e}"

def check_admin_panel(url):
    """Check single admin panel URL"""
    try:
        r = requests.head(url, timeout=5, verify=False)
        if r.status_code == 200:
            return url
        return None
    except:
        return None

def get_dns_records(domain):
    """Get DNS records"""
    records = {}
    try:
        # A records
        answers = dns.resolver.resolve(domain, 'A')
        records['A'] = [str(r) for r in answers]
    except:
        pass
    
    try:
        # MX records
        answers = dns.resolver.resolve(domain, 'MX')
        records['MX'] = [str(r.exchange) for r in answers]
    except:
        pass
    
    try:
        # NS records
        answers = dns.resolver.resolve(domain, 'NS')
        records['NS'] = [str(r) for r in answers]
    except:
        pass
    
    try:
        # TXT records
        answers = dns.resolver.resolve(domain, 'TXT')
        records['TXT'] = [str(r) for r in answers]
    except:
        pass
    
    return records

# ============================================
# ENHANCED SCAN FUNCTION
# ============================================

def scan_website(url, full_scan=True):
    """Enhanced main scan function with all features"""
    if not is_valid_url(url):
        print(Fore.RED + "[!] Invalid URL. Please include http:// or https://")
        return None
    
    print(Fore.MAGENTA + "\n" + "="*60)
    print(Fore.MAGENTA + f" SCANNING: {url}")
    print(Fore.MAGENTA + "="*60)
    
    start_time = time.time()
    
    # Get basic info
    ip = get_ip(url)
    if ip:
        print(Fore.GREEN + f"[+] IP Address: {ip}")
    
    headers = get_headers(url)
    if headers:
        print(Fore.GREEN + f"[+] Server: {headers.get('Server', 'Unknown')}")
    
    # Get WHOIS info
    whois_info = get_whois(url)
    if whois_info:
        print(Fore.GREEN + f"[+] Domain registrar: {whois_info.registrar or 'Unknown'}")
        if whois_info.creation_date:
            print(Fore.GREEN + f"[+] Creation date: {whois_info.creation_date}")
    
    # Get DNS records
    domain = urlparse(url).netloc
    dns_records = get_dns_records(domain)
    if dns_records:
        print(Fore.GREEN + "[+] DNS Records:")
        for record_type, values in dns_records.items():
            print(Fore.GREEN + f"    {record_type}: {', '.join(values)}")
    
    # Detect CMS
    cms = detect_cms(url)
    print(Fore.GREEN + f"[+] CMS: {cms}")
    
    # Detect database
    database = detect_database(url)
    print(Fore.GREEN + f"[+] Database: {database}")
    
    # Estimate users
    estimated_users = estimate_users(url, cms)
    print(Fore.GREEN + f"[+] Estimated registered users: {estimated_users}")
    
    # Scan ports
    if ip:
        open_ports = scan_ports(ip)
        print(Fore.GREEN + f"[+] Open ports: {open_ports}")
    else:
        open_ports = "Unknown"
    
    # Check vulnerabilities
    vulnerabilities = check_vulnerabilities(url, cms)
    print(Fore.GREEN + f"[+] Vulnerabilities: {vulnerabilities}")
    
    # Check admin panels
    admin_panels = check_admin_panels(url)
    print(Fore.GREEN + f"[+] Admin panels: {admin_panels}")
    
    # Save initial scan to database
    scan_id = save_scan(url, ip or "", cms, database, str(estimated_users), open_ports, vulnerabilities, 0)
    
    # Advanced features (if full_scan is True)
    risk_score = 0
    
    if full_scan:
        # JS Reconnaissance
        js_recon = JSRecon(url, scan_id)
        js_report = js_recon.run_full_recon()
        js_recon.display_results()
        risk_score += js_report['risk_score']
        
        # Subdomain enumeration
        subdomains = enumerate_subdomains(domain, scan_id)
        
        # Technology detection
        tech_stack = detect_technologies(url, scan_id)
        
        # Historical data
        historical = get_historical_data(domain)
        
        # Calculate final risk score
        if subdomains:
            risk_score += min(30, len(subdomains))
        if admin_panels != "No admin panels found":
            risk_score += 20
        if "No obvious vulnerabilities" not in vulnerabilities:
            risk_score += 25
        
        risk_score = min(100, risk_score)
        
        # Update risk score in database
        conn = sqlite3.connect('webscan.db')
        c = conn.cursor()
        c.execute("UPDATE scans SET risk_score = ? WHERE id = ?", (risk_score, scan_id))
        conn.commit()
        conn.close()
        
        # Display risk score
        print(Fore.MAGENTA + "\n" + "="*60)
        print(Fore.MAGENTA + " FINAL RISK ASSESSMENT")
        print(Fore.MAGENTA + "="*60)
        
        if risk_score < 30:
            print(Fore.GREEN + f"[+] Risk Score: {risk_score}/100 - LOW RISK")
        elif risk_score < 60:
            print(Fore.YELLOW + f"[!] Risk Score: {risk_score}/100 - MEDIUM RISK")
        else:
            print(Fore.RED + f"[!!!] Risk Score: {risk_score}/100 - HIGH RISK")
    
    end_time = time.time()
    print(Fore.GREEN + f"\n[+] Scan completed in {end_time - start_time:.2f} seconds")
    
    return scan_id

# ============================================
# REPORT GENERATION
# ============================================

def generate_report(scan_id):
    """Generate detailed report for a scan"""
    conn = sqlite3.connect('webscan.db')
    c = conn.cursor()
    
    # Get main scan info
    c.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    scan = c.fetchone()
    
    if not scan:
        print(Fore.RED + "[!] Scan not found")
        return
    
    # Get JS findings
    c.execute("SELECT * FROM js_findings WHERE scan_id = ?", (scan_id,))
    js_findings = c.fetchall()
    
    # Get subdomains
    c.execute("SELECT * FROM subdomains WHERE scan_id = ?", (scan_id,))
    subdomains = c.fetchall()
    
    # Get technologies
    c.execute("SELECT * FROM technologies WHERE scan_id = ?", (scan_id,))
    technologies = c.fetchall()
    
    conn.close()
    
    # Generate report
    report = {
        'scan_id': scan[0],
        'url': scan[1],
        'ip': scan[2],
        'cms': scan[3],
        'database': scan[4],
        'estimated_users': scan[5],
        'scan_date': scan[6],
        'open_ports': scan[7],
        'vulnerabilities': scan[8],
        'risk_score': scan[9],
        'js_findings': js_findings,
        'subdomains': subdomains,
        'technologies': technologies
    }
    
    # Save to JSON file
    filename = f"scan_report_{scan_id}_{int(time.time())}.json"
    with open(filename, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    print(Fore.GREEN + f"\n[+] Report saved to: {filename}")
    return report

def view_scan_history():
    """View scan history"""
    try:
        conn = sqlite3.connect('webscan.db')
        c = conn.cursor()
        c.execute("SELECT id, url, scan_date, risk_score FROM scans ORDER BY scan_date DESC LIMIT 10")
        scans = c.fetchall()
        conn.close()
        
        if not scans:
            print(Fore.YELLOW + "[!] No scan history found")
            return
        
        print(Fore.CYAN + "\n" + "="*60)
        print(Fore.CYAN + " RECENT SCANS")
        print(Fore.CYAN + "="*60)
        
        for scan in scans:
            risk_color = Fore.GREEN if scan[3] < 30 else Fore.YELLOW if scan[3] < 60 else Fore.RED
            print(Fore.WHITE + f"\n[ID: {scan[0]}] {scan[1]}")
            print(Fore.CYAN + f"    Date: {scan[2]}")
            print(risk_color + f"    Risk Score: {scan[3]}/100")
        
        print()
    except Exception as e:
        print(Fore.RED + f"[!] Error viewing scan history: {e}")

# ============================================
# INTERACTIVE MODE
# ============================================

def interactive_mode():
    """Interactive menu system"""
    while True:
        print(Fore.CYAN + "\n" + "="*50)
        print(Fore.CYAN + " WEBSCAN MENU")
        print(Fore.CYAN + "="*50)
        print(Fore.CYAN + "1. Quick Scan (Basic)")
        print(Fore.CYAN + "2. Full Scan (Advanced)")
        print(Fore.CYAN + "3. View Scan History")
        print(Fore.CYAN + "4. Generate Report from Scan ID")
        print(Fore.CYAN + "5. Exit")
        
        choice = input(Fore.YELLOW + "\n[?] Select option (1-5): ").strip()
        
        if choice == "1":
            url = input(Fore.YELLOW + "[?] Enter URL to scan (include http:// or https://): ").strip()
            scan_website(url, full_scan=False)
        elif choice == "2":
            url = input(Fore.YELLOW + "[?] Enter URL to scan (include http:// or https://): ").strip()
            scan_website(url, full_scan=True)
        elif choice == "3":
            view_scan_history()
        elif choice == "4":
            try:
                scan_id = int(input(Fore.YELLOW + "[?] Enter Scan ID: ").strip())
                generate_report(scan_id)
            except ValueError:
                print(Fore.RED + "[!] Invalid Scan ID")
        elif choice == "5":
            print(Fore.YELLOW + "[+] Exiting WEBSCAN. Goodbye!")
            sys.exit(0)
        else:
            print(Fore.RED + "[!] Invalid choice. Please try again.")

# ============================================
# MAIN FUNCTION
# ============================================

def main():
    """Main entry point"""
    # Initialize database
    init_db()
    
    # Show banner
    banner()
    
    # Check for command line arguments
    parser = argparse.ArgumentParser(description='WEBSCAN - Advanced Website Scanner')
    parser.add_argument('-u', '--url', help='URL to scan')
    parser.add_argument('-f', '--full', action='store_true', help='Perform full scan (includes JS recon, subdomains, etc.)')
    parser.add_argument('-s', '--scan-id', type=int, help='Generate report for specific scan ID')
    parser.add_argument('--history', action='store_true', help='View scan history')
    
    args = parser.parse_args()
    
    if args.url:
        scan_website(args.url, full_scan=args.full)
    elif args.scan_id:
        generate_report(args.scan_id)
    elif args.history:
        view_scan_history()
    else:
        interactive_mode()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(Fore.RED + f"\n[!] Unexpected error: {e}")
        sys.exit(1)
