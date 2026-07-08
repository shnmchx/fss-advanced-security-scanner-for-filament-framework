#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║    ███████╗██╗██╗      █████╗ ███╗   ███╗███████╗███╗   ██╗████████╗ ║
║    ██╔════╝██║██║     ██╔══██╗████╗ ████║██╔════╝████╗  ██║╚══██╔══╝ ║
║    █████╗  ██║██║     ███████║██╔████╔██║█████╗  ██╔██╗ ██║   ██║    ║
║    ██╔══╝  ██║██║     ██╔══██║██║╚██╔╝██║██╔══╝  ██║╚██╗██║   ██║    ║
║    ██║     ██║███████╗██║  ██║██║ ╚═╝ ██║███████╗██║ ╚████║   ██║    ║
║    ╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═══╝   ╚═╝    ║
║                                                                      ║
║                   ███████╗ ██████╗ █████╗ ███╗   ██╗                 ║
║                   ██╔════╝██╔════╝██╔══██╗████╗  ██║                 ║
║                   ███████╗██║     ███████║██╔██╗ ██║                 ║
║                   ╚════██║██║     ██╔══██║██║╚██╗██║                 ║
║                   ███████║╚██████╗██║  ██║██║ ╚████║                 ║
║                   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝                 ║
║                                                                      ║
║                 Advanced Security Scanner for Filament               ║
║                     Laravel + Filament Development                   ║
║                                                                      ║
║               Detect Misconfigurations & Exposures Before            ║
║                        Your Production Goes Live                     ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import requests
import sys
import re
import time
import urllib3
import warnings
from urllib.parse import urljoin

urllib3.disable_warnings()
warnings.filterwarnings('ignore')

class FilamentDevScanner:
    def __init__(self, target_url):
        self.target = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json, text/plain, */*',
            'X-Requested-With': 'XMLHttpRequest'
        }
        self.vulns = []
        self.filament_paths = []

    def detect_filament(self):
        print("[>] Detecting Filament Framework Presence")
        try:
            r = self.session.get(self.target, timeout=5)
            if 'filament' in r.text.lower() or 'filament' in r.headers.get('X-Powered-By', '').lower():
                print("  [+] Filament Detected")
                return True
            for path in ['/admin', '/filament', '/app']:
                r2 = self.session.get(urljoin(self.target, path), timeout=3)
                if 'filament' in r2.text.lower() or 'livewire' in r2.text.lower():
                    print(f"  [+] Filament Detected at {path}")
                    self.filament_paths.append(path)
                    return True
            print("  [-] Filament Not Detected")
            return False
        except:
            return False

    def check_debug_mode(self):
        print("\n[>] Checking Debug Mode Exposure")
        debug_paths = ['/_debugbar', '/telescope', '/_ignition', '/horizon']
        for path in debug_paths:
            url = urljoin(self.target, path)
            try:
                r = self.session.get(url, timeout=3)
                if r.status_code == 200:
                    self.vulns.append({
                        'type': 'Debug Toolbar Exposed',
                        'path': path,
                        'severity': 'HIGH',
                        'desc': 'Debugbar or Telescope accessible in development'
                    })
                    print(f"  [!] Debug Accessible: {path}")
                    if 'sql' in r.text.lower() or 'query' in r.text.lower():
                        self.vulns.append({
                            'type': 'SQL Query Leakage',
                            'path': path,
                            'severity': 'CRITICAL',
                            'desc': 'SQL queries visible through debug tools'
                        })
                        print(f"  [!] SQL Queries Exposed")
            except:
                pass

    def check_resource_exposure(self):
        print("\n[>] Scanning Filament Resource Exposure")
        resources = [
            '/admin/users', '/admin/users/create', '/admin/users/1/edit',
            '/admin/settings', '/admin/dashboard', '/admin/login',
            '/admin/pages', '/admin/widgets', '/admin/media',
            '/admin/roles', '/admin/permissions', '/admin/backup'
        ]
        for resource in resources:
            url = urljoin(self.target, resource)
            try:
                r = self.session.get(url, timeout=3)
                if r.status_code == 200:
                    self.vulns.append({
                        'type': 'Resource Exposed Without Authentication',
                        'path': url,
                        'severity': 'HIGH',
                        'desc': 'Filament resource accessible without login requirements'
                    })
                    print(f"  [!] Exposed Resource: {url}")
            except:
                pass

    def check_default_creds(self):
        print("\n[>] Testing Default Credentials")
        login_url = urljoin(self.target, '/admin/login')
        default_creds = [
            ('admin@example.com', 'password'),
            ('admin@admin.com', 'admin'),
            ('admin', 'admin'),
            ('admin@gmail.com', '123456'),
            ('user@example.com', 'password')
        ]
        for email, password in zip([c[0] for c in default_creds], [c[1] for c in default_creds]):
            try:
                r = self.session.get(login_url, timeout=3)
                csrf_match = re.search(r'name="_token" value="([^"]+)"', r.text)
                csrf = csrf_match.group(1) if csrf_match else None
                data = {
                    '_token': csrf or '',
                    'email': email,
                    'password': password,
                    'remember': 'on'
                }
                r2 = self.session.post(login_url, data=data, timeout=5)
                if 'dashboard' in r2.text.lower() or 'filament' in r2.text.lower():
                    self.vulns.append({
                        'type': 'Default Credentials Accepted',
                        'username': email,
                        'password': password,
                        'severity': 'CRITICAL',
                        'desc': 'Default credentials successfully authenticated'
                    })
                    print(f"  [!] Default Credentials: {email}:{password}")
                    return True
            except:
                pass
        print("  [+] No Default Credentials Found")
        return False

    def check_config_leak(self):
        print("\n[>] Checking Configuration File Exposure")
        config_paths = ['/config.js', '/config.json', '/.env', '/app.js', '/manifest.json']
        for path in config_paths:
            url = urljoin(self.target, path)
            try:
                r = self.session.get(url, timeout=3)
                if r.status_code == 200 and ('DB_PASSWORD' in r.text or 'filament' in r.text):
                    self.vulns.append({
                        'type': 'Sensitive Configuration Exposed',
                        'path': url,
                        'severity': 'CRITICAL',
                        'desc': 'Configuration or environment file accessible'
                    })
                    print(f"  [!] Config Exposed: {url}")
            except:
                pass

    def check_upload_vulnerability(self):
        print("\n[>] Testing File Upload Security")
        upload_url = urljoin(self.target, '/admin/media/upload')
        try:
            files = {'file': ('test.php', '<?php echo "pwned"; ?>', 'application/x-php')}
            r = self.session.post(upload_url, files=files, timeout=5)
            if r.status_code == 200:
                self.vulns.append({
                    'type': 'Unrestricted File Upload',
                    'path': upload_url,
                    'severity': 'CRITICAL',
                    'desc': 'PHP file accepted during upload without restriction'
                })
                print(f"  [!] PHP Upload Accepted")
        except:
            pass

    def check_livewire_exposure(self):
        print("\n[>] Checking Livewire Endpoint Exposure")
        lw_endpoints = ['/livewire/message', '/livewire/update']
        for endpoint in lw_endpoints:
            url = urljoin(self.target, endpoint)
            try:
                r = self.session.get(url, timeout=3)
                if r.status_code == 405:
                    self.vulns.append({
                        'type': 'Livewire Endpoint Exposed',
                        'path': url,
                        'severity': 'MEDIUM',
                        'desc': 'Livewire message endpoint accessible'
                    })
                    print(f"  [!] Livewire Endpoint: {url}")
            except:
                pass

    def check_middleware_bypass(self):
        print("\n[>] Testing Middleware Bypass")
        admin_url = urljoin(self.target, '/admin')
        try:
            r = self.session.get(admin_url, timeout=3)
            if r.status_code == 200 and 'filament' in r.text.lower():
                self.vulns.append({
                    'type': 'Middleware Bypass Detected',
                    'path': admin_url,
                    'severity': 'CRITICAL',
                    'desc': 'Admin panel accessible without authentication'
                })
                print(f"  [!] Admin Accessible Without Login")
        except:
            pass

    def check_env_dump(self):
        print("\n[>] Scanning for Environment Dump")
        endpoints = ['/debug', '/dump', '/phpinfo', '/env']
        for endpoint in endpoints:
            url = urljoin(self.target, endpoint)
            try:
                r = self.session.get(url, timeout=3)
                if 'DB_PASSWORD' in r.text or 'APP_KEY' in r.text:
                    self.vulns.append({
                        'type': 'Environment Variables Leaked',
                        'path': url,
                        'severity': 'CRITICAL',
                        'desc': 'Sensitive environment data exposed'
                    })
                    print(f"  [!] Env Dump Found: {url}")
            except:
                pass

    def brute_force_login(self):
        print("\n[>] Brute Forcing Admin Login with Common Credentials")
        login_url = urljoin(self.target, '/admin/login')
        usernames = ['admin@example.com', 'admin', 'test@example.com']
        passwords = ['password', 'admin', '123456', '12345678', 'qwerty', 'admin123', 'password123']
        try:
            r = self.session.get(login_url, timeout=3)
            csrf_match = re.search(r'name="_token" value="([^"]+)"', r.text)
            csrf = csrf_match.group(1) if csrf_match else ''
        except:
            csrf = ''
        for username in usernames:
            for password in passwords:
                data = {
                    '_token': csrf,
                    'email': username,
                    'password': password
                }
                try:
                    r = self.session.post(login_url, data=data, timeout=3)
                    if 'dashboard' in r.text.lower() or 'filament' in r.text.lower():
                        self.vulns.append({
                            'type': 'Brute Force Login Success',
                            'username': username,
                            'password': password,
                            'severity': 'CRITICAL'
                        })
                        print(f"  [!] Login Found: {username}:{password}")
                        return True
                except:
                    pass
                time.sleep(0.1)
        print("  [+] No Weak Credentials Detected")
        return False

    def full_scan(self):
        print("\n" + "=" * 80)
        print("  F I L A M E N T   S C A N")
        print("  Advanced Security Assessment for Filament Framework")
        print("  Target: " + self.target)
        print("=" * 80 + "\n")

        if not self.detect_filament():
            print("\n[!] Target Does Not Appear to Use Filament")
            print("[!] Scan Results May Be Incomplete or Inaccurate")
            return

        self.check_debug_mode()
        self.check_resource_exposure()
        self.check_default_creds()
        self.check_config_leak()
        self.check_upload_vulnerability()
        self.check_livewire_exposure()
        self.check_middleware_bypass()
        self.check_env_dump()
        self.brute_force_login()

        print("\n" + "=" * 80)
        print("  SCAN COMPLETE")
        print("  Total Vulnerabilities Found: " + str(len(self.vulns)))
        print("\n")
        for v in self.vulns:
            severity = v.get('severity', 'MEDIUM')
            label = "CRITICAL" if severity == 'CRITICAL' else "HIGH" if severity == 'HIGH' else "MEDIUM"
            print("  [" + label + "] " + v['type'])
            if 'path' in v:
                print("      Path: " + v['path'])
            if 'username' in v:
                print("      Credentials: " + v['username'] + ":" + v['password'])
        print("\n" + "=" * 80)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python filament_scan.py <target_url>")
        print("Example: python filament_scan.py https://kaladipa.id")
        sys.exit(1)
    scanner = FilamentDevScanner(sys.argv[1])
    scanner.full_scan()