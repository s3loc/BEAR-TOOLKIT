#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ELITE NETWORK & HOST RECONNAISSANCE MODULE v3.0
# Developed for REDHACK Operations (Ultra-Elite Edition)

import os
import re
import sys
import json
import time
import socket
import random
import whois
import dns.resolver
import requests
import nmap
import shodan
import censys
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import ip_network, IPv4Address

# =====================
# CONFIGURATION SECTION
# =====================
class EliteConfig:
    SHODAN_API_KEY = "YOUR_SHODAN_API_KEY"  # Replace with valid API key
    CENSYS_API_ID = "YOUR_CENSYS_API_ID"    # Replace with valid API ID
    CENSYS_API_SECRET = "YOUR_CENSYS_API_SECRET"  # Replace with valid API secret
    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36'
    ]
    SUBDOMAIN_WORDLIST = "subdomains-top1million-110000.txt"  # Custom wordlist path
    THREADS = 50  # High-performance threading
    NMAP_ARGS = "-sS -sV -O -T4 --script=vuln -Pn --min-rate=5000"  # Aggressive stealth scanning
    SNMP_COMMUNITIES = ['public', 'private', 'manager', 'admin']  # SNMP brute-force list

# ===================
# CORE RECON ENGINE
# ===================
class EliteRecon:
    def __init__(self, target_domain=None, target_ip=None):
        self.target_domain = target_domain
        self.target_ip = target_ip
        self.results = {
            'domain_info': {},
            'subdomains': [],
            'emails': [],
            'network_ranges': [],
            'hosts': {},
            'topology': {},
            'social_profiles': []
        }
        
        # API Clients
        self.shodan_client = shodan.Shodan(EliteConfig.SHODAN_API_KEY) if EliteConfig.SHODAN_API_KEY else None
        self.censys_client = censys.ipv4.CensysIPv4(api_id=EliteConfig.CENSYS_API_ID, api_secret=EliteConfig.CENSYS_API_SECRET) \
            if EliteConfig.CENSYS_API_ID and EliteConfig.CENSYS_API_SECRET else None
        self.nmap_scanner = nmap.PortScanner()

    # =====================
    # PASSIVE RECON METHODS
    # =====================
    def get_whois_dns_records(self):
        """WHOIS and DNS intelligence gathering"""
        try:
            # WHOIS Domain Lookup
            domain_info = whois.whois(self.target_domain)
            self.results['domain_info']['whois'] = domain_info
            
            # DNS Records
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
            dns_data = {}
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 3
            
            for rtype in record_types:
                try:
                    answers = resolver.resolve(self.target_domain, rtype)
                    dns_data[rtype] = [str(r) for r in answers]
                except:
                    continue
            self.results['domain_info']['dns'] = dns_data
        except Exception as e:
            pass

    def subdomain_discovery(self):
        """Multi-technique subdomain enumeration"""
        subdomains = set()
        
        # Technique 1: Certificate Transparency
        try:
            url = f"https://crt.sh/?q=%.{self.target_domain}&output=json"
            headers = {'User-Agent': random.choice(EliteConfig.USER_AGENTS)}
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry['name_value'].lower()
                    if name.endswith(self.target_domain):
                        subdomains.add(name)
        except:
            pass
        
        # Technique 2: Search Engine Scraping
        try:
            search_engines = [
                f"https://www.google.com/search?q=site:{self.target_domain}",
                f"https://www.bing.com/search?q=site:{self.target_domain}",
                f"https://search.yahoo.com/search?p=site:{self.target_domain}"
            ]
            for url in search_engines:
                headers = {'User-Agent': random.choice(EliteConfig.USER_AGENTS)}
                response = requests.get(url, headers=headers, timeout=20)
                soup = BeautifulSoup(response.text, 'html.parser')
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    if self.target_domain in href:
                        domain_match = re.search(r'https?://([^/]+)', href)
                        if domain_match:
                            sub = domain_match.group(1)
                            if sub.endswith(self.target_domain):
                                subdomains.add(sub)
        except:
            pass
        
        # Technique 3: Bruteforce with wordlist
        try:
            if os.path.exists(EliteConfig.SUBDOMAIN_WORDLIST):
                with open(EliteConfig.SUBDOMAIN_WORDLIST, 'r') as f:
                    words = f.read().splitlines()
                
                def check_subdomain(sub):
                    try:
                        full_domain = f"{sub}.{self.target_domain}"
                        socket.gethostbyname(full_domain)
                        return full_domain
                    except:
                        return None
                
                with ThreadPoolExecutor(max_workers=EliteConfig.THREADS) as executor:
                    futures = [executor.submit(check_subdomain, word) for word in words]
                    for future in as_completed(futures):
                        result = future.result()
                        if result:
                            subdomains.add(result)
        except:
            pass
        
        self.results['subdomains'] = list(subdomains)

    def email_harvesting(self):
        """Advanced email collection from multiple sources"""
        emails = set()
        
        # Source 1: Website Scraping
        try:
            url = f"http://{self.target_domain}"
            headers = {'User-Agent': random.choice(EliteConfig.USER_AGENTS)}
            response = requests.get(url, headers=headers, timeout=15)
            found_emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', response.text)
            for email in found_emails:
                if self.target_domain in email:
                    emails.add(email)
        except:
            pass
        
        # Source 2: WHOIS Data
        try:
            if 'whois' in self.results['domain_info']:
                whois_data = str(self.results['domain_info']['whois'])
                whois_emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', whois_data)
                for email in whois_emails:
                    if self.target_domain in email:
                        emails.add(email)
        except:
            pass
        
        # Source 3: Public GitHub Repos
        try:
            url = f"https://api.github.com/search/code?q=%40{self.target_domain}+in:file"
            headers = {
                'User-Agent': random.choice(EliteConfig.USER_AGENTS),
                'Accept': 'application/vnd.github.v3+json'
            }
            response = requests.get(url, headers=headers, timeout=20)
            if response.status_code == 200:
                data = response.json()
                for item in data.get('items', []):
                    email_matches = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', str(item))
                    for email in email_matches:
                        if self.target_domain in email:
                            emails.add(email)
        except:
            pass
        
        self.results['emails'] = list(emails)

    def social_media_discovery(self):
        """Deep social media and employee profiling"""
        profiles = []
        
        # LinkedIn Employee Search
        try:
            url = f"https://www.linkedin.com/search/results/people/?keywords={self.target_domain}"
            headers = {'User-Agent': random.choice(EliteConfig.USER_AGENTS)}
            response = requests.get(url, headers=headers, timeout=25)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for profile in soup.select('.entity-result__item'):
                name_elem = profile.select_one('.entity-result__title-text a')
                position_elem = profile.select_one('.entity-result__primary-subtitle')
                if name_elem and position_elem:
                    name = name_elem.get_text(strip=True)
                    profile_url = name_elem['href'] if name_elem.has_attr('href') else ''
                    position = position_elem.get_text(strip=True)
                    profiles.append({
                        'platform': 'LinkedIn',
                        'name': name,
                        'position': position,
                        'url': profile_url
                    })
        except:
            pass
        
        # GitHub Organization Members
        try:
            url = f"https://api.github.com/orgs/{self.target_domain}/members"
            headers = {'User-Agent': random.choice(EliteConfig.USER_AGENTS)}
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                members = response.json()
                for member in members:
                    profiles.append({
                        'platform': 'GitHub',
                        'username': member['login'],
                        'url': member['html_url'],
                        'type': 'Organization Member'
                    })
        except:
            pass
        
        self.results['social_profiles'] = profiles

    def shodan_censys_intel(self):
        """Shodan and Censys integration for network intelligence"""
        # Shodan Search
        if self.shodan_client:
            try:
                shodan_results = self.shodan_client.search(f"hostname:{self.target_domain}")
                for result in shodan_results['matches']:
                    ip = result['ip_str']
                    if ip not in self.results['hosts']:
                        self.results['hosts'][ip] = {
                            'ports': [],
                            'services': {},
                            'vulnerabilities': []
                        }
                    for port in result['ports']:
                        service = result.get('data', '').split('\n')[0][:100] if 'data' in result else ''
                        self.results['hosts'][ip]['ports'].append(port)
                        self.results['hosts'][ip]['services'][str(port)] = service
            except:
                pass
        
        # Censys Search
        if self.censys_client:
            try:
                query = f"parsed.names: {self.target_domain}"
                censys_results = self.censys_client.search(query, max_records=100)
                for page in censys_results:
                    for result in page:
                        ip = result['ip']
                        if ip not in self.results['hosts']:
                            self.results['hosts'][ip] = {
                                'ports': [],
                                'services': {},
                                'vulnerabilities': []
                            }
                        for service in result.get('services', []):
                            port = service['port']
                            service_name = service['service_name']
                            self.results['hosts'][ip]['ports'].append(port)
                            self.results['hosts'][ip]['services'][str(port)] = service_name
            except:
                pass

    # ====================
    # ACTIVE RECON METHODS
    # ====================
    def advanced_nmap_scan(self, target):
        """Elite-level Nmap scanning with vulnerability detection"""
        scan_results = {}
        try:
            self.nmap_scanner.scan(hosts=target, arguments=EliteConfig.NMAP_ARGS)
            for host in self.nmap_scanner.all_hosts():
                if self.nmap_scanner[host].state() == 'up':
                    scan_results[host] = {
                        'os': self.nmap_scanner[host].get('osmatch', [{}])[0].get('name', 'Unknown'),
                        'ports': []
                    }
                    
                    for proto in self.nmap_scanner[host].all_protocols():
                        ports = self.nmap_scanner[host][proto].keys()
                        for port in ports:
                            service = self.nmap_scanner[host][proto][port]
                            scan_results[host]['ports'].append({
                                'port': port,
                                'state': service['state'],
                                'service': service['name'],
                                'version': service['version'],
                                'vulns': service.get('script', {}).get('vuln', [])
                            })
        except:
            pass
        return scan_results

    def network_topology_mapping(self):
        """Advanced network topology discovery"""
        topology = {}
        
        # Traceroute Implementation
        try:
            if self.target_ip:
                # Windows: tracert, Linux: traceroute
                command = f"traceroute -n -m 15 -q 1 {self.target_ip}" if os.name != 'nt' else f"tracert -d -h 15 -w 1000 {self.target_ip}"
                result = os.popen(command).read()
                hops = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', result)
                topology['traceroute'] = list(dict.fromkeys(hops))  # Remove duplicates
        except:
            pass
        
        # SNMP Network Discovery
        try:
            if self.target_ip:
                community = self.snmp_community_bruteforce()
                if community:
                    # SNMP walk would be implemented here
                    topology['snmp_devices'] = self.snmp_discover_devices(community)
        except:
            pass
        
        self.results['topology'] = topology

    def snmp_community_bruteforce(self):
        """SNMP community string enumeration"""
        for community in EliteConfig.SNMP_COMMUNITIES:
            try:
                # Simple SNMP check (actual implementation would use pysnmp)
                test_oid = '1.3.6.1.2.1.1.1.0'  # sysDescr
                command = f"snmpget -v2c -c {community} {self.target_ip} {test_oid}"
                result = os.popen(command).read()
                if 'SNMPv2-MIB::sysDescr.0' in result:
                    return community
            except:
                continue
        return None

    def snmp_discover_devices(self, community):
        """SNMP-based network device discovery"""
        devices = []
        # Actual implementation would use pysnmp to walk ARP tables and routing tables
        return devices  # Placeholder

    def internal_ip_discovery(self):
        """Automatic internal IP range detection and scanning"""
        ip_ranges = []
        
        # Common internal ranges
        common_ranges = [
            '10.0.0.0/8',
            '172.16.0.0/12',
            '192.168.0.0/16'
        ]
        
        # Network interface detection
        try:
            if os.name == 'posix':
                result = os.popen("ip route | grep -oP '\\d+\\.\\d+\\.\\d+\\.\\d+/\\d+'").read()
                ip_ranges += result.splitlines()
            elif os.name == 'nt':
                result = os.popen("ipconfig | findstr /i \"IPv4 Subnet\"").read()
                matches = re.findall(r'\d+\.\d+\.\d+\.\d+/\d+', result)
                ip_ranges += matches
        except:
            pass
        
        # Add common ranges if none found
        if not ip_ranges:
            ip_ranges = common_ranges
        
        # Scan detected ranges
        for ip_range in set(ip_ranges):
            print(f"[*] Scanning internal range: {ip_range}")
            scan_results = self.advanced_nmap_scan(ip_range)
            for host, data in scan_results.items():
                if host not in self.results['hosts']:
                    self.results['hosts'][host] = data
        
        self.results['network_ranges'] = ip_ranges

    # ====================
    # INTEGRATION METHODS
    # ====================
    def export_to_redhack_scanner(self):
        """Format data for redhack_scanner.py integration"""
        targets = []
        for ip, data in self.results['hosts'].items():
            for port_info in data['ports']:
                if port_info['state'] == 'open':
                    targets.append({
                        'ip': ip,
                        'port': port_info['port'],
                        'service': port_info['service'],
                        'version': port_info['version']
                    })
        return targets

    def export_to_ddos_v2(self):
        """Format data for Dddos.v2.py integration"""
        targets = []
        for ip, data in self.results['hosts'].items():
            if data['ports']:
                service_ports = {svc: port for port, svc in data['services'].items()}
                targets.append({
                    'ip': ip,
                    'services': service_ports,
                    'os': data.get('os', 'Unknown')
                })
        return targets

    # ===================
    # EXECUTION FRAMEWORK
    # ===================
    def full_reconnaissance(self):
        """Execute complete reconnaissance operation"""
        print(f"[+] Starting ELITE reconnaissance against: {self.target_domain or self.target_ip}")
        
        # Passive Recon
        print("[*] Phase 1: Passive Intelligence Gathering")
        if self.target_domain:
            self.get_whois_dns_records()
            self.subdomain_discovery()
            self.email_harvesting()
            self.social_media_discovery()
            self.shodan_censys_intel()
        
        # Active Recon
        print("[*] Phase 2: Active Target Enumeration")
        if self.target_ip:
            scan_results = self.advanced_nmap_scan(self.target_ip)
            self.results['hosts'].update(scan_results)
            self.network_topology_mapping()
        elif self.target_domain:
            # Resolve domain to IP
            try:
                ip = socket.gethostbyname(self.target_domain)
                scan_results = self.advanced_nmap_scan(ip)
                self.results['hosts'].update(scan_results)
                self.target_ip = ip
                self.network_topology_mapping()
            except:
                pass
        
        # Internal Network Discovery
        print("[*] Phase 3: Internal Network Mapping")
        self.internal_ip_discovery()
        
        print("[+] Reconnaissance completed successfully")
        return self.results

# =====================
# OPERATIONAL INTERFACE
# =====================
if __name__ == "__main__":
    banner = r"""
    ███████╗██╗     ██╗███████╗████████╗███████╗
    ██╔════╝██║     ██║██╔════╝╚══██╔══╝██╔════╝
    █████╗  ██║     ██║█████╗     ██║   █████╗  
    ██╔══╝  ██║     ██║██╔══╝     ██║   ██╔══╝  
    ███████╗███████╗██║███████╗   ██║   ███████╗
    ╚══════╝╚══════╝╚═╝╚══════╝   ╚═╝   ╚══════╝
    RedHack Elite Reconnaissance Suite v3.0
    """
    print(banner)
    
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <domain|ip>")
        sys.exit(1)
    
    target = sys.argv[1]
    
    # Target validation
    try:
        IPv4Address(target)
        recon = EliteRecon(target_ip=target)
    except:
        recon = EliteRecon(target_domain=target)
    
    # Execute reconnaissance
    results = recon.full_reconnaissance()
    
    # Save results
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    filename = f"recon_{target.replace('.', '_')}_{timestamp}.json"
    with open(filename, 'w') as f:
        json.dump(results, f, indent=4)
    
    print(f"\n[+] Results saved to: {filename}")
    print("[+] Integration data prepared for:")
    print("    - redhack_scanner.py")
    print("    - Dddos.v2.py")
    
    # Export for other modules
    scanner_targets = recon.export_to_redhack_scanner()
    ddos_targets = recon.export_to_ddos_v2()
    
    print("\n[+] Mission Complete")