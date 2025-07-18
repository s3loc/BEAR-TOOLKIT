import os
import sys
import time
import subprocess
import pyfiglet
import threading
import itertools
import json
import shutil
import platform
import re
import getpass
import socket
import ssl
import random
import hashlib
import paramiko
import requests
from cryptography.fernet import Fernet

# ANSI renk kodları
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
RESET = "\033[0m"
BOLD = "\033[1m"
UNDERLINE = "\033[4m"

# Temel dizin
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Gelişmiş modül konfigürasyonu
MODULE_CONFIG = {
    '1': {
        'name': 'Web Zafiyet Tarayıcısı',
        'script': 'redhack_scanner.py',
        'path': os.path.join(BASE_DIR, 'RedHackscanner'),
        'venv': 'scanner_env',
        'requirements': 'requirements.txt',
        'status': 'active'
    },
    '2': {
        'name': 'DDoS Çerçevesi',
        'script': 'Dddos.v2.py',
        'path': os.path.join(BASE_DIR, 'DDdos'),
        'venv': 'ddos_env',
        'requirements': 'requirements.txt',
        'status': 'active'
    },
    '3': {
        'name': 'Ağ ve Host Keşfi',
        'script': 'Network & Host Reconnaissance Module.py',
        'path': os.path.join(BASE_DIR, 'Network & Host Reconnaissance Module'),
        'venv': 'recon_env',
        'requirements': 'requirements.txt',
        'status': 'active'
    },
    '4': {
        'name': 'Kimlik Bilgisi Yönetimi',
        'script': 'Credential & Access Management Module.py',
        'path': os.path.join(BASE_DIR, 'Credential & Access Management Module'),
        'venv': 'cred_env',
        'requirements': 'requirements.txt',
        'status': 'active'
    },
    '5': {
        'name': 'Sömürü ve Sömürü Sonrası',
        'script': 'exploitation_module.py',
        'path': os.path.join(BASE_DIR, 'NetHack'),
        'venv': 'exploit_env',
        'requirements': 'requirements_exploit.txt',
        'status': 'active'  # Geliştirme tamamlandı
    },
    '6': {
        'name': 'Atlatma ve Anti-Forensics',
        'script': 'Evasion & Anti-Forensics Module.py',
        'path': os.path.join(BASE_DIR, 'Evasion & Anti-Forensics Module'),
        'venv': 'evasion_env',
        'requirements': 'requirements_evasion.txt',
        'status': 'active'  # Geliştirme tamamlandı
    },
    '7': {
        'name': 'Raporlama ve Dashboard',
        'script': 'reporting_module.py',
        'path': os.path.join(BASE_DIR, 'Centralized Reporting & Dashboard Implementation'),
        'venv': 'reporting_env',
        'requirements': 'requirements_reporting.txt',
        'status': 'active'  # Geliştirme tamamlandı
    },
    '8': {
        'name': 'Sistem Yönetici Paneli',
        'script': 'system_admin.py',
        'path': os.path.join(BASE_DIR, 'SystemAdmin'),
        'venv': 'admin_env',
        'requirements': 'requirements_admin.txt',
        'status': 'active'
    }
}

# --- GELİŞMİŞ ANİMASYON VE GÖRSELLİK ---
stop_spinner = False

def print_animated_ascii(text, color=GREEN, font="standard", delay=0.001):
    """ASCII metni animasyonla yazdırır"""
    try:
        ascii_text = pyfiglet.figlet_format(text, font=font)
    except pyfiglet.FontNotFound:
        ascii_text = pyfiglet.figlet_format(text, font="standard")
        print(f"{YELLOW}[!] Font bulunamadı, 'standard' kullanılıyor{RESET}")
    
    for char in ascii_text:
        sys.stdout.write(f"{color}{char}{RESET}")
        sys.stdout.flush()
        time.sleep(delay)
    print()

def loading_spinner(message="Yükleniyor"):
    """Animasyonlu spinner"""
    spinner_chars = itertools.cycle(['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'])
    colors = [RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN]
    color_cycle = itertools.cycle(colors)
    
    while not stop_spinner:
        sys.stdout.write(f"\r{next(color_cycle)}{next(spinner_chars)}{RESET} {message}...")
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write("\r" + " " * (len(message) + 15) + "\r")

def print_header():
    """Başlık ve sistem bilgilerini göster"""
    os.system('cls' if os.name == 'nt' else 'clear')
    
    # Sistem bilgileri
    sys_info = f"{BOLD}{CYAN}┃ {platform.system()} {platform.release()} | Python {platform.python_version()} {RESET}"
    user_info = f"{BOLD}{CYAN}┃ Kullanıcı: {getpass.getuser()} {RESET}"
    time_info = f"{BOLD}{CYAN}┃ Zaman: {time.strftime('%Y-%m-%d %H:%M:%S')} {RESET}"
    ip_info = f"{BOLD}{CYAN}┃ IP: {get_public_ip()} {RESET}"
    
    # REDHACK Banner
    banner = f"""
{RED}{BOLD}
                   (                )     )  (     
   (       (     )\ )    *   ) ( /(  ( /(  )\ )  
 ( )\ (    )\   (()/(  ` )  /( )\()) )\())(()/(  
 )((_))\((((_)(  /(_))  ( )(_)|(_)\ ((_)\  /(_)) 
((_)_((_))\ _ )\(_))   (_(_())  ((_)  ((_)(_))   
 | _ ) __(_)_\(_) _ \  |_   _| / _ \ / _ \| |    
 | _ \ _| / _ \ |   /    | |  | (_) | (_) | |__  
 |___/___/_/ \_\|_|_\    |_|   \___/ \___/|____| 
                                                 


{GREEN}{BOLD}
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⣴⣶⣶⣶⣤⣤⣤⣤⣦⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⠿⣿⢟⡍⠉⠐⠂⠀⠈⠉⢻⣿⣿⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣶⣿⠛⠁⠀⠈⣴⣏⠀⠀⠀⠀⠀⠀⠀⠀⢀⠈⠹⣿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠂⠀⠀⠀⢀⣤⣶⣤⡤⣰⣿⣯⣅⣚⣛⣯⣸⣿⣿⣄⠀⠀⠀⠀⠀⠀⣠⣿⣖⣦⣜⣳⣄⣤⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⢋⡉⠉⣵⣿⣿⣿⣿⣿⡿⢃⣯⣿⣿⡿⠿⠦⠀⠠⢶⣾⣿⣿⡇⣿⣿⣿⣾⡝⠛⣻⡇⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠟⢄⠀⠸⣿⣿⣿⣿⣿⡿⠀⢸⣸⣿⠟⠀⠀⠀⠀⠀⠀⠘⢿⣿⡇⢿⣿⢿⣿⣇⢀⣼⠇⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠡⢅⣾⣿⣿⣿⣿⢟⣤⠴⢸⣿⠁⢰⡆⠁⠉⠈⠀⠀⣆⠈⣿⠇⣾⣷⣿⣿⣷⠈⠋⠀⠀⠀⢀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡼⣿⣿⣿⣿⣿⣿⣿⣹⢸⡇⠀⠘⠀⠀⠀⠀⠀⠀⠇⠀⡿⣸⣿⣿⣿⣿⣿⡆⠀⠠⠀⠈⠂⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠊⡇⣻⣿⣿⣿⣿⣿⣟⣷⡊⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⢡⣿⣿⣿⢿⣿⣿⡇⠀⠐⠆⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢘⣄⠁⡟⣏⢿⡻⡝⣞⣿⠴⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⢦⣿⣿⣿⣿⣿⣿⡼⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢪⣮⠘⠠⠩⢌⢳⡙⣮⡟⢾⡇⠀⠀⢠⠀⠀⡄⠀⠀⢰⣿⣿⣿⢯⣽⢯⣳⢃⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢜⡆⠀⢂⠐⡈⢆⡙⡜⡽⣿⡇⠀⠀⣱⠂⠀⡗⠀⠀⣼⣿⣳⢏⣿⢯⠃⢣⢻⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡽⡇⠣⢄⠀⠠⠀⡐⢌⣹⢹⠇⠀⠀⢸⠀⢹⠃⠀⠀⣿⡷⣡⠯⢐⠋⢠⣿⡛⢳⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢚⡘⢧⠘⡬⢀⠥⠀⠠⠀⠒⢸⡀⠀⢀⠀⠄⠁⠀⠀⢠⢿⠻⠈⠠⢁⠄⡜⡟⣷⣿⣯⢄⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣽⢣⠣⠜⡠⢃⠬⡑⠠⠁⠀⠀⡇⠀⠸⡄⠀⠀⠀⡼⡜⠀⠠⠐⡵⠝⣾⢹⣷⢻⣿⣿⣷⡂⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢐⡏⠆⠀⢊⠰⡁⢂⠡⠈⠀⠀⠀⢱⠀⠀⠀⠈⠈⠀⣰⠁⠀⢁⡠⢂⢪⠏⣎⣿⢰⣿⣿⣿⣿⣧⣄⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⡠⠊⢢⠘⡆⠀⠢⡑⢂⠠⠀⠀⠀⡀⠀⠳⢤⣄⣀⣠⠴⠃⠀⠀⠀⠄⡸⠋⢠⠙⢋⡟⣿⣿⣿⣿⢿⣯⠁⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠠⣔⡋⣧⠀⠀⠷⠀⡀⠱⠀⢂⠁⠀⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠁⠀⡠⣰⠟⣠⡿⣹⣿⣻⣿⣿⣮⢿⡣⠀⠀⠀⠀
⠀⠀⠀⠀⢠⢊⢅⣃⢻⠀⡀⠀⠂⠐⢀⠀⠂⠀⠀⠂⠀⠀⠀⢀⠀⠂⠀⠐⠀⣀⢁⡔⠀⣬⠲⢿⡫⢞⠝⣵⣿⣿⣿⣯⢿⣿⣄⠀⠀⠀
⠀⠀⠀⠀⡴⢋⠎⡔⡣⠜⠠⢀⠀⠀⠀⠄⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⡰⠛⠀⣠⡞⠃⣉⣭⠞⣩⣾⣿⣿⣿⣿⣿⡷⣟⡶⡀⠀⠀
⠀⠀⠀⣨⠆⠃⡄⡧⡇⡏⠔⡂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠶⠉⢀⠚⣍⠤⢖⣿⣿⣿⣿⣿⣿⣿⣾⣮⣻⡌⠀⠀
⠀⠀⠀⠀⡐⢈⡞⣥⢳⠉⢢⢁⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⢀⠀⠀⣠⢤⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣷⣿⠀⠀
⠀⠀⠀⠀⠐⡠⣵⢋⣆⡑⠣⡌⠐⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⣡⣾⣿⠿⣿⣿⠿⣫⣿⣿⣿⣿⣿⡟⢿⣿⡏⠃⠀
⠀⠀⠀⠀⠐⡰⢹⣾⡏⡎⠵⡈⠅⢂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠃⠏⢉⡀⡔⣋⠵⢾⣿⣿⣿⣿⢿⡻⢿⡎⠙⡇⠀⠀
⠀⠀⠀⠀⠡⢀⠣⠜⢧⢃⢣⡑⢌⠀⢂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⢈⠀⡡⠒⢦⠱⡘⠡⣔⣫⢶⣹⡾⢏⠲⣹⠂⡑⠀⠀⠀
{RESET}
{BOLD}{CYAN}==================================================={RESET}
{sys_info}
{user_info}
{time_info}
{ip_info}
{BOLD}{CYAN}==================================================={RESET}
    """
    print(banner)

def get_public_ip():
    """Genel IP adresini al"""
    try:
        response = requests.get('https://api.ipify.org', timeout=3)
        return response.text
    except:
        return "Bilinmiyor"

# --- GELİŞMİŞ SANAL ORTAM YÖNETİMİ ---
def check_virtualenv():
    """Virtualenv'in kurulu olup olmadığını kontrol et"""
    try:
        subprocess.run(['virtualenv', '--version'], 
                       stdout=subprocess.PIPE, 
                       stderr=subprocess.PIPE, 
                       check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def install_virtualenv():
    """Virtualenv'i sistem genelinde kur"""
    print(f"{YELLOW}[!] virtualenv kurulu değil. Kurulum yapılıyor...{RESET}")
    try:
        subprocess.run([sys.executable, '-m', 'pip', 'install', 'virtualenv'],
                       check=True)
        print(f"{GREEN}[+] virtualenv başarıyla kuruldu{RESET}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"{RED}[HATA] virtualenv kurulumu başarısız: {e}{RESET}")
        return False

def setup_virtual_environment(module_info):
    """Sanal ortamı oluştur ve bağımlılıkları yükle"""
    module_path = module_info['path']
    venv_name = module_info['venv']
    venv_path = os.path.join(module_path, venv_name)
    requirements = os.path.join(module_path, module_info['requirements'])
    
    # Virtualenv kontrolü
    if not check_virtualenv():
        if not install_virtualenv():
            return None
    
    # Sanal ortam oluştur
    if not os.path.exists(venv_path):
        print(f"{CYAN}[*] Sanal ortam oluşturuluyor: {venv_name}{RESET}")
        try:
            subprocess.run(['virtualenv', venv_path], check=True)
            print(f"{GREEN}[+] Sanal ortam oluşturuldu{RESET}")
        except subprocess.CalledProcessError as e:
            print(f"{RED}[HATA] Sanal ortam oluşturulamadı: {e}{RESET}")
            return None
    
    # Bağımlılıkları yükle
    pip_path = os.path.join(venv_path, 'bin', 'pip')
    if os.path.exists(requirements):
        print(f"{CYAN}[*] Bağımlılıklar yükleniyor...{RESET}")
        try:
            subprocess.run([pip_path, 'install', '-r', requirements, '--upgrade'], 
                           check=True)
            print(f"{GREEN}[+] Bağımlılıklar başarıyla yüklendi{RESET}")
        except subprocess.CalledProcessError as e:
            print(f"{RED}[HATA] Bağımlılık yükleme hatası: {e}{RESET}")
            print(f"{YELLOW}Lütfen {requirements} dosyasını kontrol edin{RESET}")
    else:
        print(f"{YELLOW}[!] Bağımlılık dosyası bulunamadı: {requirements}{RESET}")
    
    return os.path.join(venv_path, 'bin', 'python')

# --- GELİŞMİŞ MODÜL YÖNETİMİ ---
def validate_target(target, target_type='url'):
    """Hedef doğrulama"""
    if target_type == 'url':
        url_pattern = re.compile(
            r'^(https?://)?'  # http:// or https://
            r'(([A-Z0-9-]+\.)+[A-Z]{2,63})'  # domain
            r'(:[0-9]{1,5})?'  # port
            r'(/.*)?$', re.IGNORECASE)
        return bool(url_pattern.match(target))
    elif target_type == 'ip':
        ip_pattern = re.compile(
            r'^(\d{1,3}\.){3}\d{1,3}(:\d{1,5})?$')  # IP:port
        return bool(ip_pattern.match(target))
    return True

def get_web_scanner_args(module_path):
    """Web Scanner için argümanları al"""
    args = []
    
    while True:
        target = input(f"{YELLOW}Hedef URL: {RESET}").strip()
        if validate_target(target, 'url'):
            args.extend(['-t', target])
            break
        print(f"{RED}Geçersiz URL formatı! Örnek: http://example.com{RESET}")
    
    if input(f"{YELLOW}Proxy kullanılsın mı? (e/h): {RESET}").lower() == 'e':
        proxy_file = input(f"{YELLOW}Proxy listesi: {RESET}").strip()
        proxy_path = os.path.join(module_path, proxy_file)
        
        if os.path.exists(proxy_path):
            args.extend(['-pl', proxy_file])
        else:
            print(f"{RED}Proxy dosyası bulunamadı: {proxy_path}{RESET}")
    
    # Ek güvenlik tarama seçenekleri
    if input(f"{YELLOW}Gelişmiş tarama yapılsın mı? (e/h): {RESET}").lower() == 'e':
        args.append('--advanced')
    
    return args

def get_ddos_args():
    """DDoS için argümanları al"""
    args = []
    
    while True:
        target = input(f"{YELLOW}Hedef IP:Port: {RESET}").strip()
        if validate_target(target, 'ip'):
            ip, _, port = target.partition(':')
            args.extend([ip, port or '80'])
            break
        print(f"{RED}Geçersiz IP formatı! Örnek: 192.168.1.1:80{RESET}")
    
    # Saldırı parametreleri
    params = {
        'attack_type': ('Saldırı Türü (SYN/HTTP/MIXED/UDP)', 'MIXED'),
        'duration': ('Süre (saniye)', '600'),
        'intensity': ('Yoğunluk (1-10)', '8'),
        'threads': ('Thread sayısı (1-1000)', '500'),
        'encrypted': ('Şifreleme (AÇIK/KAPALI)', 'KAPALI'),
        'proxy': ('Proxy kullanımı (AÇIK/KAPALI)', 'KAPALI')
    }
    
    for key, (prompt, default) in params.items():
        value = input(f"{YELLOW}{prompt} [{default}]: {RESET}").strip() or default
        args.append(value.upper())
    
    return args

def get_network_recon_args():
    """Ağ ve Host Keşfi için argümanları al"""
    target = input(f"{YELLOW}Hedef IP/Subnet: {RESET}").strip()
    args = [target]
    
    # Ek seçenekler
    if input(f"{YELLOW}Port taraması yapılsın mı? (e/h): {RESET}").lower() == 'e':
        args.append('--port-scan')
    
    if input(f"{YELLOW}OS tespiti yapılsın mı? (e/h): {RESET}").lower() == 'e':
        args.append('--os-detection')
    
    return args

def get_credential_management_args():
    """Kimlik Bilgisi Yönetimi için argümanları al"""
    print(f"{YELLOW}Kimlik Bilgisi Yönetimi modülü için lütfen aşağıdaki seçeneklerden birini seçin:{RESET}")
    print("  1. Hash Kırma")
    print("  2. Brute-Force")
    print("  3. Credential Stuffing")
    print("  4. Credential Injection")
    choice = input(f"{YELLOW}Seçiminiz (1-4): {RESET}").strip()
    
    args = [choice]
    
    if choice == '1':
        hash_val = input(f"{YELLOW}Kırılacak hash değeri: {RESET}").strip()
        hash_type = input(f"{YELLOW}Hash tipi (MD5, SHA256, NTLM vb.): {RESET}").strip()
        wordlist = input(f"{YELLOW}Wordlist dosyası: {RESET}").strip() or 'rockyou.txt'
        args.extend([hash_val, hash_type, wordlist])
    elif choice == '2':
        target_bf = input(f"{YELLOW}Hedef IP/Domain: {RESET}").strip()
        port_bf = input(f"{YELLOW}Port: {RESET}").strip()
        protocol_bf = input(f"{YELLOW}Protokol (SSH, FTP, SMB, RDP): {RESET}").strip()
        users_file = input(f"{YELLOW}Kullanıcı adı listesi: {RESET}").strip()
        passwords_file = input(f"{YELLOW}Şifre listesi: {RESET}").strip()
        args.extend([target_bf, port_bf, protocol_bf, users_file, passwords_file])
    elif choice == '3':
        target_cs = input(f"{YELLOW}Hedef URL: {RESET}").strip()
        combo_file = input(f"{YELLOW}Kombinasyon dosyası: {RESET}").strip()
        args.extend([target_cs, combo_file])
    elif choice == '4':
        target_ci = input(f"{YELLOW}Hedef URL: {RESET}").strip()
        payload = input(f"{YELLOW}SQL Injection payload: {RESET}").strip()
        args.extend([target_ci, payload])
    else:
        print(f"{RED}Geçersiz seçim!{RESET}")
        return get_credential_management_args()
    
    return args

def get_exploitation_args():
    """Sömürü ve Sömürü Sonrası için argümanları al"""
    target = input(f"{YELLOW}Hedef IP: {RESET}").strip()
    port = input(f"{YELLOW}Port: {RESET}").strip()
    exploit = input(f"{YELLOW}Exploit adı: {RESET}").strip()
    payload = input(f"{YELLOW}Payload: {RESET}").strip()
    
    return [target, port, exploit, payload]

def get_evasion_args():
    """Atlatma ve Anti-Forensics için argümanları al"""
    print(f"{YELLOW}Atlatma ve Anti-Forensics modülü için lütfen aşağıdaki seçeneklerden birini seçin:{RESET}")
    print("  1. Trafik Şifreleme")
    print("  2. Log Temizleme")
    print("  3. İz Karartma")
    choice = input(f"{YELLOW}Seçiminiz (1-3): {RESET}").strip()
    
    args = [choice]
    
    if choice == '1':
        target = input(f"{YELLOW}Hedef IP: {RESET}").strip()
        port = input(f"{YELLOW}Port: {RESET}").strip()
        args.extend([target, port])
    elif choice == '2':
        log_path = input(f"{YELLOW}Log dosya yolu: {RESET}").strip()
        args.append(log_path)
    elif choice == '3':
        ip_count = input(f"{YELLOW}Sahte IP sayısı: {RESET}").strip() or '10'
        args.append(ip_count)
    
    return args

def get_reporting_args():
    """Raporlama ve Dashboard için argümanları al"""
    print(f"{YELLOW}Raporlama ve Dashboard modülü için lütfen aşağıdaki seçeneklerden birini seçin:{RESET}")
    print("  1. Rapor Oluştur")
    print("  2. Dashboard Başlat")
    choice = input(f"{YELLOW}Seçiminiz (1-2): {RESET}").strip()
    
    args = [choice]
    
    if choice == '1':
        scan_type = input(f"{YELLOW}Tarama türü: {RESET}").strip()
        output_format = input(f"{YELLOW}Çıktı formatı (HTML/PDF/CSV): {RESET}").strip()
        args.extend([scan_type, output_format])
    elif choice == '2':
        port = input(f"{YELLOW}Dashboard portu: {RESET}").strip() or '8080'
        args.append(port)
    
    return args

def run_module(module_key):
    """Seçilen modülü çalıştır"""
    global stop_spinner
    
    if module_key not in MODULE_CONFIG:
        print(f"{RED}Geçersiz modül seçimi!{RESET}")
        return
    
    module_info = MODULE_CONFIG[module_key]
    
    # Modül hazırlığı
    print(f"{CYAN}\n[*] {module_info['name']} başlatılıyor...{RESET}")
    original_dir = os.getcwd()
    
    try:
        # Dizin değiştir
        os.chdir(module_info['path'])
        
        # Sanal ortamı hazırla
        stop_spinner = False
        spinner_thread = threading.Thread(
            target=loading_spinner, 
            args=(f"{module_info['name']} hazırlanıyor",)
        )
        spinner_thread.start()
        
        python_exec = setup_virtual_environment(module_info)
        
        stop_spinner = True
        spinner_thread.join(0.5)
        
        if not python_exec:
            print(f"{RED}[!] Modül başlatılamadı{RESET}")
            return
        
        # Modül script yolunu kontrol et
        script_path = os.path.join(module_info['path'], module_info['script'])
        if not os.path.exists(script_path):
            print(f"{RED}[!] Script bulunamadı: {script_path}{RESET}")
            return
        
        # Modüle özgü argümanları al
        args = []
        if module_key == '1':
            args = get_web_scanner_args(module_info['path'])
        elif module_key == '2':
            args = get_ddos_args()
        elif module_key == '3':
            args = get_network_recon_args()
        elif module_key == '4':
            args = get_credential_management_args()
        elif module_key == '5':
            args = get_exploitation_args()
        elif module_key == '6':
            args = get_evasion_args()
        elif module_key == '7':
            args = get_reporting_args()
        
        # Modülü çalıştır
        print(f"{GREEN}[*] {module_info['name']} çalıştırılıyor...{RESET}")
        cmd = [python_exec, module_info['script']] + args
        print(f"{CYAN}Komut: {' '.join(cmd)}{RESET}")
        
        subprocess.run(cmd)
        
    except Exception as e:
        print(f"{RED}[HATA] Modül çalıştırılırken hata: {e}{RESET}")
    finally:
        os.chdir(original_dir)
        print(f"{GREEN}[*] {module_info['name']} tamamlandı{RESET}")
        time.sleep(1)

# --- GELİŞMİŞ ANA MENÜ ---
def display_menu():
    """Ana menüyü göster"""
    global stop_spinner
    
    print_header()
    
    # Modül listesi
    print(f"{BOLD}{UNDERLINE}{CYAN}MODÜLLER:{RESET}\n")
    for key, info in MODULE_CONFIG.items():
        status_color = GREEN if info['status'] == 'active' else YELLOW
        status_text = "AKTİF" if info['status'] == 'active' else "GELİŞTİRME"
        print(f"  {BOLD}{key}. {info['name']} {status_color}[{status_text}]{RESET}")
    
    # Diğer seçenekler
    print(f"\n{BOLD}{UNDERLINE}{CYAN}ARAÇLAR:{RESET}")
    print(f"  {BOLD}U. Sistem Güncellemeleri{RESET}")
    print(f"  {BOLD}T. Tüm Bağımlılıkları Yükle{RESET}")
    print(f"  {BOLD}C. Önbelleği Temizle{RESET}")
    print(f"  {BOLD}S. Sistem Durumu{RESET}")
    print(f"  {BOLD}0. Çıkış{RESET}")
    
    print(f"\n{BOLD}{CYAN}==================================================={RESET}")

def update_system():
    """Sistem güncellemelerini çalıştır"""
    print(f"{CYAN}[*] Sistem güncellemeleri kontrol ediliyor...{RESET}")
    try:
        if os.name == 'nt':
            subprocess.run(['powershell', 'Update-Module'], check=True)
        else:
            subprocess.run(['sudo', 'apt', 'update'], check=True)
            subprocess.run(['sudo', 'apt', 'upgrade', '-y'], check=True)
        print(f"{GREEN}[+] Sistem başarıyla güncellendi{RESET}")
    except subprocess.CalledProcessError as e:
        print(f"{RED}[HATA] Güncelleme başarısız: {e}{RESET}")

def install_all_dependencies():
    """Tüm bağımlılıkları yükle"""
    print(f"{CYAN}[*] Tüm modül bağımlılıkları yükleniyor...{RESET}")
    for key, module in MODULE_CONFIG.items():
        print(f"\n{BOLD}{module['name']}{RESET}")
        setup_virtual_environment(module)
    print(f"{GREEN}[+] Tüm bağımlılıklar yüklendi{RESET}")

def clear_cache():
    """Önbelleği temizle"""
    print(f"{CYAN}[*] Önbellek temizleniyor...{RESET}")
    try:
        # Sanal ortamları temizle
        for module in MODULE_CONFIG.values():
            venv_path = os.path.join(module['path'], module['venv'])
            if os.path.exists(venv_path):
                shutil.rmtree(venv_path)
                print(f"  {GREEN}- {venv_path} kaldırıldı{RESET}")
        
        # Pip cache temizle
        subprocess.run([sys.executable, '-m', 'pip', 'cache', 'purge'])
        print(f"{GREEN}[+] Önbellek başarıyla temizlendi{RESET}")
    except Exception as e:
        print(f"{RED}[HATA] Önbellek temizlenemedi: {e}{RESET}")

def system_status():
    """Sistem durumunu göster"""
    print(f"\n{BOLD}{CYAN}=== SİSTEM DURUMU ==={RESET}")
    print(f"{BOLD}İşletim Sistemi:{RESET} {platform.system()} {platform.release()}")
    print(f"{BOLD}Python Sürümü:{RESET} {platform.python_version()}")
    print(f"{BOLD}CPU Çekirdek Sayısı:{RESET} {os.cpu_count()}")
    print(f"{BOLD}Kullanılabilir Bellek:{RESET} {round(os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES') / (1024.**3), 2)} GB")
    print(f"{BOLD}Genel IP:{RESET} {get_public_ip()}")

# --- GELİŞMİŞ ANA PROGRAM ---
def main():
    # Root kontrolü
    if os.geteuid() != 0:
        print(f"{RED}[!] Root yetkisi gereklidir!{RESET}")
        print(f"Lütfen şu komutla çalıştırın: {BOLD}sudo python3 {sys.argv[0]}{RESET}")
        sys.exit(1)
    
    # Ana döngü
    while True:
        display_menu()
        choice = input(f"\n{BOLD}{CYAN}>>> Seçiminiz: {RESET}").upper()
        
        if choice == '0':
            print(f"{RED}Çıkış yapılıyor... Güvende kalın!{RESET}")
            break
        
        elif choice in MODULE_CONFIG:
            run_module(choice)
        
        elif choice == 'U':
            update_system()
            time.sleep(2)
        
        elif choice == 'T':
            install_all_dependencies()
            time.sleep(2)
        
        elif choice == 'C':
            clear_cache()
            time.sleep(2)
        
        elif choice == 'S':
            system_status()
            input(f"\n{BOLD}{CYAN}Devam etmek için Enter'a basın...{RESET}")
        
        else:
            print(f"{RED}Geçersiz seçim!{RESET}")
            time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{RED}Program kapatılıyor...{RESET}")
        sys.exit(0)
