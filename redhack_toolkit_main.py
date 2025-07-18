import os
import sys
import time
import subprocess
import pyfiglet # pyfiglet kütüphanesinin yüklü olduğundan emin olun (pip install pyfiglet)
import threading
import itertools

# ANSI renk kodları
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"

# Temel dizin, bu script'in bulunduğu yer
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Modül dizinleri ve içlerindeki ana script adları
# ve bağımlılık dosyaları ile sanal ortam adları
# DİKKAT: Bu yollar sizin belirttiğiniz dizinlere göre ayarlandı.
# İçindeki ana Python script adlarını ve requirements.txt adlarını kontrol edin ve gerekirse güncelleyin.
MODULE_CONFIG = {
    '1': { # Web Zafiyet Tarayıcısı (Web Scanner)
        'name': 'redhack_scanner.py',
        'path': os.path.join(BASE_DIR, 'RedHackscanner'),
        'venv': 'scanner_env',
        'requirements': 'requirements.txt' # Bu modülün bağımlılık listesi dosyası
    },
    '2': { # DDoS Çerçevesi (DDoS Framework)
        'name': 'Dddos.v2.py',
        'path': os.path.join(BASE_DIR, 'DDdos'),
        'venv': 'ddos_env',
        'requirements': 'requirements.txt' # Bu modülün bağımlılık listesi dosyası
    },
    '3': { # Ağ ve Host Keşfi (Network Recon)
        'name': 'Network & Host Reconnaissance Module .py',
        'path': os.path.join(BASE_DIR, 'Network & Host Reconnaissance Module'),
        'venv': 'recon_env',
        'requirements': 'requirements.txt' # Bu modülün bağımlılık listesi dosyası
    },
    '4': { # Kimlik Bilgisi Yönetimi (Credential Management)
        'name': 'Credential & Access Management Module.py',
        'path': os.path.join(BASE_DIR, 'Credential & Access Management Module'),
        'venv': 'cred_env',
        'requirements': 'requirements.txt' # Bu modülün bağımlılık listesi dosyası
    },
    '5': { # Sömürü ve Sömürü Sonrası (Exploitation)
        'name': 'exploitation_module.py',
        'path': os.path.join(BASE_DIR, 'NetHack'),
        'venv': 'exploit_env',
        'requirements': 'requirements_exploit.txt' # Örnek bağımlılık dosyası
    },
    '6': { # Atlatma ve Anti-Forensics (Evasion)
        'name': 'evasion_module.py',
        'path': os.path.join(BASE_DIR, 'NetHack'),
        'venv': 'evasion_env',
        'requirements': 'requirements_evasion.txt' # Örnek bağımlılık dosyası
    },
    '7': { # Raporlama ve Dashboard (Reporting)
        'name': 'reporting_module.py',
        'path': os.path.join(BASE_DIR, 'NetHack'),
        'venv': 'reporting_env',
        'requirements': 'requirements_reporting.txt' # Örnek bağımlılık dosyası
    }
}

# --- YENİ ANİMASYON FONKSİYONLARI ---
stop_spinner = False

def print_animated_ascii(text, color=GREEN, font="standard", delay=0.001):
    """ASCII metni harf harf animasyonla yazdırır."""
    ascii_text = pyfiglet.figlet_format(text, font=font)
    for char in ascii_text:
        sys.stdout.write(f"{color}{char}{RESET}")
        sys.stdout.flush()
        time.sleep(delay)
    print() # Yeni satıra geç

def loading_spinner():
    """Sağ tarafta dönen animasyonlu barlar oluşturur."""
    spinner_chars = itertools.cycle(['|', '/', '-', '\\'])
    colors = [RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN]
    color_cycle = itertools.cycle(colors)
    
    while not stop_spinner:
        sys.stdout.write(f"\r{next(color_cycle)}{next(spinner_chars)}{RESET} Yükleniyor...")
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write("\r" + " " * 20 + "\r") # Spinner'ı temizle

# --- MENÜ GÖRÜNTÜLEME ---
def display_menu():
    global stop_spinner
    stop_spinner = False
    spinner_thread = threading.Thread(target=loading_spinner, daemon=True)
    spinner_thread.start()

    os.system('cls' if os.name == 'nt' else 'clear')
    
    # S3LOC ASCII gösterisi
    s3loc_raw_ascii = """
 _____  _      ___   ____  ____  
|  ___|| |    / _ \ / ___|| ___| 
| |__  | |   | | | |\___ \|___ \ 
|  __| | |___ | |_| | ___) |___) |
|_|    |_____|\___/ |____/|____/ 
                                  
"""
    # S3LOC'u doğrudan yazdır, pyfiglet ile değil, çünkü zaten hazır bir ASCII
    print(f"{GREEN}{BOLD}{s3loc_raw_ascii}{RESET}") 
    
    # REDHACK için animasyonlu pyfiglet
    print_animated_ascii("REDHACK", color=CYAN, font="standard", delay=0.0005)

    print(f"{BOLD}{CYAN}======================================{RESET}")
    print(f"{BOLD}{CYAN}    REDHACK TOOLKIT - ELITE CYBER OPS{RESET}")
    print(f"{BOLD}{CYAN}======================================{RESET}")
    print(f"{GREEN}[1] Web Zafiyet Tarayıcısı (Web Scanner){RESET}")
    print(f"{GREEN}[2] DDoS Çerçevesi (DDoS Framework){RESET}")
    print(f"{GREEN}[3] Ağ ve Host Keşfi (Network Recon){RESET}")
    print(f"{GREEN}[4] Network & Host Reconnaissance Module {RESET}")
    print(f"{YELLOW}[5] Sömürü ve Sömürü Sonrası (Exploitation) {RED}(Geliştirilecek){RESET}")
    print(f"{YELLOW}[6] Atlatma ve Anti-Forensics (Evasion) {RED}(Geliştirilecek){RESET}")
    print(f"{YELLOW}[7] Raporlama ve Dashboard (Reporting) {RED}(Geliştirilecek){RESET}")
    print(f"{BOLD}{CYAN}======================================{RESET}")
    print(f"{RED}[0] Çıkış{RESET}")
    print(f"{BOLD}{CYAN}======================================{RESET}")
    
    stop_spinner = True # Spinner'ı durdur

def setup_virtual_environment(module_path, venv_name, requirements_file):
    """Sanal ortamı oluşturur ve bağımlılıkları yükler."""
    venv_path = os.path.join(module_path, venv_name)
    python_executable = os.path.join(venv_path, 'bin', 'python3')
    pip_executable = os.path.join(venv_path, 'bin', 'pip')
    reqs_path = os.path.join(module_path, requirements_file)

    if not os.path.exists(venv_path):
        print(f"{CYAN}[*] Sanal ortam '{venv_name}' oluşturuluyor...{RESET}")
        try:
            subprocess.run([sys.executable, '-m', 'venv', venv_path], check=True, capture_output=True)
            print(f"{GREEN}[+] Sanal ortam oluşturuldu.{RESET}")
        except subprocess.CalledProcessError as e:
            print(f"{RED}[HATA] Sanal ortam oluşturulamadı: {e.stderr.decode()}{RESET}")
            return False
        except Exception as e:
            print(f"{RED}[HATA] Sanal ortam oluşturulurken beklenmeyen hata: {str(e)}{RESET}")
            return False

    if os.path.exists(reqs_path):
        print(f"{CYAN}[*] Bağımlılıklar '{venv_name}' içine yükleniyor...{RESET}")
        try:
            # --break-system-packages Kali Linux için gerekli olabilir
            subprocess.run([pip_executable, 'install', '-r', reqs_path, '--break-system-packages'], check=True, capture_output=True)
            print(f"{GREEN}[+] Bağımlılıklar başarıyla yüklendi.{RESET}")
        except subprocess.CalledProcessError as e:
            print(f"{RED}[HATA] Bağımlılıklar yüklenirken hata: {e.stderr.decode()}{RESET}")
            print(f"{YELLOW}Lütfen '{reqs_path}' dosyasındaki paket isimlerini ve Python sürüm uyumluluğunu kontrol edin.{RESET}")
            return False
        except Exception as e:
            print(f"{RED}[HATA] Bağımlılıklar yüklenirken beklenmeyen hata: {str(e)}{RESET}")
            return False
    else:
        print(f"{YELLOW}[!] Bağımlılık dosyası '{requirements_file}' '{module_path}' içinde bulunamadı. Bağımlılıklar otomatik yüklenmeyecek.{RESET}")
        print(f"{YELLOW}Modülün çalışması için bağımlılıkları manuel yüklemeniz gerekebilir.{RESET}")
        time.sleep(2)

    return python_executable

def run_module(module_key):
    global stop_spinner
    module_info = MODULE_CONFIG.get(module_key)
    if not module_info:
        print(f"{RED}Geçersiz seçim! Lütfen menüden geçerli bir numara girin.{RESET}")
        time.sleep(2)
        return

    module_name = module_info['name']
    module_path = module_info['path']
    venv_name = module_info['venv']
    requirements_file = module_info['requirements']

    print(f"{CYAN}[*] '{module_info['name'].replace('.py', '')}' modülü hazırlanıyor...{RESET}")

    # Modülün kendi dizinine git
    original_cwd = os.getcwd() # Mevcut çalışma dizinini kaydet
    try:
        os.chdir(module_path)
    except FileNotFoundError:
        print(f"{RED}[HATA] Modül dizini '{module_path}' bulunamadı. Lütfen kontrol edin.{RESET}")
        time.sleep(3)
        os.chdir(original_cwd)
        return

    # Sanal ortamı kur ve bağımlılıkları yükle
    # Spinner'ı tekrar başlat (sanal ortam kurulumu sırasında gösterim için)
    stop_spinner = False
    spinner_thread = threading.Thread(target=loading_spinner, daemon=True)
    spinner_thread.start()
    
    python_executable = setup_virtual_environment(module_path, venv_name, requirements_file)
    
    stop_spinner = True # Spinner'ı durdur
    spinner_thread.join(timeout=0.2) # Spinner thread'inin kapanmasını bekle

    if not python_executable:
        os.chdir(original_cwd) # Ana dizine geri dön
        return

    # Ana script'in tam yolu
    script_path = os.path.join(module_path, module_name)

    # Dosyanın varlığını kontrol et
    if not os.path.exists(script_path):
        print(f"{RED}[HATA] '{module_name}' dosyası '{module_path}' içinde bulunamadı.{RESET}")
        print(f"{YELLOW}Lütfen dosya adlarını ve yolları '{os.path.basename(__file__)}' içinde kontrol edin.{RESET}")
        time.sleep(3)
        os.chdir(original_cwd) # Ana dizine geri dön
        return
        
    print(f"{GREEN}[*] '{module_info['name'].replace('.py', '')}' başlatılıyor...{RESET}")
    time.sleep(1)

    # Örnek: Modüllere argüman sorma (bu kısmı her modül için özelleştirmelisin)
    module_args = []
    if module_key == '1': # Web Zafiyet Tarayıcısı
        target_url = input(f"{YELLOW}Hedef URL'yi girin (örn: http://example.com): {RESET}")
        if target_url:
            module_args.extend(['-t', target_url])
        proxy_choice = input(f"{YELLOW}Proxy kullanılsın mı? (evet/hayır): {RESET}").lower()
        if proxy_choice == 'evet':
            proxy_path = input(f"{YELLOW}Proxy listesi dosyasının yolu (örn: proxy.txt): {RESET}")
            if os.path.exists(os.path.join(module_path, proxy_path)):
                 module_args.extend(['-pl', proxy_path])
            else:
                print(f"{RED}[!] Belirtilen proxy listesi dosyası bulunamadı, proxy kullanılmayacak.{RESET}")
                time.sleep(1)

    elif module_key == '2': # DDoS Çerçevesi
        target_ip = input(f"{YELLOW}Hedef IP'yi girin: {RESET}")
        target_port = input(f"{YELLOW}Hedef Port'u girin: {RESET}")
        if target_ip and target_port:
            module_args.extend([target_ip, target_port])
            attack_type = input(f"{YELLOW}Saldırı Türü (SYN, HTTP, MIXED vb. - varsayılan MIXED): {RESET}") or "MIXED"
            duration = input(f"{YELLOW}Süre (saniye - varsayılan 600): {RESET}") or "600"
            intensity = input(f"{YELLOW}Yoğunluk (1-10 - varsayılan 8): {RESET}") or "8"
            encrypted = input(f"{YELLOW}Şifreleme (ENCRYPT/KAPALI - varsayılan KAPALI): {RESET}").upper() or "KAPALI"
            compressed = input(f"{YELLOW}Sıkıştırma (COMPRESS/KAPALI - varsayılan KAPALI): {RESET}").upper() or "KAPALI"
            tunnel = input(f"{YELLOW}Tünelleme (TUNNEL/KAPALI - varsayılan KAPALI): {RESET}").upper() or "KAPALI"
            http2 = input(f"{YELLOW}HTTP/2 (HTTP2/KAPALI - varsayılan KAPALI): {RESET}").upper() or "KAPALI"
            module_args.extend([attack_type, duration, intensity, encrypted, compressed, tunnel, http2])
        else:
            print(f"{RED}[!] DDoS için hedef IP ve port gerekli. Modül başlatılamadı.{RESET}")
            os.chdir(original_cwd)
            time.sleep(2)
            return

    elif module_key == '3': # Ağ ve Host Keşfi
        target_recon = input(f"{YELLOW}Hedef Domain veya IP'yi girin: {RESET}")
        if target_recon:
            module_args.append(target_recon)
        else:
            print(f"{RED}[!] Keşif için hedef gerekli. Modül başlatılamadı.{RESET}")
            os.chdir(original_cwd)
            time.sleep(2)
            return

    elif module_key == '4': # Kimlik Bilgisi Yönetimi
        print(f"{YELLOW}Kimlik Bilgisi Yönetimi modülü için parametreler modül içinde sorulacaktır veya manuel olarak eklemeniz gerekecektir.{RESET}")
        # Örneğin:
        # hash_type = input(f"{YELLOW}Hash türü (MD5, NTLM vb.): {RESET}")
        # hash_value = input(f"{YELLOW}Hash değeri: {RESET}")
        # module_args.extend(['--hash-type', hash_type, '--hash-value', hash_value])

    # Diğer modüller için (5, 6, 7) de benzer şekilde argümanları alabilirsin

    try:
        # Modülü çalıştırma
        print(f"{CYAN}Komut: sudo {python_executable} {script_path} {' '.join(module_args)}{RESET}") # Debug için komutu göster
        subprocess.run(['sudo', python_executable, script_path] + module_args, check=False)
        
    except Exception as e:
        print(f"{RED}[HATA] Modül başlatılırken hata oluştu: {e}{RESET}")
        time.sleep(3)

    os.chdir(original_cwd) # Ana dizine geri dön
    print(f"\n{GREEN}[*] '{module_name}' kapatıldı. Ana menüye dönülüyor...{RESET}")
    time.sleep(2)

def main():
    while True:
        display_menu()
        choice = input(f"\n{BOLD}{CYAN}>>> Bir seçim yapın: {RESET}")

        if choice == '0':
            print(f"{RED}REDHACK TOOLKIT kapatılıyor... Güvende kalın!{RESET}")
            break
        elif choice in MODULE_CONFIG:
            run_module(choice)
        else:
            print(f"{RED}Geçersiz seçim! Lütfen menüden geçerli bir numara girin.{RESET}")
            time.sleep(2)

if __name__ == "__main__":
    # Script'in root yetkisiyle çalışıp çalışmadığını kontrol et
    if os.geteuid() != 0:
        print(f"{RED}[!] Bu ana arayüzün ROOT yetkisiyle çalıştırılması gerekmektedir (sudo python3 {os.path.basename(__file__)}).{RESET}")
        sys.exit(1)
        
    main()