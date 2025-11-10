# BEAR TOOLKIT — Düzenlenmiş Dokümantasyon

![BEAR TOOLKIT](https://github.com/user-attachments/assets/f5d9a4be-428d-4f62-9741-ae5794b11c41)

---

# ⚠️ Yasal ve Etik Uyarı

Bu yazılım **sadece** yasal ve etik güvenlik testleri, araştırma ve eğitim amaçları için tasarlanmıştır.
Herhangi bir yetkisiz ağa, sisteme veya hizmete karşı kullanımı **cezai ve hukuki sorumluluk** doğurur. Kullanıcı, yazılımı nasıl kullandığından tamamen sorumludur. Geliştirici ve dağıtıcısı, kötüye kullanımdan sorumlu tutulamaz.

---

# Hızlı Başlangıç

**Gereksinimler**

* Python 3.8 veya üstü (3.10+ önerilir)
* Root/sudo yetkisi gerektiren bazı modüller ve sistem araçları
* Modüllere özel API anahtarları (Shodan, Censys vb.) bazı fonksiyonlar için gereklidir

**Önerilen çalışma ortamı**

* Debian/Ubuntu/Kali tabanlı dağıtımlar
* Her modül için izole Python sanal ortamı (venv) kullanımı tavsiye edilir

---

# Kurulum Adımları

1. Sistem paketlerini güncelleyin:

```bash
sudo apt update
sudo apt full-upgrade -y
sudo apt autoremove -y
```

2. Gerekli sistem paketlerini yükleyin (örnek):

```bash
sudo apt install -y python3-pip python3-venv python3-dev libbluetooth-dev libssl-dev libffi-dev build-essential nmap net-tools tshark snmpd snmp
# Selenium / headless tarayıcı için
sudo apt install -y chromium-browser chromium-chromedriver
```

3. Projeyi klonlayın veya indirin ve ana dizine gidin (örnek):

```bash
cd ~/Desktop
git clone <REPO_URL> BEAR-TOOLKIT
cd BEAR-TOOLKIT
```

4. Ana script bağımlılığını yükleyin (örnek):

```bash
sudo pip3 install pyfiglet
```

> Not: `sudo pip3 install` kullanımı sistem düzeyinde paket yüklediği için dikkatli olun. Tercihen proje bağımlılıklarını sanal ortam içinde yükleyin.

---

# Sanal Ortam ve Modül Bağımlılıkları

Projede her modül kendi `requirements.txt` dosyasını bulundurur. Ana menüden bir modül ilk kez çalıştırıldığında, o modül için otomatik olarak sanal ortam oluşturup bağımlılıkları yükleyecek bir mekanizma varsa bunu kullanın; yoksa elle kurun.

Örnek: bir modülün requirements dosyası

```
# DDdos/requirements.txt
nmap
psutil
requests
PySocks
h2
aioquic
scapy
dnspython
```

```
# RedHackscanner/requirements.txt
requests
beautifulsoup4
nmap3
selenium
tqdm
scikit-learn
numpy
cryptography
```

```
# NetworkRecon/requirements.txt
whois
dnspython
requests
python-nmap
shodan
censys
beautifulsoup4
```

Her modül klasöründe `requirements.txt` olduğundan emin olun. Gerekirse bu dosyaları güncelleyin.

**Sanal ortam (örnek kullanım)**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r module/requirements.txt
```

---

# Çalıştırma

Ana dizinde ana menüyü başlatın:

```bash
cd /path/to/BEAR-TOOLKIT
sudo python3 redhack_toolkit_main.py
```

Ana menü açıldığında, istenen modülün numarasını girin. Her modül kendi çalıştırma argümanlarını ve konfigürasyon talimatlarını gösterecektir.

> Not: Sudo gerektiren işlemler (low-level ağ işlemleri, belirli packet crafting) risk ve yan etki oluşturabilir. Yalnızca izinli ve izole ortamlarda çalıştırın.

---

# Modüller ve Özellikler (Özet)

Aşağıdaki liste projede yer alan ana modüllerin kısa açıklamasıdır. İsimlendirme ve içerik zaman içinde güncellenebilir.

## 1) Web Zafiyet Tarayıcısı (Web Scanner)

* Genel amaç: XSS, SQLi, LFI, RCE, SSTI, IDOR, SSRF, CSRF, güvenlik başlıkları, dizin listeleme, oturum zaafiyetleri vb. tespit.
* Özellikler:

  * Otomatik crawler ve form analizi
  * Selenium ile headless DOM tabanlı testler
  * WAF/IDS atlatma teknikleri (farklı kodlama ve enjeksiyon teknikleri)
  * IsolationForest tabanlı anomali tespiti (WAF davranış analizi)
  * OOB (Out-of-Band) test desteği (blind SQLi, SSRF vb.)
  * HTML/TXT raporlama, CVSS skorlama, PoC üretme

## 2) DDoS Çerçevesi (DDoS Framework)

* Genel amaç: Deneysel/araştırma amaçlı trafik oluşturma ve mitigasyon testi
* Özellikler:

  * Çoklu protokol desteği (SYN, UDP, ICMP, HTTP vb.)
  * Sistem optimizasyonu (kernel parametreleri)
  * Trafik adaptasyonu ve polimorfik paket üretimi
  * Proxy/tünelleme ve spoofing destekleri (araştırma/izole ortamlarda kullanılmalı)

## 3) Ağ ve Host Keşfi (Network Recon)

* Genel amaç: Pasif ve aktif keşif ile hedefin yüzeyini haritalama
* Özellikler:

  * WHOIS, DNS, sertifika şeffaflığı, arama motoru scraping
  * Shodan / Censys entegrasyonu (API anahtarı gerektirir)
  * Nmap tabanlı aktif taramalar (OS fingerprint, servis versiyon)
  * SNMP keşfi ve temel brute-force
  * Traceroute ve topoloji haritalama

## 4) Kimlik Bilgisi Yönetimi (Credential Management)

* Genel amaç: Hash kırma, brute-force, credential stuffing, post-exploitation araçları için entegrasyon
* Özellikler:

  * Hashcat / John entegrasyonları için çıktı hazırlama
  * Çok protokollü brute-force (SSH, FTP, SMB, Web formları)
  * Credential stuffing otomasyonları
  * İmpacket / mimikatz benzeri işlemler için entegrasyon (yalnızca yetkili/test ortamlarında)
  * Proxy/TOR destekleri

## 5–7) Geliştirilecek Modüller

* Exploitation / Post-Exploitation
* Evasion & Anti-Forensics
* Raporlama & Dashboard (web tabanlı görselleştirme ve merkezi veri toplama)

---

# Raporlama & Kayıt

* Tarama ve analiz sonuçları için modüller HTML ve/veya TXT formatında rapor üretebilir. Rapor formatının standartlaştırılması ve daha iyi okunabilirlik için `Reporting & Dashboard` modülünün geliştirilmesi tavsiye edilir.
* Öneri: Raporları zaman damgası ile `reports/` klasöründe saklayın ve hassas verileri (parolalar, hash’ler) şifreli bir vault içinde tutun.

---

# Güvenlik ve Etik Kuralları (Önemli)

1. **Yetki alın**: Herhangi bir test, tarama veya saldırı simülasyonu için hedef sistem sahibinden yazılı izin alın.
2. **İzinsiz kullanım yasaktır**: İzinsiz testler suç teşkil eder.
3. **Log ve iz bırakma**: Araçlar iz bırakabilir; test ortamlarını izole edin.
4. **Kişisel veriler**: Kişisel verilerle karşılaşıldığında yürürlükteki veri koruma yasalarına uyun.
5. **Sorumluluk reddi**: Geliştirici ve dağıtıcısı kötü amaçlı kullanımdan sorumlu tutulamaz.

---

# Katkıda Bulunma

Katkılar memnuniyetle karşılanır. Aşağıdaki adımlar takip edilebilir:

1. Fork yapın ve kendi dalınızda geliştirin.
2. Yeni özellikler için açık bir issue açın.
3. `README` ve `requirements.txt` dosyalarını güncel tutun.
4. Pull request gönderirken yapılan değişiklikleri açıklayan detaylı bir açıklama ekleyin.
5. Güvenlik açıkları bildirmek için özel kanallar kullanın; halka açık issue yerine sorumlu açıklama tercih edin.

---

# Lisans

Proje açık kaynaklı bir lisans altında dağıtılmaktadır. Lütfen proje içindeki `LICENSE` dosyasını kontrol edin ve lisans hüküm ve koşullarına uyun. (Varsa: ör. MIT, GPL-3.0 vb.)

---

# Örnek `requirements.txt` Yapısı (Klasör Bazlı)

```
/DDdos/requirements.txt
/RedHackscanner/requirements.txt
/NetworkRecon/requirements.txt
/CredentialManager/requirements.txt
```

Her dosya kendi modülünün gerektirdiği paketleri listeler. `scikit-learn` kullanımı gerekiyorsa `scikit-learn` yazın; `sklearn` PyPI paketi eskidir ve hataya sebep olabilir.

---

# Hızlı Hata Giderme (FAQ)

* **pip install sırasında “sklearn” hatası alıyorum**
  `sklearn` paketinin artık deprecated olduğu uyarısını görürsünüz. `scikit-learn` kullanın. `requirements.txt` içinde `sklearn` varsa `scikit-learn` ile değiştirin.

* **Modülün `best_partition` hatası veriyor**
  Bu genellikle `python-louvain` veya `community` paketlerinin sürüm uyumsuzluğundan kaynaklanır. Doğru paket (`python-louvain`) ve uyumlu sürümü yükleyin.

* **Raporda eksik veriler/boş sonuçlar**
  Girdi parametrelerini, izinleri ve gerekli API anahtarlarının doğru yüklü olduğunu kontrol edin. Ayrıca tarama izinleri ve ağ erişimi ayarlarını doğrulayın.

---

# İletişim

Projeyi geliştiren ekip veya repo sahipleriyle ilgili iletişim bilgileri `CONTRIBUTING.md` veya repo açıklamasında bulunmalıdır. Güvenlik açıkları için doğrudan ve özel iletişim kullanılmasını tavsiye edin.

---
