# CloudPanel Web Server Kurulum Kılavuzu

Bu doküman, **Ubuntu Server 24.04** üzerinde **CloudPanel** kurulumu için önerilen temel yapılandırmaları içerir. Amaç; güvenli, stabil ve uzun süre bakım gerektirmeyen bir sunucu elde etmektir.

---

## 🚀 Hızlı Kurulum (Otomatik Script)

Tüm kurulum adımlarını otomatik olarak yapmak için:

```bash
# Script'i indirin
wget https://raw.githubusercontent.com/OsmanYavuz-web/ubuntu-cloudpanel-installer/main/webserver-full-install.sh
# veya
curl -O https://raw.githubusercontent.com/OsmanYavuz-web/ubuntu-cloudpanel-installer/main/webserver-full-install.sh

# Çalıştırma izni verin
chmod +x webserver-full-install.sh

# Root yetkisiyle çalıştırın
sudo bash webserver-full-install.sh
```

### Script Özellikleri

✅ **Güvenli Tekrar Çalıştırma:** Script idempotent tasarımlıdır. Tekrar çalıştırırsanız:
- CloudPanel zaten kuruluysa atlanır (mevcut siteler korunur)
- Diğer servisler çalışıyorsa atlanır
- Sadece eksik olanlar kurulur ve optimizasyonlar güncellenir

✅ **Kurulum İçeriği:**
- Sistem güncellemeleri
- SSH, Fail2Ban, UFW (Firewall)
- 4GB Swap yapılandırması
- CloudPanel + MariaDB 11.4
- PHP optimizasyonları (Laravel için)
- Redis + PHP Redis extension (PECL ile otomatik)
- Nginx ve MariaDB optimizasyonları

✅ **Kurulum Süresi:** 10-15 dakika

✅ **Log Dosyası:** `/var/log/webserver-full-install.log`

---

## Manuel Kurulum Adımları

Aşağıdaki bölümler script'in yaptığı işlemleri manuel olarak yapmak isterseniz takip edilebilir.

---

## 1. Sanal Makine Oluşturma

```
VirtualBox veya VmWare kullanarak sanal makine oluşturun.
```

---

## 2. İşletim Sistemi Kurulumu

```
Ubuntu Server (ubuntu-24.04.3-live-server-amd64) kurulumu yapılır.
```

---

## 3. Sistem Güncelleme ve Temel Araçlar

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install wget curl net-tools htop sudo -y
```

---

## 4. SSH Sunucusu Kurulumu

```bash
sudo apt install openssh-server -y
sudo systemctl enable ssh
sudo systemctl status ssh
```

---

## 5. Saat Dilimi ve NTP Senkronizasyonu

```bash
sudo timedatectl set-timezone Europe/Istanbul
sudo timedatectl set-ntp true

timedatectl
```

---

## 6. Otomatik Güvenlik Güncellemeleri

```bash
sudo apt install unattended-upgrades -y
sudo dpkg-reconfigure unattended-upgrades
```

> Öneri: `50unattended-upgrades` içinde sadece `-security` repository'si aktif olsun; `-updates` ve paket yükseltmeleri elle yapılmalı (web servis kesintisi riskini azaltmak için).

---

## 7. journald Log Boyut Yönetimi

```bash
sudo nano /etc/systemd/journald.conf
```

Aşağıdaki ayarları ekleyin veya düzenleyin:

```
SystemMaxUse=200M
SystemMaxFileSize=50M
```

Servisi yeniden başlatın:

```bash
sudo systemctl restart systemd-journald
```

---

## 8. Fail2Ban Kurulumu (SSH Brute-Force Koruma)

```bash
sudo apt install fail2ban -y
sudo systemctl enable --now fail2ban
sudo fail2ban-client status
sudo fail2ban-client status sshd
```

---

## 9. Firewall (UFW) — Tavsiye Edilen Kurallar

CloudPanel ve web servisleri için temel UFW kuralları:

```bash
# UFW yükle (eğer yoksa)
sudo apt install ufw -y

# SSH, HTTP, HTTPS ve CloudPanel arayüzü (8443)
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 8443/tcp

# Aktif et
sudo ufw --force enable
sudo ufw status verbose
```

> Neden: İnternete açık sunucularda sadece ihtiyaç duyulan portları açmak temel savunmadır.

---

## 10. Swap Yönetimi (Önerilen: 4GB)

16GB RAM için 4GB swap dengeli bir tercih; bellek taşmasını ve OOM kill durumlarını hafifletir.

```bash
# Varolan swap kapat
sudo swapoff -a
sudo rm -f /swapfile || true

# 4GB swap oluştur
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile

# kalıcı yapmak için fstab'a ekle
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

# swappiness düşük tut (10)
echo 'vm.swappiness=10' | sudo tee /etc/sysctl.d/99-swappiness.conf
sudo sysctl --system
```

---


## 11. CloudPanel Kurulumu

Resmi dökümantasyon: [https://www.cloudpanel.io/docs/v2/getting-started/other/](https://www.cloudpanel.io/docs/v2/getting-started/other/)

Önerilen kurulum komutu (imza kontrolüyle):

```bash
sudo apt update && sudo apt -y upgrade && sudo apt -y install curl wget sudo

curl -sS https://installer.cloudpanel.io/ce/v2/install.sh -o install.sh; \
echo "19cfa702e7936a79e47812ff57d9859175ea902c62a68b2c15ccd1ebaf36caeb install.sh" | \
sha256sum -c && sudo DB_ENGINE=MARIADB_11.4 bash install.sh
```

---

## 12. Nginx Logrotate (Disk Dolmasını Önleme)

Aşağıdaki `logrotate` dosyası Nginx loglarını günlük döndürür ve 14 gün saklar.

```bash
sudo tee /etc/logrotate.d/nginx > /dev/null <<'EOF'
/var/log/nginx/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 640 www-data adm
    sharedscripts
    postrotate
        systemctl reload nginx >/dev/null 2>&1 || true
    endscript
}
EOF
```

---

## 13. MariaDB (MariaDB 11.4) — 16GB RAM için Önerilen Temel Konfig

Aşağıdaki yapılandırma CloudPanel tarafından yönetilen MariaDB örnekleri için genel performans iyileştirmeleri içerir.

```bash
sudo tee /etc/mysql/mariadb.conf.d/90-optimized.cnf > /dev/null <<'EOF'
[mysqld]
innodb_buffer_pool_size=6G
innodb_buffer_pool_instances=6
innodb_log_file_size=512M
innodb_flush_method=O_DIRECT
max_connections=1000
thread_cache_size=64
query_cache_type=0
query_cache_size=0
EOF

sudo systemctl restart mariadb
```

> Neden: innodb_buffer_pool_size veritabanı önbelleği için ana kaynaktır; 16GB RAM olan sunucuda 6GB güvenli bir başlangıçtır. Gerektiğinde mysqltuner ile daha ince ayar yapılmalıdır.

---

## 14. Kurulum Sonrası Kontroller

* CloudPanel UI: `https://SUNUCU-IP:8443`
* UFW durum: `sudo ufw status verbose`
* Fail2Ban durumu: `sudo fail2ban-client status`
* Journald limitleri: `journalctl --disk-usage`
* Swap doğrulama: `swapon --show`

---

## 15. Ek Ayarlar 

### Ubuntu İçinde Otomatik Disk Büyütme
```bash
sudo apt-get update && sudo apt-get install -y cloud-guest-utils && \
lsblk && \
sudo growpart /dev/sda 3 && \
sudo pvresize /dev/sda3 && \
sudo lvextend -l +100%FREE /dev/mapper/ubuntu--vg-ubuntu--lv && \
sudo resize2fs /dev/mapper/ubuntu--vg-ubuntu--lv && \
df -h


sudo pvresize /dev/sda3 \
&& sudo lvextend -l +100%FREE /dev/ubuntu-vg/ubuntu-lv \
&& sudo resize2fs /dev/ubuntu-vg/ubuntu-lv \
&& df -h
```

### limits.conf ile açık dosya sınırını artır
```bash
echo "* soft nofile 65535
* hard nofile 65535" | sudo tee -a /etc/security/limits.conf >/dev/null
```

### systemd için global open file limit
```bash
sudo mkdir -p /etc/systemd/system.conf.d
echo "[Manager]
DefaultLimitNOFILE=65535" | sudo tee /etc/systemd/system.conf.d/limits.conf >/dev/null
sudo systemctl daemon-reload
```

### fstab içinde noatime etkinleştir (disk I/O azaltır)
```bash
sudo sed -i 's/\(\/.* ext4 \)defaults/\1defaults,noatime/' /etc/fstab
```

### Nginx Worker Auto Scaling
```bash
sudo sed -i 's/worker_processes .*/worker_processes auto;/' /etc/nginx/nginx.conf
sudo systemctl reload nginx
```

### Kernel TCP Optimize
```bash
sudo tee /etc/sysctl.d/99-network-optimizations.conf > /dev/null << 'EOF'
net.core.somaxconn = 4096
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 120
net.ipv4.ip_local_port_range = 1024 65000
EOF

sudo sysctl --system
```

### Swap İçin ZRAM
```bash
sudo apt install zram-config -y
```

---

## 16. PHP Optimizasyonları (Laravel için Kritik)

Laravel uygulamaları için PHP-FPM ve OPcache optimizasyonları. Bu ayarlar performansı önemli ölçüde artırır.

### PHP-FPM Pool Ayarları

CloudPanel'de her site için PHP-FPM pool'u `/home/SITE-KULLANICI-ADI/htdocs/SITE-ADI/php-fpm/pool.d/` altında bulunur. Ancak global ayarlar için:

```bash
# PHP versiyonunuzu kontrol edin (örnek: 8.3)
php -v

# PHP-FPM ana konfigürasyon dosyası (PHP 8.3 için örnek)
sudo nano /etc/php/8.3/fpm/pool.d/www.conf
```

Aşağıdaki ayarları bulup değiştirin veya ekleyin:

```ini
; Process Manager Ayarları (16GB RAM için optimize edilmiş)
pm = dynamic
pm.max_children = 50
pm.start_servers = 10
pm.min_spare_servers = 5
pm.max_spare_servers = 20
pm.max_requests = 500

; Her process için memory limit
pm.process_idle_timeout = 10s
```

> **Açıklama:**
> - `pm.max_children`: Aynı anda maksimum 50 PHP process (her biri ~50MB = 2.5GB)
> - `pm.start_servers`: Başlangıçta 10 process
> - `pm.max_requests`: Her process 500 istek sonra yenilenir (memory leak önleme)

### PHP.ini Optimizasyonları (Laravel için)

```bash
# PHP 8.3 için (versiyonunuza göre değiştirin)
sudo nano /etc/php/8.3/fpm/php.ini
```

Aşağıdaki ayarları bulup değiştirin:

```ini
; Memory ve Execution
memory_limit = 512M
max_execution_time = 300
max_input_time = 300
post_max_size = 128M
upload_max_filesize = 128M

; OPcache (ZORUNLU - Laravel için kritik!)
opcache.enable = 1
opcache.enable_cli = 1
opcache.memory_consumption = 256
opcache.interned_strings_buffer = 16
opcache.max_accelerated_files = 20000
opcache.validate_timestamps = 0
opcache.revalidate_freq = 0
opcache.save_comments = 1
opcache.fast_shutdown = 1

; Realpath Cache (Laravel için çok önemli!)
realpath_cache_size = 4096K
realpath_cache_ttl = 600

; Session
session.gc_maxlifetime = 1440
session.gc_probability = 1
session.gc_divisor = 1000
```

Servisi yeniden başlatın:

```bash
sudo systemctl restart php8.3-fpm
```

### OPcache Açıklaması

> **Neden `opcache.validate_timestamps = 0`?**
> 
> Production ortamında PHP dosyalarının değişip değişmediğini sürekli kontrol etmek performans kaybına yol açar. Bu ayar ile PHP dosyaları bir kez derlenir ve cache'de kalır.
>
> **Önemli:** Kod değişikliği yaptığınızda OPcache'i temizlemeniz gerekir:
> ```bash
> sudo systemctl reload php8.3-fpm
> # veya CloudPanel üzerinden "Clear OPcache" butonunu kullanın
> ```

### Nginx için Laravel Özel Ayarlar

CloudPanel'de sitenizin Nginx vHost ayarlarına gidin ve şunları ekleyin:

```nginx
# Nginx vHost içine eklenecek
location / {
    try_files $uri $uri/ /index.php?$query_string;
}

# Static dosyalar için cache
location ~* \.(jpg|jpeg|png|gif|ico|css|js|svg|woff|woff2|ttf|eot)$ {
    expires 365d;
    add_header Cache-Control "public, immutable";
    access_log off;
}

# Gzip compression
gzip on;
gzip_vary on;
gzip_min_length 1024;
gzip_types text/plain text/css text/xml text/javascript application/x-javascript application/xml+rss application/json application/javascript;
```

### Redis/Memcached Kurulumu (Opsiyonel ama Önerilen)

Laravel için cache ve session driver olarak Redis kullanmak performansı çok artırır:

```bash
# Redis kurulumu
sudo apt install redis-server -y
sudo systemctl enable redis-server
sudo systemctl start redis-server

# PHP Redis extension (apt ile deneyin, yoksa PECL ile kurun)
sudo apt install php8.3-redis -y 2>/dev/null || {
  echo "Redis extension apt'ta bulunamadı, PECL ile kuruluyor..."
  sudo apt install php8.3-dev php-pear build-essential -y
  sudo pecl channel-update pecl.php.net
  printf "\n" | sudo pecl install redis
  echo "extension=redis.so" | sudo tee /etc/php/8.3/mods-available/redis.ini
  sudo phpenmod redis
}

sudo systemctl restart php8.3-fpm

# Laravel .env dosyanızda:
# CACHE_DRIVER=redis
# SESSION_DRIVER=redis
# QUEUE_CONNECTION=redis
```

### MySQL/MariaDB için Laravel Optimizasyonu

Laravel'in çok sorgu yaptığı durumlarda:

```bash
sudo nano /etc/mysql/mariadb.conf.d/91-laravel-optimized.cnf
```

```ini
[mysqld]
# Query Cache (MariaDB 10.x için)
query_cache_type = 1
query_cache_size = 128M
query_cache_limit = 2M

# Connection Pool
max_connections = 500
thread_cache_size = 128

# Table Cache
table_open_cache = 4000
table_definition_cache = 2000

# Temp Tables
tmp_table_size = 128M
max_heap_table_size = 128M
```

```bash
sudo systemctl restart mariadb
```

---

## 17. Neden Bunları Ekledik?

Kısa özet:

* **Firewall**: Saldırı düzeyini azaltır.
* **Swap**: OOM/ram baskısını azaltır, stabil çalışma sağlar.
* **Logrotate**: Disk dolmasını engeller, performans kaybını önler.
* **MariaDB tuning**: Veritabanı için bellek ve IO optimizasyonu sağlar, CloudPanel altında web uygulamalarınız yavaşlamaz.
* **PHP Optimizasyonları**: OPcache ve PHP-FPM ayarları Laravel uygulamalarını 5-10 kat hızlandırır. Redis ile cache performansı dramatik şekilde artar.
* **Ek Ayarlar**: Sistem limitlerini artırır, disk I/O'yu optimize eder ve network performansını iyileştirir.

---
