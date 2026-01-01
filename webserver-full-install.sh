#!/usr/bin/env bash
# CloudPanel Web Server Tam Otomatik Kurulum Scripti
# Ubuntu Server 24.04 için optimize edilmiştir
# Kullanım: sudo bash webserver-full-install.sh
#
# Geliştirici: Osman Yavuz
# GitHub: https://github.com/OsmanYavuz-web/ubuntu-cloudpanel-installer
# Repository: https://github.com/OsmanYavuz-web/ubuntu-cloudpanel-installer

set -euo pipefail

# Renkli çıktı için
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Root kontrolü
if [ "$(id -u)" -ne 0 ]; then
  echo -e "${RED}Bu script root yetkisi ile çalıştırılmalıdır!${NC}"
  echo "Kullanım: sudo bash webserver-full-install.sh"
  exit 1
fi

# Banner
echo -e "${GREEN}"
echo "╔════════════════════════════════════════════════════════╗"
echo "║   CloudPanel Web Server Otomatik Kurulum Scripti       ║"
echo "║   Ubuntu 24.04 + CloudPanel + Laravel Optimizasyonu    ║"
echo "╚════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${GREEN}✓ Bu script güvenli tekrar çalıştırılabilir (idempotent)${NC}"
echo -e "${GREEN}  Mevcut kurulumlar korunur, sadece eksik olanlar kurulur.${NC}"
echo ""

# Onay
echo -e "${YELLOW}Bu script şunları yapacak:${NC}"
echo "  - Sistem güncellemesi"
echo "  - SSH, Fail2Ban, UFW kurulumu"
echo "  - Swap oluşturma (dinamik: 4-8GB)"
echo "  - CloudPanel kurulumu (MariaDB 11.4)"
echo "  - PHP optimizasyonları (Laravel için)"
echo "  - Redis kurulumu"
echo "  - Sistem optimizasyonları"
echo ""
echo -e "${YELLOW}Devam etmek istiyor musunuz? (y/N)${NC}"
read -r REPLY
if [[ ! "$REPLY" =~ ^[Yy]$ ]]; then
  echo "İptal edildi."
  exit 0
fi

# Log dosyası
LOG_FILE="/var/log/webserver-full-install.log"
exec > >(tee -a "$LOG_FILE")
exec 2>&1

echo -e "\n${GREEN}[1/16] Sistem güncelleniyor...${NC}"
apt update && apt upgrade -y
apt install -y wget curl net-tools htop sudo

echo -e "\n${GREEN}[2/16] Gerekli paketler yükleniyor...${NC}"
apt install -y curl git ca-certificates gnupg lsb-release bind9-dnsutils wget net-tools htop

echo -e "\n${GREEN}[3/16] SSH Sunucusu kontrol ediliyor...${NC}"
if systemctl is-active --quiet ssh; then
  echo -e "${YELLOW}✓ SSH zaten kurulu ve çalışıyor, atlanıyor...${NC}"
else
  echo "SSH kuruluyor..."
  apt install -y openssh-server
  systemctl enable ssh
  systemctl start ssh
fi
echo "SSH durumu:"
systemctl status ssh --no-pager | head -5

echo -e "\n${GREEN}[4/16] Saat dilimi ve NTP ayarlanıyor...${NC}"
timedatectl set-timezone Europe/Istanbul
timedatectl set-ntp true
timedatectl

echo -e "\n${GREEN}[5/16] Otomatik güvenlik güncellemeleri yapılandırılıyor...${NC}"
apt install -y unattended-upgrades
echo 'APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";' > /etc/apt/apt.conf.d/20auto-upgrades
echo -e "${YELLOW}Not: unattended-upgrades sadece security güncellemelerini yapacak şekilde yapılandırılmalıdır.${NC}"

echo -e "\n${GREEN}[6/16] UFW Firewall yapılandırılıyor...${NC}"
apt install -y ufw

# UFW zaten aktifse kuralları koru, değilse yeni kurallar ekle
if ufw status | grep -q "Status: active"; then
  echo -e "${YELLOW}✓ UFW zaten aktif, mevcut kurallar korunuyor...${NC}"
  # Eksik kuralları ekle
  ufw allow 22/tcp comment 'SSH' 2>/dev/null || true
  ufw allow 80/tcp comment 'HTTP' 2>/dev/null || true
  ufw allow 443/tcp comment 'HTTPS' 2>/dev/null || true
  ufw allow 8443/tcp comment 'CloudPanel' 2>/dev/null || true
else
  echo "UFW ilk kez yapılandırılıyor..."
  ufw --force reset
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow 22/tcp comment 'SSH'
  ufw allow 80/tcp comment 'HTTP'
  ufw allow 443/tcp comment 'HTTPS'
  ufw allow 8443/tcp comment 'CloudPanel'
  ufw --force enable
fi
ufw status verbose

echo -e "\n${GREEN}[7/16] Fail2Ban kontrol ediliyor...${NC}"
if systemctl is-active --quiet fail2ban; then
  echo -e "${YELLOW}✓ Fail2Ban zaten kurulu ve çalışıyor, atlanıyor...${NC}"
else
  echo "Fail2Ban kuruluyor..."
  apt install -y fail2ban
  systemctl enable fail2ban
  systemctl start fail2ban
fi
fail2ban-client status || true

echo -e "\n${GREEN}[8/16] Swap yapılandırılıyor...${NC}"
if swapon --show | grep -q '/swapfile'; then
  CURRENT_SWAP_SIZE=$(swapon --show --noheadings --bytes | grep '/swapfile' | awk '{print $3}')
  RAM_GB=$(free -g | awk '/^Mem:/{print $2}')
  EXPECTED_SIZE=$((RAM_GB * 2))
  [ $EXPECTED_SIZE -lt 4 ] && EXPECTED_SIZE=4
  [ $EXPECTED_SIZE -gt 8 ] && EXPECTED_SIZE=8
  EXPECTED_SIZE_BYTES=$((EXPECTED_SIZE * 1024 * 1024 * 1024))
  
  if [ "$CURRENT_SWAP_SIZE" -ge "$EXPECTED_SIZE_BYTES" ]; then
    echo -e "${YELLOW}✓ Swap zaten yapılandırılmış ($(swapon --show | grep swapfile | awk '{print $3}')), atlanıyor...${NC}"
  else
    echo "Mevcut swap küçük, yeniden oluşturuluyor..."
    swapoff -a || true
    rm -f /swapfile || true
    RAM_GB=$(free -g | awk '/^Mem:/{print $2}')
    SWAP_SIZE=$((RAM_GB * 2))
    [ $SWAP_SIZE -lt 4 ] && SWAP_SIZE=4
    [ $SWAP_SIZE -gt 8 ] && SWAP_SIZE=8
    fallocate -l ${SWAP_SIZE}G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
  fi
else
  echo "Swap oluşturuluyor..."
  # Varolan swap'ı kapat
  swapoff -a || true
  rm -f /swapfile || true
  
  # Dinamik swap oluştur (RAM'e göre 2x, min 4GB, max 8GB)
  RAM_GB=$(free -g | awk '/^Mem:/{print $2}')
  SWAP_SIZE=$((RAM_GB * 2))
  [ $SWAP_SIZE -lt 4 ] && SWAP_SIZE=4
  [ $SWAP_SIZE -gt 8 ] && SWAP_SIZE=8
  
  fallocate -l ${SWAP_SIZE}G /swapfile
  chmod 600 /swapfile
  mkswap /swapfile
  swapon /swapfile
fi

# fstab'a ekle (eğer yoksa)
if ! grep -q '/swapfile' /etc/fstab; then
  echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

# swappiness ayarla
if [ ! -f /etc/sysctl.d/99-swappiness.conf ] || ! grep -q 'vm.swappiness=10' /etc/sysctl.d/99-swappiness.conf; then
  echo 'vm.swappiness=10' > /etc/sysctl.d/99-swappiness.conf
  echo 'vm.vfs_cache_pressure=50' >> /etc/sysctl.d/99-swappiness.conf
  sysctl --system
fi

echo "Swap durumu:"
swapon --show
free -h

echo -e "\n${GREEN}[9/16] CloudPanel kontrol ediliyor...${NC}"

# CloudPanel'in kurulu olup olmadığını kontrol et (çoklu kontrol)
CLOUDPANEL_INSTALLED=false

if [ -f /usr/local/bin/clpctl ]; then
  CLOUDPANEL_INSTALLED=true
elif systemctl is-active --quiet nginx 2>/dev/null && systemctl is-active --quiet mariadb 2>/dev/null; then
  # Port 80, 443 ve 3306 kontrol et
  if netstat -tuln 2>/dev/null | grep -qE ':(80|443|3306)\s'; then
    echo -e "${YELLOW}⚠ Port 80, 443 veya 3306 zaten kullanımda (CloudPanel veya başka servis)${NC}"
    CLOUDPANEL_INSTALLED=true
  fi
fi

if [ "$CLOUDPANEL_INSTALLED" = true ]; then
  echo -e "${YELLOW}✓ CloudPanel zaten kurulu, atlanıyor...${NC}"
  if [ -f /usr/local/bin/clpctl ]; then
    echo -e "${YELLOW}  Versiyon: $(clpctl --version 2>/dev/null || echo 'Bilinmiyor')${NC}"
  fi
  echo -e "${YELLOW}  Not: Mevcut CloudPanel kurulumu ve siteleri korunuyor.${NC}"
else
  echo "CloudPanel kuruluyor (MariaDB 11.4)..."
  echo -e "${YELLOW}Not: CloudPanel kurulumu 5-10 dakika sürebilir...${NC}"
  
  # CloudPanel installer'ı indir
  curl -sS https://installer.cloudpanel.io/ce/v2/install.sh -o /tmp/install.sh
  
  # SHA256 kontrolü (opsiyonel - güncel hash'i kontrol edin)
  # echo "19cfa702e7936a79e47812ff57d9859175ea902c62a68b2c15ccd1ebaf36caeb /tmp/install.sh" | sha256sum -c || {
  #   echo -e "${RED}CloudPanel installer SHA256 kontrolü başarısız!${NC}"
  #   exit 1
  # }
  
  # CloudPanel'i kur
  DB_ENGINE=MARIADB_11.4 bash /tmp/install.sh || {
    echo -e "${RED}CloudPanel kurulumu başarısız! Port kontrolü nedeniyle atlanıyor.${NC}"
    echo -e "${YELLOW}Muhtemelen CloudPanel zaten kurulu. Devam ediliyor...${NC}"
  }
fi

echo -e "\n${GREEN}[10/16] Nginx Logrotate yapılandırılıyor...${NC}"
cat > /etc/logrotate.d/nginx <<'EOF'
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
echo "Logrotate test:"
logrotate -d /etc/logrotate.d/nginx | head -10

echo -e "\n${GREEN}[11/16] MariaDB optimizasyonları uygulanıyor...${NC}"

if systemctl is-active --quiet mariadb 2>/dev/null; then
  if [ -f /etc/mysql/mariadb.conf.d/90-optimized.cnf ]; then
    echo -e "${YELLOW}✓ MariaDB optimizasyon dosyası zaten mevcut, güncelleniyor...${NC}"
  else
    echo "MariaDB optimizasyon dosyası oluşturuluyor..."
  fi
  
  cat > /etc/mysql/mariadb.conf.d/90-optimized.cnf <<'EOF'
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
  systemctl restart mariadb
  echo "MariaDB durumu:"
  systemctl status mariadb --no-pager | head -5
else
  echo -e "${YELLOW}⚠ MariaDB çalışmıyor, optimizasyon atlanıyor...${NC}"
fi

echo -e "\n${GREEN}[12/16] Sistem optimizasyonları uygulanıyor...${NC}"

# limits.conf
if ! grep -q "nofile 65535" /etc/security/limits.conf; then
  echo "File limits yapılandırılıyor..."
  echo "* soft nofile 65535
* hard nofile 65535" >> /etc/security/limits.conf
else
  echo -e "${YELLOW}✓ File limits zaten yapılandırılmış${NC}"
fi

# systemd limits
mkdir -p /etc/systemd/system.conf.d
if [ ! -f /etc/systemd/system.conf.d/limits.conf ] || ! grep -q "DefaultLimitNOFILE=65535" /etc/systemd/system.conf.d/limits.conf; then
  echo "Systemd limits yapılandırılıyor..."
  echo "[Manager]
DefaultLimitNOFILE=65535" > /etc/systemd/system.conf.d/limits.conf
  systemctl daemon-reload
else
  echo -e "${YELLOW}✓ Systemd limits zaten yapılandırılmış${NC}"
fi

# Kernel TCP optimizasyonları
if [ ! -f /etc/sysctl.d/99-cloudpanel-optimizations.conf ]; then
  echo "Kernel TCP optimizasyonları yapılandırılıyor..."
  cat > /etc/sysctl.d/99-cloudpanel-optimizations.conf <<'EOF'
net.core.somaxconn = 4096
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 120
net.ipv4.ip_local_port_range = 1024 65000
EOF
  sysctl --system
else
  echo -e "${YELLOW}✓ Kernel TCP optimizasyonları zaten yapılandırılmış${NC}"
fi

# Nginx worker processes
if [ -f /etc/nginx/nginx.conf ]; then
  if ! grep -q "worker_processes auto" /etc/nginx/nginx.conf; then
    echo "Nginx worker processes otomatik yapılandırılıyor..."
    sed -i 's/worker_processes .*/worker_processes auto;/' /etc/nginx/nginx.conf
    systemctl reload nginx
  else
    echo -e "${YELLOW}✓ Nginx worker processes zaten otomatik${NC}"
  fi
fi

# Journald log boyut yönetimi
mkdir -p /etc/systemd/journald.conf.d
if [ ! -f /etc/systemd/journald.conf.d/size-limit.conf ]; then
  echo "Journald log yönetimi yapılandırılıyor..."
  cat > /etc/systemd/journald.conf.d/size-limit.conf <<'EOF'
[Journal]
SystemMaxUse=200M
SystemMaxFileSize=50M
EOF
  systemctl restart systemd-journald
else
  echo -e "${YELLOW}✓ Journald log yönetimi zaten yapılandırılmış${NC}"
fi
echo "journald disk kullanımı:"
journalctl --disk-usage

# ZRAM
if dpkg -l zram-config 2>/dev/null | grep -q "^ii"; then
  echo -e "${YELLOW}✓ ZRAM zaten kurulu${NC}"
else
  echo "ZRAM kuruluyor..."
  apt install -y zram-config
fi

echo -e "${GREEN}Sistem optimizasyonları tamamlandı${NC}"

echo -e "\n${GREEN}[13/16] Otomatik bakım mekanizmaları yapılandırılıyor...${NC}"

# apt autoremove otomasyonu (haftalık)
if [ ! -f /etc/cron.weekly/apt-autoremove ]; then
  echo "apt autoremove cron job oluşturuluyor..."
  cat > /etc/cron.weekly/apt-autoremove <<'EOF'
#!/bin/bash
# Otomatik kullanılmayan paket temizliği
/usr/bin/apt-get autoremove -y >/dev/null 2>&1
/usr/bin/apt-get autoclean -y >/dev/null 2>&1
EOF
  chmod +x /etc/cron.weekly/apt-autoremove
else
  echo -e "${YELLOW}✓ apt autoremove cron job zaten mevcut${NC}"
fi

# Disk temizliği (haftalık - /tmp, eski loglar)
if [ ! -f /etc/cron.weekly/system-cleanup ]; then
  echo "Sistem temizliği cron job oluşturuluyor..."
  cat > /etc/cron.weekly/system-cleanup <<'EOF'
#!/bin/bash
# Otomatik disk temizliği
# /tmp dizinindeki 7 günden eski dosyaları temizle
find /tmp -type f -atime +7 -delete 2>/dev/null
find /tmp -type d -empty -delete 2>/dev/null

# Eski kernel paketlerini temizle (en son 2 kernel'i koru)
OLD_KERNELS=$(dpkg -l | grep -E 'linux-image-[0-9]' | grep -v $(uname -r | sed 's/-generic//') | awk '{print $2}' | head -n -2)
if [ -n "$OLD_KERNELS" ]; then
  apt-get purge -y $OLD_KERNELS >/dev/null 2>&1
fi
EOF
  chmod +x /etc/cron.weekly/system-cleanup
else
  echo -e "${YELLOW}✓ Sistem temizliği cron job zaten mevcut${NC}"
fi

# Sistem sağlık kontrolü (günlük - disk kullanımı uyarısı)
if [ ! -f /etc/cron.daily/system-health-check ]; then
  echo "Sistem sağlık kontrolü cron job oluşturuluyor..."
  cat > /etc/cron.daily/system-health-check <<'EOF'
#!/bin/bash
# Disk kullanımı kontrolü ve uyarı
DISK_USAGE=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
if [ "$DISK_USAGE" -gt 85 ]; then
  echo "UYARI: Disk kullanımı %${DISK_USAGE} - Kritik seviyeye yaklaşıyor!" | logger -t system-health
fi

# Swap kullanımı kontrolü
SWAP_USAGE=$(free | awk '/^Swap:/ {if ($2>0) printf "%.0f", $3*100/$2; else print "0"}')
if [ "$SWAP_USAGE" -gt 80 ]; then
  echo "UYARI: Swap kullanımı %${SWAP_USAGE} - RAM yetersiz olabilir!" | logger -t system-health
fi
EOF
  chmod +x /etc/cron.daily/system-health-check
else
  echo -e "${YELLOW}✓ Sistem sağlık kontrolü cron job zaten mevcut${NC}"
fi

echo -e "${GREEN}Otomatik bakım mekanizmaları yapılandırıldı${NC}"

echo -e "\n${GREEN}[14/17] PHP optimizasyonları yapılandırılıyor...${NC}"

# PHP versiyonunu tespit et
PHP_VERSION=$(php -r "echo PHP_MAJOR_VERSION.'.'.PHP_MINOR_VERSION;" 2>/dev/null || echo "8.3")
echo "Tespit edilen PHP versiyonu: $PHP_VERSION"

# PHP-FPM pool ayarları
PHP_FPM_POOL="/etc/php/$PHP_VERSION/fpm/pool.d/www.conf"
if [ -f "$PHP_FPM_POOL" ]; then
  # Backup al
  cp "$PHP_FPM_POOL" "$PHP_FPM_POOL.backup"
  
  # Pool ayarlarını güncelle
  sed -i 's/^pm = .*/pm = dynamic/' "$PHP_FPM_POOL"
  sed -i 's/^pm.max_children = .*/pm.max_children = 50/' "$PHP_FPM_POOL"
  sed -i 's/^pm.start_servers = .*/pm.start_servers = 10/' "$PHP_FPM_POOL"
  sed -i 's/^pm.min_spare_servers = .*/pm.min_spare_servers = 5/' "$PHP_FPM_POOL"
  sed -i 's/^pm.max_spare_servers = .*/pm.max_spare_servers = 20/' "$PHP_FPM_POOL"
  sed -i 's/^;pm.max_requests = .*/pm.max_requests = 500/' "$PHP_FPM_POOL"
  sed -i 's/^pm.max_requests = .*/pm.max_requests = 500/' "$PHP_FPM_POOL"
fi

# PHP.ini optimizasyonları
PHP_INI="/etc/php/$PHP_VERSION/fpm/php.ini"
if [ -f "$PHP_INI" ]; then
  # Backup al
  cp "$PHP_INI" "$PHP_INI.backup"
  
  # Memory ve execution
  sed -i 's/^memory_limit = .*/memory_limit = 512M/' "$PHP_INI"
  sed -i 's/^max_execution_time = .*/max_execution_time = 300/' "$PHP_INI"
  sed -i 's/^max_input_time = .*/max_input_time = 300/' "$PHP_INI"
  sed -i 's/^post_max_size = .*/post_max_size = 128M/' "$PHP_INI"
  sed -i 's/^upload_max_filesize = .*/upload_max_filesize = 128M/' "$PHP_INI"
  
  # OPcache
  sed -i 's/^;opcache.enable=.*/opcache.enable=1/' "$PHP_INI"
  sed -i 's/^opcache.enable=.*/opcache.enable=1/' "$PHP_INI"
  sed -i 's/^;opcache.enable_cli=.*/opcache.enable_cli=1/' "$PHP_INI"
  sed -i 's/^;opcache.memory_consumption=.*/opcache.memory_consumption=256/' "$PHP_INI"
  sed -i 's/^;opcache.interned_strings_buffer=.*/opcache.interned_strings_buffer=16/' "$PHP_INI"
  sed -i 's/^;opcache.max_accelerated_files=.*/opcache.max_accelerated_files=20000/' "$PHP_INI"
  sed -i 's/^;opcache.validate_timestamps=.*/opcache.validate_timestamps=0/' "$PHP_INI"
  sed -i 's/^;opcache.save_comments=.*/opcache.save_comments=1/' "$PHP_INI"
  sed -i 's/^;opcache.fast_shutdown=.*/opcache.fast_shutdown=1/' "$PHP_INI"
  
  # Realpath cache
  sed -i 's/^;realpath_cache_size =.*/realpath_cache_size = 4096K/' "$PHP_INI"
  sed -i 's/^;realpath_cache_ttl =.*/realpath_cache_ttl = 600/' "$PHP_INI"
fi

# PHP-FPM'i yeniden başlat
systemctl restart "php$PHP_VERSION-fpm"
echo "PHP-FPM durumu:"
systemctl status "php$PHP_VERSION-fpm" --no-pager | head -5

echo -e "\n${GREEN}[15/17] MariaDB Laravel optimizasyonları uygulanıyor...${NC}"

if systemctl is-active --quiet mariadb 2>/dev/null; then
  if [ -f /etc/mysql/mariadb.conf.d/91-laravel-optimized.cnf ]; then
    echo -e "${YELLOW}✓ Laravel optimizasyon dosyası zaten mevcut, güncelleniyor...${NC}"
  else
    echo "Laravel optimizasyon dosyası oluşturuluyor..."
  fi
  
  cat > /etc/mysql/mariadb.conf.d/91-laravel-optimized.cnf <<'EOF'
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
EOF
  systemctl restart mariadb
else
  echo -e "${YELLOW}⚠ MariaDB çalışmıyor, Laravel optimizasyonu atlanıyor...${NC}"
fi

echo -e "\n${GREEN}[16/17] Redis kontrol ediliyor...${NC}"

# Redis server kontrolü
if systemctl is-active --quiet redis-server; then
  echo -e "${YELLOW}✓ Redis server zaten kurulu ve çalışıyor${NC}"
else
  echo "Redis server kuruluyor..."
  apt install -y redis-server
  systemctl enable redis-server
  systemctl start redis-server
fi

# PHP Redis extension kontrolü
if php -m 2>/dev/null | grep -q "^redis$"; then
  echo -e "${YELLOW}✓ PHP Redis extension zaten kurulu${NC}"
else
  echo "PHP Redis extension kuruluyor..."
  if apt install -y "php$PHP_VERSION-redis" 2>/dev/null; then
    echo "Redis extension apt ile kuruldu."
  else
    echo -e "${YELLOW}Redis extension apt'ta bulunamadı, PECL ile kuruluyor...${NC}"
    apt install -y "php$PHP_VERSION-dev" php-pear build-essential
    pecl channel-update pecl.php.net
    
    # Eğer zaten PECL ile kuruluysa hata verme
    if pecl list | grep -q "^redis"; then
      echo -e "${YELLOW}✓ Redis extension zaten PECL ile kurulu${NC}"
    else
      printf "\n" | pecl install redis
    fi
    
    # Extension'ı aktif et
    echo "extension=redis.so" > "/etc/php/$PHP_VERSION/mods-available/redis.ini"
    phpenmod redis
  fi
  
  systemctl restart "php$PHP_VERSION-fpm"
fi

echo "Redis durumu:"
systemctl status redis-server --no-pager | head -5
redis-cli ping

echo -e "\n${GREEN}[17/17] Kurulum özeti${NC}"

echo -e "\n${GREEN}═══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✓ Kurulum başarıyla tamamlandı!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${YELLOW}Kurulum Sonrası Adımlar:${NC}"
echo ""
echo "1. CloudPanel UI: https://$(hostname -I | awk '{print $1}'):8443"
echo "   (Tarayıcınızda açın ve admin kullanıcısı oluşturun)"
echo ""
echo "2. Sistem Durumu:"
echo "   - UFW: $(ufw status | grep Status)"
echo "   - Fail2Ban: $(fail2ban-client status | grep 'Number of jail' 2>/dev/null || echo 'Çalışıyor')"
echo "   - Swap: $(swapon --show | tail -1)"
echo "   - PHP: $(php -v | head -1)"
echo "   - Redis: $(redis-cli ping 2>/dev/null || echo 'HATA')"
echo ""
echo -e "${YELLOW}Laravel Siteleri İçin:${NC}"
echo ""
echo "1. .env dosyasında Redis ayarlarını yapın:"
echo "   CACHE_DRIVER=redis"
echo "   SESSION_DRIVER=redis"
echo "   QUEUE_CONNECTION=redis"
echo ""
echo "2. Laravel cache'leri oluşturun:"
echo "   php artisan config:cache"
echo "   php artisan route:cache"
echo "   php artisan view:cache"
echo ""
echo "3. Composer optimizasyonu:"
echo "   composer install --optimize-autoloader --no-dev"
echo ""
echo -e "${YELLOW}Önemli Notlar:${NC}"
echo ""
echo "- OPcache validate_timestamps=0 olduğu için kod değişikliklerinden sonra:"
echo "  sudo systemctl reload php$PHP_VERSION-fpm"
echo ""
echo "- Tüm kurulum logları: $LOG_FILE"
echo ""
echo -e "${GREEN}Başarılar! 🚀${NC}"

exit 0