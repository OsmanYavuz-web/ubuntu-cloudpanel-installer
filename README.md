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
- Dinamik Swap yapılandırması (RAM'e göre 2x, min 4GB, max 8GB)
- CloudPanel + MariaDB 11.4
- PHP optimizasyonları (Laravel için)
- Redis + PHP Redis extension (PECL ile otomatik)
- Nginx ve MariaDB optimizasyonları
- Otomatik bakım mekanizmaları (apt autoremove, disk temizliği, sistem sağlık kontrolü)

✅ **Kurulum Süresi:** 10-15 dakika

✅ **Log Dosyası:** `/var/log/webserver-full-install.log`

---

## Manuel Kurulum (İsteğe Bağlı)

Script otomatik olarak tüm kurulumu yapar. Manuel kurulum için aşağıdaki adımları takip edebilirsiniz:

### Sistem Hazırlığı

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install wget curl openssh-server ufw fail2ban -y
sudo timedatectl set-timezone Europe/Istanbul
sudo timedatectl set-ntp true
```

### Firewall ve Güvenlik

```bash
sudo ufw allow 22/tcp comment 'SSH'
sudo ufw allow 80/tcp comment 'HTTP'
sudo ufw allow 443/tcp comment 'HTTPS'
sudo ufw allow 8443/tcp comment 'CloudPanel'
sudo ufw --force enable
sudo systemctl enable --now fail2ban
```

### Swap ve CloudPanel

```bash
# Dinamik swap (RAM x 2, min 4GB, max 8GB)
RAM_GB=$(free -g | awk '/^Mem:/{print $2}')
SWAP_SIZE=$((RAM_GB * 2))
[ $SWAP_SIZE -lt 4 ] && SWAP_SIZE=4
[ $SWAP_SIZE -gt 8 ] && SWAP_SIZE=8
sudo swapoff -a 2>/dev/null || true
sudo rm -f /swapfile || true
sudo fallocate -l ${SWAP_SIZE}G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile && sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
echo 'vm.swappiness=10' | sudo tee /etc/sysctl.d/99-swappiness.conf
sudo sysctl --system

# CloudPanel kurulumu (MariaDB 11.4 ile)
curl -sS https://installer.cloudpanel.io/ce/v2/install.sh -o install.sh
echo "19cfa702e7936a79e47812ff57d9859175ea902c62a68b2c15ccd1ebaf36caeb install.sh" | sha256sum -c
sudo DB_ENGINE=MARIADB_11.4 bash install.sh
```

Kurulum sonrası: `https://SUNUCU-IP:8443`

> **Detaylı manuel kurulum:** Script otomatik olarak Nginx logrotate, MariaDB optimizasyonları, sistem optimizasyonları (limits, TCP, journald, ZRAM), PHP optimizasyonları (Laravel için), Redis kurulumu ve otomatik bakım mekanizmalarını yapılandırır. Detaylar için script kaynak koduna bakın.

> **PHP Optimizasyonları (Laravel):** OPcache, PHP-FPM pool ayarları, Redis kurulumu ve MariaDB optimizasyonları için detaylı rehber: [CloudPanel PHP Optimizasyonları](https://www.cloudpanel.io/docs/) (script otomatik yapılandırır)

---

## Kurulum Sonrası

1. **CloudPanel UI:** `https://SUNUCU-IP:8443` - İlk kurulumda admin kullanıcısı oluşturun
2. **Durum Kontrolleri:**
   ```bash
   sudo ufw status verbose
   sudo fail2ban-client status
   swapon --show
   ```
3. **PHP Optimizasyonları:** Script otomatik yapılandırır. Laravel uygulamaları için OPcache ve Redis aktif.

> **Detaylı optimizasyon rehberi:** [CloudPanel Resmi Dökümantasyon](https://www.cloudpanel.io/docs/)

---

## 📞 Destek ve Kaynaklar

**Geliştirici:** Osman Yavuz

📧 **Email:** omnyvz.yazilim@gmail.com

**GitHub Repository:** [https://github.com/OsmanYavuz-web/ubuntu-cloudpanel-installer](https://github.com/OsmanYavuz-web/ubuntu-cloudpanel-installer)

**CloudPanel Resmi Dökümantasyon:** [https://www.cloudpanel.io/docs/](https://www.cloudpanel.io/docs/)

---

## ⚠️ Önemli Notlar

- CloudPanel port 8443'te çalışır, firewall'da açık olduğundan emin olun
- İlk kurulumda admin kullanıcısı oluşturmanız gerekir
- MariaDB 11.4 otomatik olarak kurulur
- PHP optimizasyonları Laravel uygulamaları için önerilir
- Disk alanı izleme için sistem sağlık kontrolü cron job'ı aktif edilir

---

**Not**: Bu script Linux sunucular için tasarlanmıştır. Windows'ta çalışmaz.

---
