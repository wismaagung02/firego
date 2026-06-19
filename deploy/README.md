# Deploy Firego ke Shared Hosting (cPanel) via SSH

Deploy otomatis dari GitHub ke server Anda **tanpa root**. Kredensial SSH
disimpan di GitHub Secrets — tidak pernah ada di kode atau chat.

## 1. Tambahkan GitHub Secrets

**Settings → Secrets and variables → Actions → New repository secret:**

| Secret | Isi |
|--------|-----|
| `SSH_HOST` | alamat server, mis. `server123.hostingku.com` |
| `SSH_USER` | username SSH cPanel Anda |
| `SSH_KEY`  | isi **private key** SSH (seluruh isi file `id_ed25519`/`id_rsa`) |
| `SSH_PORT` | (opsional) port SSH, default `22` |

Membuat key bila belum ada (di komputer Anda):
```bash
ssh-keygen -t ed25519 -f firego_deploy -N ""
# salin PUBLIC key ke server:
ssh-copy-id -i firego_deploy.pub USER@HOST
# tempel isi PRIVATE key (firego_deploy) ke secret SSH_KEY
```

Opsional, **Variables** (bukan secret):
| Variable | Default | Guna |
|----------|---------|------|
| `DEPLOY_DIR` | `~/firego` | folder tujuan di server |
| `GOARCH` | `amd64` | ganti ke `arm64` bila server ARM |

## 2. Trigger deploy

Push ke `main` (atau jalankan manual di tab **Actions → Deploy ke server via SSH → Run workflow**). Workflow akan:
1. build binary Linux,
2. SCP binary + dashboard ke server,
3. jalankan `restart.sh` yang otomatis memilih cara start.

## 3. Cara start di server (otomatis dipilih restart.sh)

**Opsi A — systemd user service** (kalau host mengaktifkan `systemctl --user`):
```bash
mkdir -p ~/.config/systemd/user
cp ~/firego/firego.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now firego.service
loginctl enable-linger "$USER"     # tetap jalan walau logout
```

**Opsi B — keepalive cron** (tanpa systemd, paling portabel):
```bash
crontab -e
# tambahkan: cek tiap 5 menit, hidupkan lagi bila mati
*/5 * * * * $HOME/firego/keepalive.sh >/dev/null 2>&1
```

## 4. Konfigurasi key & port

Buat `~/firego/.firego.env` di server agar admin key stabil:
```bash
cat > ~/firego/.firego.env <<'EOF'
FIREGO_ADMIN_KEY=ganti-dengan-key-rahasia-anda
FIREGO_SECRET=ganti-dengan-secret-acak-panjang
PORT=8080
EOF
chmod 600 ~/firego/.firego.env
```

## 5. Agar bisa diakses lewat domain (penting di shared hosting)

Binary listen di `PORT` (mis. 8080), tapi shared hosting hanya mengekspos
80/443. Hubungkan domain/subdomain ke port itu lewat reverse proxy:

- **cPanel "Application Manager"** (jika ada) — daftarkan app ke domain.
- atau `.htaccess` di docroot subdomain:
  ```apache
  RewriteEngine On
  RewriteRule ^(.*)$ http://127.0.0.1:8080/$1 [P,L]
  ```
  (butuh `mod_proxy` aktif — tanyakan ke support hosting bila ragu).

> ⚠️ Banyak shared host **memblokir port custom & proses background**.
> Bila Opsi A/B gagal atau domain tak bisa di-proxy, pertimbangkan VPS
> murah atau Render (lihat `../render.yaml`) yang jauh lebih andal untuk
> aplikasi yang perlu proses terus berjalan.
