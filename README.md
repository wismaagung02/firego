# 🔥 Firego

**Firego** adalah *Backend-as-a-Service* ringan mirip **Firebase**, ditulis sepenuhnya dalam **Go** tanpa dependency eksternal (hanya standard library). Cocok untuk belajar cara kerja Firebase, prototyping cepat, atau backend self-hosted skala kecil.

## ✨ Fitur

| Layanan Firebase | Padanan di Firego |
|------------------|-------------------|
| Authentication | Register / Login dengan JWT (HMAC-SHA256), password di-hash **bcrypt** + blacklist token |
| Realtime Database | Pohon JSON ter-alamat path, REST API (PUT/PATCH/POST/DELETE/GET) |
| Realtime updates | Streaming langsung via **Server-Sent Events (SSE)** |
| Cloud Storage | Upload / download / list objek file |
| Security Rules | Aturan JSON ala Firebase: `auth != null`, `auth.uid === $uid`, dll |
| Multi-App (Projects) | Banyak app terisolasi, masing-masing punya data & secret JWT sendiri |
| SDK Config | Endpoint config per-app untuk inisialisasi client |
| Remote Config | Key-value config per-app yang bisa diubah tanpa deploy ulang |
| Console | Dashboard web + **dokumentasi interaktif** di `/` |

Semua data dipersistensi ke disk sebagai file JSON (`data/`), jadi tidak butuh database eksternal. Setiap endpoint client diawali `/v1/{appID}/…` (gunakan `default` jika hanya satu app).

## 🚀 Menjalankan

```bash
go run ./cmd/firego
# atau
go build -o firego ./cmd/firego && ./firego
```

Buka **http://localhost:8080** untuk membuka Firego Console.

### Opsi konfigurasi

| Flag | Env | Default | Keterangan |
|------|-----|---------|------------|
| `-addr` | `FIREGO_ADDR` / `PORT` | `:8080` | Alamat listen HTTP (`PORT` diprioritaskan, dipakai platform cloud) |
| `-data` | `FIREGO_DATA` | `data` | Direktori penyimpanan data |
| `-web`  | `FIREGO_WEB`  | `web`  | Direktori dashboard |
| —       | `FIREGO_ADMIN_KEY` | *(acak)* | Admin key tetap (disarankan saat deploy) |
| —       | `FIREGO_SECRET` | *(acak)* | Master secret JWT tetap (disarankan saat deploy) |

> Admin key tampil di log saat startup. Gunakan untuk mengelola app & rules di dashboard.

## 📡 API

Endpoint yang memodifikasi data memerlukan header `Authorization: Bearer <token>`.

### Authentication

```bash
# Register
curl -X POST localhost:8080/v1/default/auth/register \
  -d '{"email":"demo@firego.dev","password":"rahasia123"}'

# Login -> mengembalikan { "user": {...}, "token": "..." }
curl -X POST localhost:8080/v1/default/auth/login \
  -d '{"email":"demo@firego.dev","password":"rahasia123"}'

# Info user saat ini
curl localhost:8080/v1/default/auth/me -H "Authorization: Bearer $TOKEN"
```

### Realtime Database

```bash
# Tulis (ganti seluruh nilai)
curl -X PUT localhost:8080/v1/default/db/users/alice \
  -H "Authorization: Bearer $TOKEN" -d '{"name":"Alice","age":30}'

# Merge sebagian (PATCH)
curl -X PATCH localhost:8080/v1/default/db/users/alice \
  -H "Authorization: Bearer $TOKEN" -d '{"age":31}'

# Tambah ke list dengan key terurut waktu (PUSH) -> { "name": "-Ov..." }
curl -X POST localhost:8080/v1/default/db/messages \
  -H "Authorization: Bearer $TOKEN" -d '{"text":"halo"}'

# Baca (publik)
curl localhost:8080/v1/default/db/users/alice

# Hapus
curl -X DELETE localhost:8080/v1/default/db/users/alice -H "Authorization: Bearer $TOKEN"
```

### Realtime Stream (SSE)

```bash
# Pantau perubahan pada path apa pun di subtree /messages
curl -N localhost:8080/v1/default/stream/messages
```

Setiap perubahan dikirim sebagai event SSE bertipe `put`, `patch`, atau `delete`:

```
event: put
data: {"type":"put","path":"/messages/-Ov...","data":{"text":"halo"}}
```

### Cloud Storage

```bash
# Upload (body = isi file)
curl -X POST localhost:8080/v1/default/storage/notes/hello.txt \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: text/plain" \
  --data-binary @hello.txt

# Download
curl localhost:8080/v1/default/storage/notes/hello.txt

# List (opsional ?prefix=)
curl localhost:8080/v1/default/storage

# Hapus
curl -X DELETE localhost:8080/v1/default/storage/notes/hello.txt -H "Authorization: Bearer $TOKEN"
```

## 🏗️ Arsitektur

```
cmd/firego/         Entry point & wiring server
internal/
  jwt/              JWT HMAC-SHA256 (standard library)
  auth/             Akun pengguna, bcrypt, penerbitan & blacklist token
  database/         Pohon JSON realtime + persistensi + push-ID ala Firebase
  realtime/         Hub publish/subscribe untuk SSE
  storage/          Object store berbasis filesystem
  rules/            Mesin Security Rules (parser + evaluator ekspresi)
  ratelimit/        Rate limiter fixed-window per-IP
  apps/             Manajemen multi-app + Remote Config per-app
  server/           Routing HTTP, middleware auth, CORS, handler
web/                Dashboard "Firego Console" + dokumentasi
Dockerfile          Build image container
render.yaml         Blueprint deploy Render
.github/workflows/  CI: build & publish image ke GHCR
```

## ☁️ Deploy (akses lewat URL publik)

GitHub Pages tidak bisa menjalankan server Go, jadi gunakan platform container. Repo ini sudah menyertakan `Dockerfile`, `render.yaml`, dan workflow GitHub Actions yang build image ke GHCR.

### Render (paling mudah)

1. Buka [dashboard.render.com](https://dashboard.render.com) → **New → Blueprint**
2. Connect repo GitHub ini (Render membaca `render.yaml` otomatis)
3. Klik **Apply** → dapat URL `https://firego-xxxx.onrender.com`
4. *(disarankan)* set env `FIREGO_ADMIN_KEY` dan `FIREGO_SECRET` agar key stabil

### Docker (lokal atau platform lain)

```bash
docker build -t firego .
docker run -p 8080:8080 \
  -e FIREGO_ADMIN_KEY=rahasia-admin \
  -e FIREGO_SECRET=rahasia-secret \
  firego
```

### Image dari GitHub Container Registry

Setiap push ke `main`, GitHub Actions build & publish image:

```bash
docker run -p 8080:8080 ghcr.io/wismaagung02/firego:latest
```

Server otomatis mengikuti env `PORT` yang disuntikkan Render/Railway/Cloud Run. Untuk data persisten, mount volume ke `/app/data` (lihat komentar di `render.yaml`).

## 🧪 Test

```bash
go test ./...
```

## ⚠️ Catatan

Proyek ini dibuat untuk tujuan edukasi/prototyping. Sudah menyertakan bcrypt, security rules per-path, rate limiting, dan header keamanan HTTP. Untuk produksi pertimbangkan juga: TLS/HTTPS (biasanya disediakan platform deploy), backend penyimpanan yang lebih tangguh, serta blacklist token yang persisten (saat ini in-memory).
