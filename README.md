# 🔥 Firego

**Firego** adalah *Backend-as-a-Service* ringan mirip **Firebase**, ditulis sepenuhnya dalam **Go** tanpa dependency eksternal (hanya standard library). Cocok untuk belajar cara kerja Firebase, prototyping cepat, atau backend self-hosted skala kecil.

## ✨ Fitur

| Layanan Firebase | Padanan di Firego |
|------------------|-------------------|
| Authentication | Register / Login dengan JWT (HMAC-SHA256), password di-hash bersalt |
| Realtime Database | Pohon JSON ter-alamat path, REST API (PUT/PATCH/POST/DELETE/GET) |
| Realtime updates | Streaming langsung via **Server-Sent Events (SSE)** |
| Cloud Storage | Upload / download / list objek file |
| Console | Dashboard web sederhana di `/` |

Semua data dipersistensi ke disk sebagai file JSON (`data/`), jadi tidak butuh database eksternal.

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
| `-addr` | `FIREGO_ADDR` | `:8080` | Alamat listen HTTP |
| `-data` | `FIREGO_DATA` | `data` | Direktori penyimpanan data |
| `-web`  | `FIREGO_WEB`  | `web`  | Direktori dashboard |

## 📡 API

Endpoint yang memodifikasi data memerlukan header `Authorization: Bearer <token>`.

### Authentication

```bash
# Register
curl -X POST localhost:8080/v1/auth/register \
  -d '{"email":"demo@firego.dev","password":"rahasia123"}'

# Login -> mengembalikan { "user": {...}, "token": "..." }
curl -X POST localhost:8080/v1/auth/login \
  -d '{"email":"demo@firego.dev","password":"rahasia123"}'

# Info user saat ini
curl localhost:8080/v1/auth/me -H "Authorization: Bearer $TOKEN"
```

### Realtime Database

```bash
# Tulis (ganti seluruh nilai)
curl -X PUT localhost:8080/v1/db/users/alice \
  -H "Authorization: Bearer $TOKEN" -d '{"name":"Alice","age":30}'

# Merge sebagian (PATCH)
curl -X PATCH localhost:8080/v1/db/users/alice \
  -H "Authorization: Bearer $TOKEN" -d '{"age":31}'

# Tambah ke list dengan key terurut waktu (PUSH) -> { "name": "-Ov..." }
curl -X POST localhost:8080/v1/db/messages \
  -H "Authorization: Bearer $TOKEN" -d '{"text":"halo"}'

# Baca (publik)
curl localhost:8080/v1/db/users/alice

# Hapus
curl -X DELETE localhost:8080/v1/db/users/alice -H "Authorization: Bearer $TOKEN"
```

### Realtime Stream (SSE)

```bash
# Pantau perubahan pada path apa pun di subtree /messages
curl -N localhost:8080/v1/stream/messages
```

Setiap perubahan dikirim sebagai event SSE bertipe `put`, `patch`, atau `delete`:

```
event: put
data: {"type":"put","path":"/messages/-Ov...","data":{"text":"halo"}}
```

### Cloud Storage

```bash
# Upload (body = isi file)
curl -X POST localhost:8080/v1/storage/notes/hello.txt \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: text/plain" \
  --data-binary @hello.txt

# Download
curl localhost:8080/v1/storage/notes/hello.txt

# List (opsional ?prefix=)
curl localhost:8080/v1/storage

# Hapus
curl -X DELETE localhost:8080/v1/storage/notes/hello.txt -H "Authorization: Bearer $TOKEN"
```

## 🏗️ Arsitektur

```
cmd/firego/         Entry point & wiring server
internal/
  jwt/              JWT HMAC-SHA256 (standard library)
  auth/             Akun pengguna, hashing password, penerbitan token
  database/         Pohon JSON realtime + persistensi + push-ID ala Firebase
  realtime/         Hub publish/subscribe untuk SSE
  storage/          Object store berbasis filesystem
  server/           Routing HTTP, middleware auth, CORS, handler
web/                Dashboard "Firego Console"
```

## 🧪 Test

```bash
go test ./...
```

## ⚠️ Catatan

Proyek ini dibuat untuk tujuan edukasi/prototyping. Untuk produksi pertimbangkan: bcrypt/argon2 untuk password, security rules per-path, rate limiting, TLS, dan backend penyimpanan yang lebih tangguh.
