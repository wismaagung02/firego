#!/usr/bin/env bash
# restart.sh — (re)start Firego di shared hosting TANPA root.
# Strategi (otomatis pilih yang tersedia):
#   1. systemctl --user  (jika host mengaktifkan user lingering)
#   2. fallback: nohup + PID file, dijaga oleh cron keepalive (lihat keepalive.sh)
#
# Dijalankan oleh GitHub Actions setelah binary baru di-upload.
set -euo pipefail

APP_DIR="${FIREGO_DIR:-$HOME/firego}"
BIN="$APP_DIR/firego"
PIDFILE="$APP_DIR/firego.pid"
LOG="$APP_DIR/firego.log"
PORT="${FIREGO_PORT:-8080}"

cd "$APP_DIR"
chmod +x "$BIN"

# ── Opsi 1: systemd user service ─────────────────────────────────────────
if systemctl --user >/dev/null 2>&1; then
  echo "[restart] memakai systemctl --user"
  systemctl --user daemon-reload
  systemctl --user restart firego.service
  systemctl --user --no-pager status firego.service | head -5
  exit 0
fi

# ── Opsi 2: nohup + PID file ─────────────────────────────────────────────
echo "[restart] systemd user tidak tersedia → memakai nohup"
if [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
  echo "[restart] menghentikan proses lama PID $(cat "$PIDFILE")"
  kill "$(cat "$PIDFILE")" 2>/dev/null || true
  sleep 2
fi

export PORT
export FIREGO_DATA="${FIREGO_DATA:-$APP_DIR/data}"
export FIREGO_WEB="${FIREGO_WEB:-$APP_DIR/web}"
# FIREGO_ADMIN_KEY & FIREGO_SECRET sebaiknya di-set di ~/.firego.env (lihat README)
[[ -f "$APP_DIR/.firego.env" ]] && set -a && . "$APP_DIR/.firego.env" && set +a

nohup "$BIN" >>"$LOG" 2>&1 &
echo $! > "$PIDFILE"
sleep 1
echo "[restart] Firego berjalan PID $(cat "$PIDFILE") di port $PORT"
