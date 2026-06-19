#!/usr/bin/env bash
# keepalive.sh — jaga Firego tetap hidup di shared hosting yang sering membunuh
# proses background. Pasang sebagai cron tiap beberapa menit:
#
#   crontab -e
#   */5 * * * * $HOME/firego/keepalive.sh >/dev/null 2>&1
#
# Hanya dipakai untuk mode nohup (bukan systemd).
set -euo pipefail

APP_DIR="${FIREGO_DIR:-$HOME/firego}"
PIDFILE="$APP_DIR/firego.pid"

if [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
  exit 0   # masih hidup
fi

# Mati → hidupkan lagi
exec "$APP_DIR/restart.sh"
