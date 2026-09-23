#!/usr/bin/env bash
# One-command install of the PRAHARI live sensor on a real Linux server.
#
#   sudo bash deploy/install.sh [interface]
#
# Creates a dedicated unprivileged user, installs the code under /opt/prahari,
# registers a systemd service granted only CAP_NET_RAW, and starts it bound to
# localhost. Put a reverse proxy (deploy/nginx.conf) in front for TLS and the
# public port. There is nothing to pip install — the engine is pure CPython.
set -euo pipefail

IFACE="${1:-eth0}"
DEST=/opt/prahari
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ $EUID -ne 0 ]]; then echo "run with sudo"; exit 1; fi
command -v python3 >/dev/null || { echo "python3 3.10+ required"; exit 1; }

echo "==> interface to monitor: $IFACE"
ip link show "$IFACE" >/dev/null 2>&1 || echo "   (warning: $IFACE not found yet — set IFACE in the service later)"

echo "==> creating service account 'prahari'"
id prahari >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin prahari

echo "==> installing code to $DEST"
mkdir -p "$DEST"
cp -r "$REPO_ROOT/prahari" "$REPO_ROOT/sensor" "$REPO_ROOT/web" "$REPO_ROOT/eval" "$DEST/"
echo "==> precomputing demo datasets"
( cd "$DEST" && python3 -m web.build >/dev/null )
chown -R prahari:prahari "$DEST"

echo "==> installing systemd service (iface=$IFACE)"
sed "s/Environment=IFACE=eth0/Environment=IFACE=$IFACE/" \
    "$REPO_ROOT/deploy/prahari.service" > /etc/systemd/system/prahari.service
systemctl daemon-reload
systemctl enable --now prahari

sleep 2
if systemctl is-active --quiet prahari; then
  echo "==> PRAHARI is running on 127.0.0.1:8000"
  echo "    journalctl -u prahari -f      # live log"
  echo "    next: put a TLS reverse proxy in front — see deploy/nginx.conf"
else
  echo "!! service did not start; check: journalctl -u prahari -n 40"
  exit 1
fi
