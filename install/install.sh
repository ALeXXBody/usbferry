#!/usr/bin/env bash
# Install netshare server as a systemd service under /opt/netshare.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root (sudo ./install/install.sh)" >&2; exit 1
fi

SRC="$(cd "$(dirname "$0")/.." && pwd)"
DEST=/opt/netshare

mkdir -p "$DEST"
cp -r "$SRC/netshare" "$SRC/web" "$DEST"/
cp "$SRC/README.md" "$DEST"/ 2>/dev/null || true
cp "$SRC/install/netshare-server.service" /etc/systemd/system/

systemctl daemon-reload
systemctl enable netshare-server.service

echo
echo "installed to $DEST"
echo "start now with:      systemctl start netshare-server"
echo "add a client token:  cd $DEST && python3 -m netshare add-token --name mylaptop"
echo "config:              /root/.config/netshare/server.json"
