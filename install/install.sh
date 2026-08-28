#!/usr/bin/env bash
# Install usbferry server as a systemd service under /opt/usbferry.
# Config (tokens, certs, state) lives in /etc/usbferry — independent of $HOME.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root (sudo ./install/install.sh)" >&2; exit 1
fi

SRC="$(cd "$(dirname "$0")/.." && pwd)"
DEST=/opt/usbferry
CONF=/etc/usbferry

mkdir -p "$DEST" "$CONF"
cp -r "$SRC/usbferry" "$SRC/web" "$SRC/pyproject.toml" "$SRC/README.md" "$DEST"/

# idempotent venv + install
python3 -m venv "$DEST/.venv"
"$DEST/.venv/bin/pip" install --upgrade pip -q
"$DEST/.venv/bin/pip" install "$DEST" -q

cp "$SRC/install/usbferry-server.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable usbferry-server.service

echo
echo "installed to $DEST   (config: $CONF)"
echo "start now:      systemctl start usbferry-server"
echo "add a token:    USBFERRY_CONFIG_DIR=$CONF $DEST/.venv/bin/usbferry add-token --name mylaptop"
echo "web admin:      http://<this-host>:7580/"
