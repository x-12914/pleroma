#!/usr/bin/env bash
# Pleroma sensor installer — interactive.
#
# Run as a user with sudo. Installs:
#   /opt/pleroma-sensor/agent.py        the script itself
#   /opt/pleroma-sensor/.venv/          isolated Python env with cicflowmeter + requests
#   /usr/local/bin/pleroma-sensor       shim that runs the venv's python on agent.py
#   /etc/pleroma-sensor/config          server URL, interface, batch settings
#   /etc/pleroma-sensor/key             API key (mode 600)
#   /etc/systemd/system/pleroma-sensor.service
#
# Usage:
#   sudo ./install.sh
#
# Re-running is safe; it'll prompt before overwriting an existing key.

set -euo pipefail

require_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "ERROR: run as root (use sudo)." >&2
    exit 1
  fi
}

require_root

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
INSTALL_DIR="/opt/pleroma-sensor"
CONFIG_DIR="/etc/pleroma-sensor"
SHIM="/usr/local/bin/pleroma-sensor"
UNIT="/etc/systemd/system/pleroma-sensor.service"

echo "== pleroma-sensor installer =="

# ---- 1. System deps ----
echo "[1/6] installing system deps (python3-venv, python3-pip, tcpdump)…"
if command -v apt-get &>/dev/null; then
  apt-get update -qq
  apt-get install -y python3-venv python3-pip tcpdump libpcap-dev > /dev/null
elif command -v dnf &>/dev/null; then
  dnf install -y python3-virtualenv python3-pip tcpdump libpcap-devel > /dev/null
else
  echo "WARN: unknown package manager — install python3-venv, pip, libpcap manually." >&2
fi

# ---- 2. Venv + Python deps ----
# We dropped cicflowmeter — both v0.3 and v0.4 are broken on Python 3.14
# (sniff packets fine, never flush CSV). The agent now implements the
# 78 CIC features directly on top of Scapy, so we only need scapy + requests.
echo "[2/6] creating venv at $INSTALL_DIR/.venv and installing scapy + requests…"
mkdir -p "$INSTALL_DIR"
python3 -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/pip" install --quiet --upgrade pip
"$INSTALL_DIR/.venv/bin/pip" install --quiet scapy requests

# ---- 3. Copy agent ----
echo "[3/6] installing agent to $INSTALL_DIR/agent.py"
cp "$SCRIPT_DIR/agent.py" "$INSTALL_DIR/agent.py"
chmod 755 "$INSTALL_DIR/agent.py"

# ---- 4. Shim ----
echo "[4/6] writing shim $SHIM"
cat > "$SHIM" <<EOF
#!/usr/bin/env bash
exec $INSTALL_DIR/.venv/bin/python $INSTALL_DIR/agent.py "\$@"
EOF
chmod 755 "$SHIM"

# ---- 5. Config + key ----
mkdir -p "$CONFIG_DIR"
chmod 755 "$CONFIG_DIR"

if [[ ! -f "$CONFIG_DIR/config" ]]; then
  echo "[5/6] configuring sensor…"
  DEFAULT_IFACE="$(ip -o -4 route show to default 2>/dev/null | awk '{print $5}' | head -1)"
  read -rp "  pleroma server URL [https://pleroma-aicds.duckdns.org]: " PLEROMA_SERVER
  PLEROMA_SERVER="${PLEROMA_SERVER:-https://pleroma-aicds.duckdns.org}"
  read -rp "  network interface to sniff [${DEFAULT_IFACE:-eth0}]: " PLEROMA_INTERFACE
  PLEROMA_INTERFACE="${PLEROMA_INTERFACE:-${DEFAULT_IFACE:-eth0}}"
  cat > "$CONFIG_DIR/config" <<EOF
# pleroma sensor config — managed by install.sh, edit freely
PLEROMA_SERVER=$PLEROMA_SERVER
PLEROMA_INTERFACE=$PLEROMA_INTERFACE
PLEROMA_BATCH_SIZE=50
PLEROMA_BATCH_INTERVAL=10
PLEROMA_VERIFY_TLS=true
EOF
  chmod 644 "$CONFIG_DIR/config"
else
  echo "[5/6] $CONFIG_DIR/config already exists — leaving it alone"
fi

if [[ -f "$CONFIG_DIR/key" ]]; then
  read -rp "  $CONFIG_DIR/key exists. Overwrite with a new API key? [y/N] " REPLACE
  if [[ "${REPLACE,,}" != "y" ]]; then
    echo "  keeping existing key"
  else
    rm -f "$CONFIG_DIR/key"
  fi
fi

if [[ ! -f "$CONFIG_DIR/key" ]]; then
  echo
  echo "  Get an API key by registering a sensor in the dashboard:"
  echo "    1. Log in to your pleroma instance"
  echo "    2. Sidebar → Sensors → Register a new sensor"
  echo "    3. Copy the key shown in the reveal modal"
  echo
  read -rsp "  paste the API key (pleroma_…): " PLEROMA_SENSOR_KEY
  echo
  echo "$PLEROMA_SENSOR_KEY" > "$CONFIG_DIR/key"
  chmod 600 "$CONFIG_DIR/key"
  chown root:root "$CONFIG_DIR/key"
fi

# ---- 6. systemd ----
echo "[6/6] installing systemd unit…"
cp "$SCRIPT_DIR/pleroma-sensor.service" "$UNIT"
systemctl daemon-reload
systemctl enable pleroma-sensor.service > /dev/null

echo
echo "== install complete =="
echo
echo "Start the sensor now:"
echo "  sudo systemctl start pleroma-sensor"
echo
echo "Watch the logs:"
echo "  sudo journalctl -u pleroma-sensor -f"
echo
echo "Verify flows are arriving by visiting your pleroma dashboard"
echo "and checking the Logs page after ~30s of normal browsing."
