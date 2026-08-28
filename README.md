# netshare

Share **USB devices** and a **LAN connection** across networks or the internet —
with a modern desktop GUI, a CLI, and a web-managed server.

netshare is a server/client app that tunnels the kernel-standard **USB/IP
(usbip)** protocol and raw **ethernet frames (TAP virtual NIC)** through one
encrypted, token-authenticated TLS connection — so a USB device plugged into
your server appears locally plugged into your client machine, and your client
can join the server's network from anywhere.

```
   CLIENT (anywhere)                          SERVER (has the USB device / LAN)
   ┌─────────────────────┐    TLS + token     ┌──────────────────────────────┐
   │ usbip attach ──► 127.0.0.1:3240 ═══╗     │  usbipd :3240 (loopback)  ◄──┼── bound USB devices
   │                                     ║ ═══╪═► tunnel :7575            │
   │ TAP ns0 (10.77.0.x) ════════════════╬══► │  TAP ns-lan0 ──► NAT/bridge ─┼── LAN / internet
   └─────────────────────┘                 ══►└──────────────────────────────┘
                                            └─ web UI :7580 for management
```

- **Encrypted**: TLS 1.2+ with self-signed certs, SHA-256 fingerprint pinning
  (trust-on-first-use), per-client tokens (stored hashed)
- **Multiplexed**: N usbip channels + LAN frames + control on one TCP port (7575)
- **USB**: uses the kernel-standard usbip protocol — interoperable with
  Linux `usbip` and Windows **usbip-win2** clients
- **LAN**: TAP-based virtual NIC; NAT mode (default) or bridge mode
- **Web UI**: embedded, token-protected management (status, bind/unbind USB
  devices, LAN leases, tokens)
- **Zero dependencies**: Python 3.10+ standard library only; `openssl` CLI for
  first-run cert generation

---

## Requirements

| Role | OS | Needs |
|---|---|---|
| Server | Linux | root, `usbip`/`usbipd` (for USB sharing), `/dev/net/tun` + `iptables` (for LAN sharing) |
| Client (Linux) | Linux | root for attach/LAN, `usbip` tools (`vhci-hcd`) |
| Client (Windows) | Windows 10/11 | [usbip-win2](https://github.com/vadimgrn/usbip-win2) for USB; OpenVPN TAP driver for LAN (experimental) |

**Server kernel note** — needs `usbip-host` module support (any standard
Debian/Ubuntu/Fedora/Proxmox kernel has it):

```bash
sudo apt install usbip hwdata        # Debian/Ubuntu (package may be linux-tools-$(uname -r))
sudo modprobe usbip-core usbip-host
```

TrueNAS / unprivileged LXCs block `/dev/net/tun` and lack `usbip-host` — run
the server in a standard Linux VM instead (LAN-only mode also works fine
without usbip).

## Quick start

### Graphical client (recommended)

Windows: double-click **`netshare.exe`** (or run `.\netshare.exe gui`).
Linux/macOS: `python3 -m netshare gui`.

The GUI opens a native window (Edge WebView2 / WebKit; falls back to your
browser) where you:

1. **Add server** — name, address, token, optional LAN toggle
2. **Connect** — first connection shows the server's certificate fingerprint
   to verify and pin (trust-on-first-use)
3. **USB devices tab** — see everything plugged into the server, one-click
   **Attach** (device appears locally), **Detach all** when done
4. **LAN tab** — your virtual IP, server IP, subnet
5. **Activity tab** — live traffic stats and logs

Everything is stored in `~/.config/netshare/gui.json` (profiles) and
`client.json` (pinned fingerprints). CLI equivalents: `list-usb`, `attach`,
`connect --lan`.

### Server

```bash
git clone <your-repo> && cd netshare
sudo ./install/install.sh              # copies to /opt/netshare, enables systemd unit
sudo systemctl start netshare-server

sudo python3 -m netshare add-token --name mylaptop
# token: ns_XXXXXXXX...   (shown once)
```

Open the web UI: `http://<server>:7580/` (unlock with any token), or edit
`~/.config/netshare/server.json`:

```json
{
  "port": 7575, "web": {"port": 7580},
  "lan": {"enabled": true, "mode": "nat", "subnet": "10.77.0.0/24"},
  "usbip": {"port": 3240}
}
```

For access from the internet, forward/reach TCP **7575** (the only port that
must be exposed — usbipd stays loopback-only and is firewall-rejected on other
interfaces automatically when iptables is available).

### Client

**Windows (no Python needed):**

1. Download **`netshare.exe`** from [Releases](../../releases) (built by CI, self-contained)
2. Install [usbip-win2](https://github.com/vadimgrn/usbip-win2/releases) once (the Windows USB/IP client driver; a restore point is recommended before driver installs)
3. PowerShell **as Administrator**:

```powershell
.\netshare.exe list-usb myserver.example.com --token ns_XXX --trust
.\netshare.exe attach myserver.example.com -b 1-2 --token ns_XXX --trust   # Ctrl-C detaches
.\netshare.exe connect myserver.example.com --token ns_XXX --trust --lan   # virtual NIC (needs TAP driver)
```

**Linux:**

```bash
# see what's plugged into the server
python3 -m netshare list-usb myserver.example.com --token ns_XXX --trust

# attach a device (appears as if locally plugged in; Ctrl-C detaches)
python3 -m netshare attach myserver.example.com -b 1-2 --token ns_XXX --trust

# LAN too: virtual NIC with an IP from the server's tunnel subnet
python3 -m netshare connect myserver.example.com --token ns_XXX --trust --lan

# route ALL traffic through the server (remote-gateway mode)
python3 -m netshare connect myserver.example.com --token ns_XXX --trust --lan --default-route
```

First connection pins the server's certificate fingerprint (TOFU); verify it
against the value printed by the server (also shown in the web UI). Tokens can
be passed via `NETSHARE_TOKEN` env var.

**Windows client**: install [usbip-win2](https://github.com/vadimgrn/usbip-win2)
(same `usbip attach -r 127.0.0.1 -b <busid>` syntax is automated for you, run
PowerShell as Administrator). For LAN sharing install the OpenVPN TAP driver;
the client configures it via netsh (experimental).

## How USB sharing works

1. Web UI or CLI **binds** (exports) a server-side USB device:
   `usbip bind -b 1-2`
2. Client runs `netshare attach ... -b 1-2`, which:
   - opens the encrypted tunnel and forwards local `127.0.0.1:3240` to the
     server's usbipd
   - runs `usbip attach -r 127.0.0.1 -b 1-2` locally
3. The kernel `vhci-hcd` driver makes the device appear locally; detach with
   Ctrl-C.

## How LAN sharing works

- **nat** (default): server TAP gets `10.77.0.1/24`, NAT (MASQUERADE) out the
  server's default interface. Each client token gets a stable lease
  (`10.77.0.x`). Client TAP + optional `--default-route` = full remote gateway.
- **bridge**: set `"lan": {"mode": "bridge", "bridge": "br0"}` to enslave the
  server TAP into an existing bridge — the client appears as a real L2 member
  of your LAN (broadcasts, mDNS, DLNA...).

## Security model

- TLS 1.2+, self-signed cert, **fingerprint pinned** by the client on first use
- Tokens hashed (SHA-256) at rest, constant-time compare, named per device,
  revocable in the web UI
- usbipd restricted to loopback by an iptables REJECT rule (best effort)
- Web UI requires a valid token (Bearer) for every API call
- LAN clients are isolated from each other at L3 unless you bridge

Caveat: the tunnel is authenticated/encrypted but carries no application-level
authorization per USB device — any token can attach any *bound* device. Bind
only what you share; issue per-person tokens and revoke to cut access.

## Development

```bash
python3 tests/test_loopback.py     # full protocol/relay/auth suite, no hardware needed
```

Layout: `netshare/common.py` (framing) · `server.py` (tunnel+usbip+LAN) ·
`client.py` · `webui.py` + `web/index.html` · `tapw.py` (TAP backends) ·
`certutil.py`.

## Status / limitations

- Windows LAN mode is experimental (TAP-Windows driver, blocking IO threads)
- usbip isochronous devices (webcams/audio) depend on usbip quality, not this
  tunnel; control/bulk devices (dongles, printers, serial, storage) work well
- No per-device ACLs yet (see security model)
