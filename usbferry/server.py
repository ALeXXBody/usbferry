"""usbferry server: TLS tunnel, token auth, usbip backend, LAN (TAP/NAT) backend."""

import asyncio
import ipaddress
import json
import os
import platform
import re
import socket
import time
import uuid

from . import __version__, certutil
from .common import (
    CH_CONTROL, DEFAULT_PORT, DEFAULT_WEB_PORT, FT_CLOSE, FT_CTRL, FT_DATA,
    FT_OPEN, FT_PING, FT_PONG, MAX_HELLO, ProtocolError, USBIP_PORT,
    config_dir, constant_time_eq, human_bytes, load_json, log,
    new_token, read_frame, run, save_json,
    token_hash, which,
)
from .tapw import KernelTap, TapClosed, TapError


class UsbipManager:
    """Manages the local usbip daemon (usbipd) and bind/unbind of devices."""

    def __init__(self, cfg: dict):
        self.host = cfg.get("host", "127.0.0.1")
        self.port = int(cfg.get("port", USBIP_PORT))
        self.start_daemon = cfg.get("start_daemon", True)
        self.firewall = cfg.get("firewall", True)
        self.usbip_bin = which("usbip")
        self.usbipd_bin = which("usbipd")
        self.available = False
        self.error = None
        self._proc = None

    async def start(self):
        if await self._port_open():
            self.available = True
            log.info("usbipd already listening on %s:%s", self.host, self.port)
        elif self.usbipd_bin and self.start_daemon:
            log.info("starting usbipd ...")
            # -D daemonizes on classic usbipd; some builds lack it, so try both
            rc, _, err = await run([self.usbipd_bin, "-D"], timeout=5)
            if rc not in (0,):
                try:
                    self._proc = await asyncio.create_subprocess_exec(
                        self.usbipd_bin,
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.DEVNULL,
                    )
                    await asyncio.sleep(0.5)
                except OSError as e:
                    self.error = f"cannot start usbipd: {e}"
            for _ in range(20):
                if await self._port_open():
                    break
                await asyncio.sleep(0.25)
            self.available = await self._port_open()
            if self.available:
                log.info("usbipd started (pid %s)", self._proc.pid if self._proc else "daemon")
            else:
                self.error = self.error or "usbipd did not come up (kernel usbip_host module missing?)"
                log.warning("usbipd unavailable: %s", self.error)
        else:
            self.error = "usbipd not found in PATH (install linux-tools-`uname -r` / usbip package)"
            log.warning("usbip unavailable: %s", self.error)

        if self.available and self.firewall:
            await self._harden_firewall()

    async def _port_open(self) -> bool:
        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port), timeout=1.0)
            w.close()
            return True
        except (OSError, asyncio.TimeoutError):
            return False

    async def _harden_firewall(self):
        """usbipd binds all interfaces; block non-loopback access so only the
        encrypted usbferry tunnel reaches it."""
        if not which("iptables"):
            log.warning("iptables not found; consider blocking external TCP/%s for usbipd", self.port)
            return
        rule = ["iptables", "-t", "filter"]
        check = rule + ["-C", "INPUT", "!", "-i", "lo", "-p", "tcp", "--dport", str(self.port), "-j", "REJECT"]
        add = rule + ["-I", "INPUT", "!", "-i", "lo", "-p", "tcp", "--dport", str(self.port), "-j", "REJECT"]
        rc, _, _ = await run(check)
        if rc != 0:
            rc, _, err = await run(add)
            if rc == 0:
                log.info("firewall: restricted usbipd to loopback (REJECT non-lo tcp/%s)", self.port)
            else:
                log.warning("could not add firewall rule for usbipd: %s", err.strip())

    async def list_devices(self) -> list[dict]:
        if not self.usbip_bin:
            return []
        rc, out, _ = await run([self.usbip_bin, "list", "-l"])
        devices = []
        if rc == 0:
            lines = out.splitlines()
            for i, line in enumerate(lines):
                m = re.match(r"\s*-\s*busid\s+(\S+)\s+\(([0-9a-fA-F]{4}:[0-9a-fA-F]{4})\)", line)
                if not m:
                    continue
                desc = ""
                if i + 1 < len(lines):
                    desc = lines[i + 1].strip()
                devices.append({
                    "busid": m.group(1),
                    "vidpid": m.group(2).lower(),
                    "desc": re.sub(r"\s*\(" + re.escape(m.group(2)) + r"\)$", "", desc),
                    "exported": False,
                })
        exported = set()
        if self.available:
            rc, out, _ = await run([self.usbip_bin, "list", "-r", self.host])
            if rc == 0:
                for line in out.splitlines():
                    m = re.match(r"\s*(\S+):", line)
                    if m and "-" in m.group(1):
                        exported.add(m.group(1))
        for d in devices:
            if d["busid"] in exported:
                d["exported"] = True
        return devices

    async def bind(self, busid: str) -> tuple[bool, str]:
        if not self.usbip_bin:
            return False, "usbip tool not installed on server"
        rc, out, err = await run([self.usbip_bin, "bind", "-b", busid])
        return rc == 0, (err.strip() or out.strip() or f"exit {rc}")

    async def unbind(self, busid: str) -> tuple[bool, str]:
        if not self.usbip_bin:
            return False, "usbip tool not installed on server"
        rc, out, err = await run([self.usbip_bin, "unbind", "-b", busid])
        return rc == 0, (err.strip() or out.strip() or f"exit {rc}")

    async def stop(self):
        if self._proc:
            try:
                self._proc.terminate()
            except ProcessLookupError:
                pass


_BUSID_RE = re.compile(r"^\d+-\d+(\.\d+)*$")
_USBIPD_STATE_RE = re.compile(
    r"\s(Not shared|Shared(?: \(read-only\))?|Attached(?: \(.*\))?)$")


class WindowsUsbipManager:
    """Server-side usbip management on Windows via usbipd-win (dorssel/usbipd-win).

    usbipd-win runs a Windows service (its own daemon on TCP/3240); we only
    manage it: check the service port, parse `usbipd list`, bind/unbind.
    """

    def __init__(self, cfg: dict):
        self.host = cfg.get("host", "127.0.0.1")
        self.port = int(cfg.get("port", USBIP_PORT))
        self.start_daemon = cfg.get("start_daemon", True)
        self.usbipd_bin = which("usbipd") or which("usbipd.exe")
        self.available = False
        self.error = None

    async def start(self):
        if await self._port_open():
            self.available = True
            log.info("usbipd-win service listening on %s:%s", self.host, self.port)
            return
        if self.usbipd_bin and self.start_daemon:
            rc, _, _ = await run(["net", "start", "usbipd"], timeout=20)
            for _ in range(20):
                if await self._port_open():
                    break
                await asyncio.sleep(0.25)
        if await self._port_open():
            self.available = True
            log.info("usbipd-win service started")
        else:
            self.error = (
                "usbipd-win service is not running. Install usbipd-win "
                "(https://github.com/dorssel/usbipd-win/releases) or start it "
                "from an admin prompt:  net start usbipd")
            log.warning("usbip unavailable: %s", self.error)

    async def _port_open(self) -> bool:
        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port), timeout=1.0)
            w.close()
            return True
        except (OSError, asyncio.TimeoutError):
            return False

    @staticmethod
    def parse_list(out: str) -> list[dict]:
        devices = []
        for raw in out.splitlines():
            line = raw.strip()
            if not line:
                continue
            tok = line.split()
            if not _BUSID_RE.match(tok[0]):
                # usbipd-win 2.x style:  "  1-2: vendor : product (045e:00cb)"
                m = re.match(
                    r"(\d+-\d+(?:\.\d+)*):\s+(.*?)\s*\(([0-9a-fA-F]{4}:[0-9a-fA-F]{4})\)",
                    line)
                if m:
                    devices.append({"busid": m.group(1), "vidpid": m.group(3).lower(),
                                    "desc": m.group(2).strip(), "exported": False})
                continue
            busid = tok[0]
            desc = line[len(busid):].strip()
            state = ""
            m = _USBIPD_STATE_RE.search(desc)
            if m:
                state = m.group(1)
                desc = desc[:m.start()].strip()
            vidpid = ""
            vm = re.search(r"([0-9a-fA-F]{4}:[0-9a-fA-F]{4})", desc)
            if vm:
                vidpid = vm.group(1).lower()
                desc = (desc[:vm.start()] + " " + desc[vm.end():]).strip(" -")
            devices.append({"busid": busid, "vidpid": vidpid,
                            "desc": desc or "USB device",
                            "exported": state.startswith("Shared")})
        return devices

    async def list_devices(self) -> list[dict]:
        if not self.usbipd_bin:
            return []
        rc, out, _ = await run([self.usbipd_bin, "list"])
        if rc != 0:
            return []
        return self.parse_list(out)

    async def bind(self, busid: str) -> tuple[bool, str]:
        if not self.usbipd_bin:
            return False, "usbipd not installed on this machine"
        rc, out, err = await run([self.usbipd_bin, "bind", "--busid", busid])
        return rc == 0, (err.strip() or out.strip() or f"exit {rc}")

    async def unbind(self, busid: str) -> tuple[bool, str]:
        if not self.usbipd_bin:
            return False, "usbipd not installed on this machine"
        rc, out, err = await run([self.usbipd_bin, "unbind", "--busid", busid])
        return rc == 0, (err.strip() or out.strip() or f"exit {rc}")

    async def stop(self):
        pass  # service is external; we never kill it


def make_usbip_manager(cfg: dict):
    """Platform-appropriate usbip backend for the server."""
    if os.name == "nt":
        return WindowsUsbipManager(cfg)
    return UsbipManager(cfg)


class LanManager:
    """Server-side LAN sharing over a TAP interface.

    nat mode:    tap gets SERVER_IP/prefix, ip_forward + iptables MASQUERADE out the WAN iface
    bridge mode: tap is enslaved to an existing bridge (config lan.bridge)
    """

    def __init__(self, cfg: dict, state_path: str, tap_factory=None):
        self.cfg = cfg
        self.state_path = state_path
        self.tap_factory = tap_factory  # test hook: () -> tap endpoint
        self.tap = None
        self.sessions: set = set()
        self.active = False
        self.error = None
        self.subnet = ipaddress.ip_network(cfg.get("subnet", "10.77.0.0/24"), strict=False)
        self.server_ip = cfg.get("server_ip") or str(next(self.subnet.hosts()))
        self.mtu = int(cfg.get("mtu", 1500))
        self.mode = cfg.get("mode", "nat")
        self.iface = cfg.get("iface", "ns-lan0")
        self._pump_task = None

    async def start(self):
        try:
            if self.tap_factory:
                self.tap = self.tap_factory()
            else:
                self.tap = await KernelTap.create(self.iface)
        except TapError as e:
            self.error = str(e)
            log.warning("LAN sharing disabled: %s", self.error)
            return
        await self._configure()
        self._pump_task = asyncio.create_task(self._pump())
        self.active = True
        log.info("LAN sharing active: mode=%s subnet=%s tap=%s", self.mode, self.subnet, self.iface)

    async def _configure(self):
        if not self.cfg.get("configure", True):
            log.info("lan.configure=false - skipping host network setup")
            return
        if self.mode == "bridge":
            br = self.cfg.get("bridge")
            if not br:
                self.error = "lan.mode=bridge requires lan.bridge=<existing bridge>"
                raise TapError(self.error)
            await run(["ip", "link", "set", self.iface, "master", br])
            await run(["ip", "link", "set", self.iface, "up"])
            return
        # nat mode
        await run(["ip", "link", "set", self.iface, "down"])
        await run(["ip", "addr", "flush", "dev", self.iface])
        await run(["ip", "addr", "add", f"{self.server_ip}/{self.subnet.prefixlen}", "dev", self.iface])
        await run(["ip", "link", "set", self.iface, "mtu", str(self.mtu), "up"])
        await run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
        wan = await self._wan_iface()
        if not wan:
            self.error = "could not determine default-route interface for NAT"
            raise TapError(self.error)
        await self._nat_rules(str(self.subnet), wan)
        log.info("LAN NAT: %s -> %s", self.subnet, wan)

    async def _wan_iface(self) -> str | None:
        rc, out, _ = await run(["ip", "route", "show", "default"])
        m = re.search(r"\bdev\s+(\S+)", out)
        return m.group(1) if m else None

    async def _nat_rules(self, subnet: str, wan: str):
        if which("iptables"):
            for check, add in [
                (["-t", "nat", "-C", "POSTROUTING", "-s", subnet, "-o", wan, "-j", "MASQUERADE"],
                 ["-t", "nat", "-A", "POSTROUTING", "-s", subnet, "-o", wan, "-j", "MASQUERADE"]),
                (["-C", "FORWARD", "-s", subnet, "-j", "ACCEPT"],
                 ["-I", "FORWARD", "-s", subnet, "-j", "ACCEPT"]),
                (["-C", "FORWARD", "-d", subnet, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
                 ["-I", "FORWARD", "-d", subnet, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"]),
            ]:
                rc, _, _ = await run(["iptables"] + check)
                if rc != 0:
                    await run(["iptables"] + add)
        else:
            log.warning("iptables not found; add NAT rules manually for %s -> %s", subnet, wan)

    async def _pump(self):
        try:
            while True:
                frame = await self.tap.read_frame()
                for s in list(self.sessions):
                    try:
                        s.send_data(s.lan_ch, frame)
                    except Exception:
                        self.sessions.discard(s)
        except TapClosed:
            log.info("LAN tap closed")
        except asyncio.CancelledError:
            raise
        except Exception as e:
            log.error("LAN pump crashed: %r", e)
        finally:
            self.active = False

    def write_frame(self, data: bytes):
        if self.tap is not None:
            asyncio.get_running_loop().create_task(self._write(data))

    async def _write(self, data: bytes):
        try:
            await self.tap.write_frame(data)
        except (TapClosed, TapError):
            pass

    def join(self, session):
        self.sessions.add(session)

    def leave(self, session):
        self.sessions.discard(session)

    def assign_ip(self, token_h: str) -> str:
        state = load_json(self.state_path, {"leases": {}})
        leases: dict = state.setdefault("leases", {})
        key = token_h[:16]
        if key in leases:
            return leases[key]
        used = {self.server_ip} | set(leases.values())
        for ip in self.subnet.hosts():
            ip = str(ip)
            if ip not in used:
                leases[key] = ip
                save_json(self.state_path, state)
                return ip
        raise TapError("LAN address pool exhausted")

    def lease_list(self) -> list[dict]:
        state = load_json(self.state_path, {"leases": {}})
        return [{"key": k, "ip": v} for k, v in state.get("leases", {}).items()]

    async def stop(self):
        if self._pump_task:
            self._pump_task.cancel()
        if self.tap:
            self.tap.close()
        if self.tap_factory is None:
            await run(["ip", "link", "delete", self.iface])


class Channel:
    __slots__ = ("ch", "tcp_writer", "pump")

    def __init__(self, ch, tcp_writer, pump):
        self.ch = ch
        self.tcp_writer = tcp_writer
        self.pump = pump


class Session:
    def __init__(self, server, reader, writer, addr):
        self.id = uuid.uuid4().hex[:8]
        self.server = server
        self.reader = reader
        self.writer = writer
        self.addr = f"{addr[0]}:{addr[1]}" if isinstance(addr, tuple) else str(addr)
        self.token_name = "?"
        self.hostname = "?"
        self.channels: dict[int, Channel] = {}
        self.lan_ch: int | None = None
        self.lan_ip: str | None = None
        self.rx = 0
        self.tx = 0
        self.connected_at = time.time()
        self.last_seen = time.monotonic()
        self.closed = False

    def send_data(self, ch: int, payload: bytes):
        self.tx += len(payload)
        self.send(FT_DATA, ch, payload)

    def send(self, ftype: int, ch: int, payload: bytes = b""):
        self.writer.write(bytes([ftype, ch]) + len(payload).to_bytes(4, "big") + payload)

    def kick(self):
        self.writer.close()


DEFAULT_CONFIG = {
    "bind": "0.0.0.0",
    "port": DEFAULT_PORT,
    "web": {"bind": "0.0.0.0", "port": DEFAULT_WEB_PORT},
    "usbip": {"host": "127.0.0.1", "port": USBIP_PORT, "start_daemon": True, "firewall": True},
    "lan": {"enabled": True, "mode": "nat", "subnet": "10.77.0.0/24", "server_ip": "10.77.0.1", "mtu": 1500, "bridge": ""},
    "tokens": [],
    "keepalive": {"interval": 20, "timeout": 60},
}


class UsbferryServer:
    def __init__(self, config_path: str | None = None, overrides: dict | None = None,
                 usbip_manager=None, lan_manager=None):
        self.config_path = config_path or os.path.join(config_dir(), "server.json")
        self.cfg = dict(DEFAULT_CONFIG)
        deep_merge(self.cfg, load_json(self.config_path, {}))
        try:
            self._cfg_mtime = os.path.getmtime(self.config_path)
        except OSError:
            self._cfg_mtime = None
        if overrides:
            deep_merge(self.cfg, overrides)
        self.state_path = os.path.join(os.path.dirname(self.config_path), "server.state.json")
        self.fingerprint = ""
        self.sessions: dict[str, Session] = {}
        self._srv = None
        self.started_at = 0
        self.usbip = usbip_manager or make_usbip_manager(self.cfg["usbip"])
        if lan_manager is not None:
            self.lan = lan_manager
        else:
            self.lan = LanManager(self.cfg["lan"], self.state_path)
        self.webui = None
        self._ka_task = None

    # ----- tokens -----------------------------------------------------------
    def add_token(self, name: str) -> str:
        token = new_token()
        tokens = self.cfg.setdefault("tokens", [])
        tokens.append({"name": name, "hash": token_hash(token),
                       "created": time.strftime("%Y-%m-%d %H:%M:%S")})
        self._save_config()
        return token

    def remove_token(self, name: str) -> bool:
        tokens = self.cfg.get("tokens", [])
        before = len(tokens)
        self.cfg["tokens"] = [t for t in tokens if t["name"] != name]
        changed = len(self.cfg["tokens"]) != before
        if changed:
            self._save_config()
        return changed

    def verify_token(self, token: str) -> str | None:
        # tokens may be added/removed on disk while running (add-token CLI);
        # one stat() per auth keeps the in-memory list in sync
        self._reload_tokens_if_changed()
        return self._lookup_token(token)

    def _lookup_token(self, token: str) -> str | None:
        th = token_hash(token)
        for t in self.cfg.get("tokens", []):
            if constant_time_eq(t["hash"], th):
                return t["name"]
        return None

    def _reload_tokens_if_changed(self):
        try:
            mtime = os.path.getmtime(self.config_path)
        except OSError:
            return
        if mtime == getattr(self, "_cfg_mtime", None):
            return
        fresh = load_json(self.config_path, {})
        if isinstance(fresh.get("tokens"), list):
            self.cfg["tokens"] = fresh["tokens"]
            self._cfg_mtime = mtime
            log.info("reloaded %d token(s) from %s", len(self.cfg["tokens"]), self.config_path)

    def _save_config(self):
        save_json(self.config_path, self.cfg)
        try:
            self._cfg_mtime = os.path.getmtime(self.config_path)
        except OSError:
            pass

    # ----- lifecycle --------------------------------------------------------
    async def start(self):
        cert_dir = self.cfg.get("certs_dir") or os.path.join(os.path.dirname(self.config_path), "certs")
        cert, key, self.fingerprint = certutil.ensure_cert(cert_dir)
        await self.usbip.start()
        if self.cfg["lan"].get("enabled", True):
            await self.lan.start()
        else:
            log.info("LAN sharing disabled in config")

        ctx = certutil.server_ssl_context(cert, key)
        self._srv = await asyncio.start_server(
            self._handle_client, self.cfg["bind"], int(self.cfg["port"]), ssl=ctx)
        self.started_at = time.time()
        self._ka_task = asyncio.create_task(self._keepalive_loop())

        from .webui import WebUI
        web_cfg = self.cfg.get("web", {})
        self.webui = WebUI(self, web_cfg.get("bind", "0.0.0.0"), int(web_cfg.get("port", DEFAULT_WEB_PORT)))
        await self.webui.start()

        log.info("=" * 62)
        log.info("usbferry server v%s listening on %s:%s (tunnel, TLS)", __version__, self.cfg["bind"], self.cfg["port"])
        log.info("web UI: http://%s:%s/", web_cfg.get("bind", "0.0.0.0"), web_cfg.get("port", DEFAULT_WEB_PORT))
        log.info("cert fingerprint: %s", self.fingerprint)
        log.info("usb sharing: %s", "ready" if self.usbip.available else f"UNAVAILABLE ({self.usbip.error})")
        log.info("lan sharing: %s", f"ready ({self.lan.mode})" if self.lan.active else f"UNAVAILABLE ({self.lan.error})")
        if not self.cfg.get("tokens"):
            log.warning("NO TOKENS configured - run:  python3 -m usbferry add-token --name mylaptop")
        log.info("=" * 62)

    async def stop(self):
        if self._ka_task:
            self._ka_task.cancel()
        for s in list(self.sessions.values()):
            await self._cleanup_session(s)
        if self._srv:
            self._srv.close()
            await self._srv.wait_closed()
        await self.lan.stop()
        await self.usbip.stop()
        if self.webui:
            await self.webui.stop()

    # ----- connection handling ---------------------------------------------
    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        session = Session(self, reader, writer, addr)
        try:
            writer.get_extra_info("socket").setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=15)
            if len(line) > MAX_HELLO:
                raise ProtocolError("hello too large")
            hello = json.loads(line)
            token = hello.get("token", "")
            name = self.verify_token(token)
            if not name:
                writer.write(json.dumps({"ok": False, "error": "invalid token"}).encode() + b"\n")
                await writer.drain()
                log.warning("auth failed from %s", session.addr)
                return
            session.token_name = name
            session.hostname = str(hello.get("hostname", "?"))[:64]
            want = hello.get("want", [])

            reply = {"ok": True, "v": 1, "server": platform.node() or "usbferry",
                     "version": __version__,
                     "usbip": self.usbip.available}
            if "lan" in want and self.lan.active:
                session.lan_ip = self.lan.assign_ip(token_hash(token))
                reply["lan"] = {"ip": session.lan_ip,
                                "prefix": self.lan.subnet.prefixlen,
                                "server_ip": self.lan.server_ip,
                                "mtu": self.lan.mtu}
            writer.write(json.dumps(reply).encode() + b"\n")
            await writer.drain()

            self.sessions[session.id] = session
            log.info("session %s from %s (%s / %s) - usbip=%s lan_ip=%s",
                     session.id, session.addr, session.token_name, session.hostname,
                     self.usbip.available, session.lan_ip)
            await self._frame_loop(session)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionResetError,
                json.JSONDecodeError, ProtocolError, OSError) as e:
            log.debug("session %s ended (%r)", session.id, e)
        finally:
            await self._cleanup_session(session)

    async def _frame_loop(self, session: Session):
        while True:
            ftype, ch, payload = await read_frame(session.reader)
            session.last_seen = time.monotonic()
            if ftype == FT_PING:
                session.send(FT_PONG, ch)
                await session.writer.drain()
            elif ftype == FT_PONG:
                pass
            elif ftype == FT_CTRL and ch == CH_CONTROL:
                await self._handle_ctrl(session, payload)
            elif ftype == FT_OPEN:
                await self._open_channel(session, ch, payload)
            elif ftype == FT_CLOSE:
                self._close_channel(session, ch)
            elif ftype == FT_DATA:
                session.rx += len(payload)
                if ch == session.lan_ch and self.lan.active:
                    self.lan.write_frame(payload)
                elif ch in session.channels:
                    cw = session.channels[ch].tcp_writer
                    cw.write(payload)
                    if cw.transport.get_write_buffer_size() > 262144:
                        await cw.drain()
            else:
                raise ProtocolError(f"unknown frame type {ftype}")

    async def _handle_ctrl(self, session: Session, payload: bytes):
        try:
            req = json.loads(payload)
        except json.JSONDecodeError:
            return
        rid = req.get("id")
        cmd = req.get("cmd")

        def reply(ok, data=None, error=None):
            obj = {"id": rid, "ok": ok}
            if data is not None:
                obj["data"] = data
            if error:
                obj["error"] = error
            session.send(FT_CTRL, CH_CONTROL, json.dumps(obj).encode())

        if cmd == "usb.list":
            reply(True, {"available": self.usbip.available,
                         "error": self.usbip.error,
                         "devices": await self.usbip.list_devices()})
        elif cmd == "info":
            reply(True, self.status())
        else:
            reply(False, error=f"unknown cmd {cmd}")
        await session.writer.drain()

    async def _open_channel(self, session: Session, ch: int, payload: bytes):
        if ch == CH_CONTROL or ch in session.channels:
            session.send(FT_CLOSE, ch, b'{"reason":"bad channel"}')
            return
        try:
            req = json.loads(payload) if payload else {"type": "usbip"}
        except json.JSONDecodeError:
            session.send(FT_CLOSE, ch, b'{"reason":"bad open"}')
            return
        ctype = req.get("type", "usbip")

        if ctype == "usbip":
            if not self.usbip.available:
                session.send(FT_CLOSE, ch, json.dumps(
                    {"reason": f"usbip unavailable on server: {self.usbip.error}"}).encode())
                await session.writer.drain()
                return
            try:
                r, w = await asyncio.open_connection(self.usbip.host, self.usbip.port)
            except OSError as e:
                session.send(FT_CLOSE, ch, json.dumps({"reason": str(e)}).encode())
                await session.writer.drain()
                return
            pump = asyncio.create_task(self._usbip_pump(session, ch, r))
            session.channels[ch] = Channel(ch, w, pump)
            log.debug("session %s: usbip channel %d open", session.id, ch)
        elif ctype == "lan":
            if not self.lan.active:
                session.send(FT_CLOSE, ch, json.dumps(
                    {"reason": f"lan unavailable on server: {self.lan.error}"}).encode())
                await session.writer.drain()
                return
            if session.lan_ch is not None:
                session.send(FT_CLOSE, ch, b'{"reason":"lan already open"}')
                await session.writer.drain()
                return
            session.lan_ch = ch
            self.lan.join(session)
            log.debug("session %s: lan channel %d open", session.id, ch)
        else:
            session.send(FT_CLOSE, ch, b'{"reason":"unknown channel type"}')

    async def _usbip_pump(self, session: Session, ch: int, r: asyncio.StreamReader):
        try:
            while True:
                data = await r.read(65536)
                if not data:
                    break
                session.send_data(ch, data)
                await session.writer.drain()
        except (ConnectionResetError, asyncio.IncompleteReadError, OSError):
            pass
        finally:
            log.debug("session %s: usbip channel %d closed by daemon", session.id, ch)
            try:
                session.send(FT_CLOSE, ch)
                await session.writer.drain()
            except (ConnectionResetError, OSError, AttributeError, asyncio.CancelledError):
                pass
            self._close_channel(session, ch)

    def _close_channel(self, session: Session, ch: int):
        if session.lan_ch == ch:
            self.lan.leave(session)
            session.lan_ch = None
            return
        chan = session.channels.pop(ch, None)
        if chan:
            if chan.pump and not chan.pump.done():
                chan.pump.cancel()
            if chan.tcp_writer:
                chan.tcp_writer.close()

    async def _cleanup_session(self, session: Session):
        if session.closed:
            return
        session.closed = True
        for ch in list(session.channels):
            self._close_channel(session, ch)
        if session.lan_ch is not None:
            self.lan.leave(session)
        self.sessions.pop(session.id, None)
        try:
            session.writer.close()
        except OSError:
            pass
        if session.token_name != "?":
            log.info("session %s closed (%s / %s) rx=%s tx=%s", session.id, session.token_name,
                     session.hostname, human_bytes(session.rx), human_bytes(session.tx))

    async def _keepalive_loop(self):
        interval = int(self.cfg.get("keepalive", {}).get("interval", 20))
        timeout = int(self.cfg.get("keepalive", {}).get("timeout", 60))
        while True:
            await asyncio.sleep(interval)
            now = time.monotonic()
            for s in list(self.sessions.values()):
                if now - s.last_seen > timeout:
                    log.info("session %s keepalive timeout", s.id)
                    s.kick()
                    continue
                try:
                    s.send(FT_PING, CH_CONTROL)
                except Exception:
                    pass

    # ----- status (web UI + ctrl) -------------------------------------------
    def status(self) -> dict:
        sessions = [{
            "id": s.id, "addr": s.addr, "token": s.token_name, "hostname": s.hostname,
            "channels": len(s.channels), "lan": s.lan_ip,
            "rx": s.rx, "tx": s.tx, "since": int(s.connected_at),
        } for s in self.sessions.values()]
        return {
            "version": __version__,
            "uptime": int(time.time() - self.started_at) if self.started_at else 0,
            "fingerprint": self.fingerprint,
            "port": self.cfg["port"],
            "sessions": sessions,
            "usbip": {"available": self.usbip.available, "error": self.usbip.error,
                      "port": self.usbip.port},
            "lan": {"active": self.lan.active, "error": self.lan.error,
                    "mode": self.lan.mode, "subnet": str(self.lan.subnet),
                    "server_ip": self.lan.server_ip, "leases": self.lan.lease_list()},
        }


def deep_merge(base: dict, extra: dict):
    for k, v in extra.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            deep_merge(base[k], v)
        else:
            base[k] = v
