"""usbferry client: TLS tunnel, local usbip port-forward, TAP-based LAN, attach automation."""

import asyncio
import json
import os
import platform
import re
import socket
import sys
import time

from . import certutil
from .common import (
    CH_CONTROL, DEFAULT_PORT, FT_CLOSE, FT_CTRL, FT_DATA, FT_OPEN, FT_PING,
    FT_PONG, config_dir, load_json, log, read_frame, run,
    save_json, send_frame, which,
)
from .tapw import KernelTap, TapClosed, TapError, WinTap

LAN_CH = 1
USB_CH_BASE = 100


class ClientError(Exception):
    pass


class SecurityError(ClientError):
    fingerprint: str | None = None


class UsbipChannelConn:
    """One forwarded TCP connection: local socket <-> tunnel usbip channel."""

    def __init__(self, ch, reader, writer):
        self.ch = ch
        self.reader = reader
        self.writer = writer


class UsbferryClient:
    def __init__(self, host, port=DEFAULT_PORT, token="", *,
                 want_usb=True, want_lan=False, trust=False, fingerprint=None,
                 forward_host="127.0.0.1", forward_port=3240,
                 tap_name="ns0", default_route=False, dns=None,
                 state_path=None, tap_factory=None, on_ready=None):
        self.host = host
        self.port = port
        self.token = token
        self.want_usb = want_usb
        self.want_lan = want_lan
        self.trust = trust
        self.fingerprint = fingerprint
        self.forward_host = forward_host
        self.forward_port = forward_port
        self.tap_name = tap_name
        self.default_route = default_route
        self.dns = dns
        self.state_path = state_path or os.path.join(config_dir(), "client.json")
        self.tap_factory = tap_factory
        self.on_ready = on_ready

        self.reader = None
        self.writer = None
        self.welcome = None
        self.tap = None
        self.tap_ip = None
        self.usb_conns: dict[int, UsbipChannelConn] = {}
        self._next_ch = USB_CH_BASE
        self._fwd_srv = None
        self._tasks: list[asyncio.Task] = []
        self._ctrl_futs: dict[int, asyncio.Future] = {}
        self._ctrl_id = 0
        self._closed = False
        self.ready = asyncio.Event()
        self.rx = 0
        self.tx = 0

    # ----- fingerprint trust ------------------------------------------------
    def _state(self) -> dict:
        return load_json(self.state_path, {"servers": {}})

    def _server_entry(self) -> dict:
        st = self._state()
        return st.get("servers", {}).get(f"{self.host}:{self.port}", {})

    def _pin_fingerprint(self, fp: str) -> None:
        expected = self.fingerprint or self._server_entry().get("fingerprint")
        if expected and expected.lower() != fp.lower():
            raise SecurityError(
                f"TLS certificate fingerprint MISMATCH for {self.host}:{self.port}\n"
                f"  expected: {expected}\n"
                f"  got:      {fp}\n"
                "Possible MITM. If you knowingly changed the server cert, update "
                "~/.config/usbferry/client.json or pass --fingerprint.")
        if not expected:
            if self.trust or (sys.stdin.isatty() and self._ask_trust(fp)):
                st = self._state()
                st.setdefault("servers", {})[f"{self.host}:{self.port}"] = {
                    "fingerprint": fp, "added": time.strftime("%Y-%m-%d %H:%M:%S")}
                save_json(self.state_path, st)
                log.info("pinned server fingerprint %s", fp)
            else:
                err = SecurityError(
                    f"unknown server fingerprint {fp}\n"
                    "Verify it with the server operator, then rerun with --trust "
                    "(or --fingerprint).")
                err.fingerprint = fp
                raise err

    @staticmethod
    def _ask_trust(fp: str) -> bool:
        print(f"\nFirst contact with this server. Certificate SHA-256 fingerprint:\n  {fp}\n")
        try:
            return input("Trust and pin this certificate? [y/N] ").strip().lower() == "y"
        except (EOFError, KeyboardInterrupt):
            return False

    # ----- main -------------------------------------------------------------
    async def run(self):
        await self.connect()
        await self.run_connected()

    async def connect(self):
        """TLS connect, pin fingerprint, authenticate. Raises SecurityError
        (with .fingerprint set) when the cert is unknown and trust was not given."""
        if not self.token:
            raise ClientError("no token given (--token / config)")
        ctx = certutil.client_ssl_context()
        log.info("connecting to %s:%s ...", self.host, self.port)
        self.reader, self.writer = await asyncio.open_connection(
            self.host, self.port, ssl=ctx, server_hostname="usbferry")

        ssl_obj = self.writer.get_extra_info("ssl_object")
        self._pin_fingerprint(certutil.peer_fingerprint(ssl_obj))
        try:
            self.writer.get_extra_info("socket").setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass

        want = []
        if self.want_usb:
            want.append("usbip")
        if self.want_lan:
            want.append("lan")
        hello = {"v": 1, "token": self.token, "hostname": os.uname().nodename if hasattr(os, "uname") else platform.node(),
                 "want": want}
        self.writer.write(json.dumps(hello).encode() + b"\n")
        await self.writer.drain()

        line = await asyncio.wait_for(self.reader.readline(), timeout=15)
        self.welcome = json.loads(line)
        if not self.welcome.get("ok"):
            raise ClientError(f"server rejected us: {self.welcome.get('error', '?')}")

        log.info("connected to %s (usbferry v%s)", self.welcome.get("server", "?"),
                 self.welcome.get("version", "?"))

    async def run_connected(self):
        """Start forwards/LAN/TAP and pump frames until the connection dies."""
        if self.want_lan:
            await self._start_lan()
        if self.want_usb and self.welcome.get("usbip"):
            await self._start_forward()
        elif self.want_usb:
            log.warning("usb sharing unavailable on server: %s", self.welcome.get("usbip"))

        # the frame loop must run while on_ready executes: callbacks like
        # list-usb issue ctrl requests and wait for replies
        loop_task = asyncio.create_task(self._frame_loop())
        self.ready.set()
        try:
            if self.on_ready:
                await self.on_ready(self)
            await loop_task
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass  # connection ended (e.g. on_ready closed it, or server hung up)
        finally:
            loop_task.cancel()
            await self._cleanup()

    # ----- lan --------------------------------------------------------------
    async def _start_lan(self):
        lan = self.welcome.get("lan")
        if not lan:
            log.warning("LAN sharing unavailable on server (disabled or TAP missing)")
            return
        await send_frame(self.writer, FT_OPEN, LAN_CH, b'{"type":"lan"}')

        if self.tap_factory:
            self.tap = self.tap_factory()
        elif os.name == "nt" and WinTap is not None:
            self.tap = WinTap.open()
        else:
            self.tap = await KernelTap.create(self.tap_name)
        self.tap_ip = lan["ip"]

        if isinstance(self.tap, KernelTap):
            prefix = lan["prefix"]
            await run(["ip", "addr", "flush", "dev", self.tap.name])
            await run(["ip", "addr", "add", f"{self.tap_ip}/{prefix}", "dev", self.tap.name])
            await run(["ip", "link", "set", "dev", self.tap.name, "mtu", str(lan.get("mtu", 1500)), "up"])
            if self.default_route:
                await run(["ip", "route", "replace", "default", "via", lan["server_ip"],
                           "dev", self.tap.name, "metric", "50"])
                log.info("default route now via tunnel (%s)", lan["server_ip"])
        elif WinTap is not None and isinstance(self.tap, WinTap):
            # configure the TAP-Windows adapter (netsh: static IP, no gateway;
            # add a default route only with --default-route)
            await run(["netsh", "interface", "ip", "set", "address",
                       f"name={self.tap.name}", "static", self.tap_ip,
                       str(_mask_from_prefix(lan["prefix"]))])
            if self.default_route:
                await run(["netsh", "interface", "ip", "add", "route",
                           "0.0.0.0/0", f"name={self.tap.name}", lan["server_ip"], "metric=50"])

        self._tasks.append(asyncio.create_task(self._tap_pump()))
        log.info("LAN up: %s has %s (server %s, prefix /%s)",
                 getattr(self.tap, "name", "tap"), self.tap_ip,
                 lan["server_ip"], lan["prefix"])

    async def _tap_pump(self):
        try:
            while True:
                data = await self.tap.read_frame()
                self.tx += len(data)
                await send_frame(self.writer, FT_DATA, LAN_CH, data)
        except TapClosed:
            log.warning("local TAP closed")
        except asyncio.CancelledError:
            raise
        except (ConnectionError, OSError, AttributeError):
            log.warning("LAN channel write failed; stopping TAP pump")

    # ----- usb forward ------------------------------------------------------
    async def _start_forward(self):
        self._fwd_srv = await asyncio.start_server(
            self._forward_conn, self.forward_host, self.forward_port)
        log.info("usbip forward ready: %s:%s -> tunnel (attach with: "
                 "usbip attach -r %s -b <busid>)",
                 self.forward_host, self.forward_port, self.forward_host)

    async def _forward_conn(self, reader, writer):
        while self._next_ch in self.usb_conns:
            self._next_ch += 1
        ch = self._next_ch
        self._next_ch += 1
        conn = UsbipChannelConn(ch, reader, writer)
        self.usb_conns[ch] = conn
        await send_frame(self.writer, FT_OPEN, ch, b'{"type":"usbip"}')
        pump = asyncio.create_task(self._conn_pump(conn))
        self._tasks.append(pump)

    async def _conn_pump(self, conn: UsbipChannelConn):
        try:
            while True:
                data = await conn.reader.read(65536)
                if not data:
                    break
                self.tx += len(data)
                await send_frame(self.writer, FT_DATA, conn.ch, data)
        except (ConnectionResetError, asyncio.IncompleteReadError, OSError):
            pass
        finally:
            try:
                await send_frame(self.writer, FT_CLOSE, conn.ch)
            except (asyncio.CancelledError, ConnectionError, OSError, AttributeError):
                pass
            self.usb_conns.pop(conn.ch, None)
            conn.writer.close()

    # ----- frames -----------------------------------------------------------
    async def _frame_loop(self):
        while True:
            ftype, ch, payload = await read_frame(self.reader)
            if ftype == FT_PING:
                await send_frame(self.writer, FT_PONG, ch)
            elif ftype == FT_PONG:
                continue
            elif ftype == FT_CTRL and ch == CH_CONTROL:
                self._ctrl_reply(payload)
            elif ftype == FT_DATA:
                self.rx += len(payload)
                if ch == LAN_CH and self.tap is not None:
                    asyncio.create_task(self._tap_write(payload))
                elif ch in self.usb_conns:
                    self.usb_conns[ch].writer.write(payload)
            elif ftype == FT_CLOSE:
                if ch == LAN_CH:
                    log.warning("server closed LAN channel")
                    if self.tap:
                        self.tap.close()
                        self.tap = None
                elif ch in self.usb_conns:
                    conn = self.usb_conns.pop(ch)
                    conn.writer.close()
            elif ftype == FT_OPEN:
                log.debug("server tried to open channel %d - ignoring", ch)

    async def _tap_write(self, data):
        try:
            await self.tap.write_frame(data)
        except (TapClosed, TapError):
            pass

    def _ctrl_reply(self, payload: bytes):
        try:
            obj = json.loads(payload)
        except json.JSONDecodeError:
            return
        fut = self._ctrl_futs.pop(obj.get("id"), None)
        if fut and not fut.done():
            fut.set_result(obj)

    async def ctrl_request(self, cmd: str, timeout: float = 10.0) -> dict:
        self._ctrl_id += 1
        rid = self._ctrl_id
        fut = asyncio.get_running_loop().create_future()
        self._ctrl_futs[rid] = fut
        await send_frame(self.writer, FT_CTRL, CH_CONTROL,
                         json.dumps({"id": rid, "cmd": cmd}).encode())
        try:
            return await asyncio.wait_for(fut, timeout)
        finally:
            self._ctrl_futs.pop(rid, None)

    # ----- cleanup ----------------------------------------------------------
    async def _cleanup(self):
        if self._closed:
            return
        self._closed = True
        for t in self._tasks:
            if not t.done():
                t.cancel()
        if self._fwd_srv:
            self._fwd_srv.close()
        for conn in list(self.usb_conns.values()):
            conn.writer.close()
        if self.tap:
            self.tap.close()
            if isinstance(self.tap, KernelTap) and self.tap_factory is None:
                await run(["ip", "link", "delete", self.tap.name])
        if self.writer:
            self.writer.close()
        log.info("disconnected (rx=%s tx=%s)", self.rx, self.tx)


def _mask_from_prefix(prefix: int) -> str:
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    return socket.inet_ntoa(mask.to_bytes(4, "big"))


# ---------------------------------------------------------------------------
# usbip attach/detach helpers (Linux usbip / Windows usbip-win2 share syntax)
# ---------------------------------------------------------------------------

def usbip_binary() -> str | None:
    return which("usbip") or which("usbip.exe")


async def usbip_attach(busid: str, remote: str = "127.0.0.1") -> tuple[bool, str]:
    binary = usbip_binary()
    if not binary:
        return False, ("usbip client tool not found. Linux: apt install usbip / linux-tools-$(uname -r). "
                       "Windows: install usbip-win2 (github.com/vadimgrn/usbip-win2).")
    rc, out, err = await run([binary, "attach", "-r", remote, "-b", busid], timeout=30)
    return rc == 0, (out.strip() + " " + err.strip()).strip() or f"exit {rc}"


async def usbip_detach_ours(remote: str = "127.0.0.1") -> list[str]:
    """Detach every vhci port that was attached from `remote`."""
    binary = usbip_binary()
    if not binary:
        return []
    rc, out, _ = await run([binary, "port"], timeout=15)
    if rc != 0:
        return []
    detached = []
    current = None
    for line in out.splitlines():
        m = re.match(r"\s*Port\s+(\d+)", line)
        if m:
            current = int(m.group(1))
            continue
        if current is not None and remote in line:
            rc2, _, _ = await run([binary, "detach", "-p", str(current)], timeout=15)
            if rc2 == 0:
                detached.append(str(current))
            current = None
    return detached
