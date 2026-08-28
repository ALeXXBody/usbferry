"""Shared protocol framing, config helpers, and utilities.

Wire protocol (after TLS handshake):
  1. Client sends one JSON line (hello):   {"v":1,"token":"...","hostname":"...","want":["usbip","lan"]}
  2. Server replies one JSON line:         {"ok":true,"server":"...","usbip":true,"lan":{...}} or {"ok":false,"error":"..."}
  3. Then binary frames:

  Frame header (6 bytes, big-endian): >BBI  = frame_type, channel, payload_len

  frame types:
    0x01 DATA   payload = stream bytes (usbip channel) or one ethernet frame (lan channel)
    0x02 OPEN   payload = {"type": "usbip" | "lan"}   channel id chosen by opener
    0x03 CLOSE  channel teardown; payload may be json {"reason": "..."}
    0x04 PING   keepalive (payload ignored)
    0x05 PONG   keepalive reply
    0x06 CTRL   channel 0 only; payload = json {"id":n,"cmd":"..."} -> {"id":n,"ok":bool,"data":...}

  channel 0 is reserved for control. Each TCP connection to the local usbip
  forward port gets its own "usbip" channel; there is at most one "lan" channel
  per session.
"""

import asyncio
import hashlib
import hmac
import json
import logging
import os
import secrets
import struct
import sys
import time

log = logging.getLogger("netshare")

DEFAULT_PORT = 7575
DEFAULT_WEB_PORT = 7580
USBIP_PORT = 3240

FT_DATA = 0x01
FT_OPEN = 0x02
FT_CLOSE = 0x03
FT_PING = 0x04
FT_PONG = 0x05
FT_CTRL = 0x06

CH_CONTROL = 0

MAX_FRAME = 70000  # jumbo ethernet frame headroom
MAX_HELLO = 4096

_H = struct.Struct(">BBI")


class ProtocolError(Exception):
    pass


def frame(ftype: int, ch: int, payload: bytes = b"") -> bytes:
    if len(payload) > MAX_FRAME:
        raise ProtocolError("frame too large")
    return _H.pack(ftype, ch, len(payload)) + payload


async def read_frame(reader: asyncio.StreamReader):
    hdr = await reader.readexactly(_H.size)
    ftype, ch, ln = _H.unpack(hdr)
    if ln > MAX_FRAME:
        raise ProtocolError(f"frame length {ln} exceeds max")
    payload = await reader.readexactly(ln) if ln else b""
    return ftype, ch, payload


async def send_frame(writer: asyncio.StreamWriter, ftype: int, ch: int, payload: bytes = b"") -> None:
    writer.write(frame(ftype, ch, payload))
    await writer.drain()


def jframe(ftype: int, ch: int, obj) -> bytes:
    return frame(ftype, ch, json.dumps(obj).encode())


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_token() -> str:
    return "ns_" + secrets.token_urlsafe(24)


def constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def config_dir() -> str:
    base = os.environ.get("NETSHARE_CONFIG_DIR")
    if base:
        return base
    return os.path.join(os.path.expanduser("~"), ".config", "netshare")


def load_json(path: str, default):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def save_json(path: str, data) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=2)


async def run(cmd, timeout: float = 15.0):
    """Run a command, return (rc, stdout, stderr) as text. Never raises."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except (FileNotFoundError, PermissionError, OSError) as e:
        return 127, "", str(e)
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        return 124, "", "timeout"
    return proc.returncode, out.decode(errors="replace"), err.decode(errors="replace")


def which(name: str) -> str | None:
    from shutil import which as _w
    return _w(name)


def human_bytes(n: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PiB"


def is_elevated() -> bool:
    """True when running with admin/root rights (usbip bind needs this)."""
    if os.name != "nt":
        return getattr(os, "geteuid", lambda: 0)() == 0
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def setup_logging(verbose: bool = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


# ---------------------------------------------------------------- crash UX
# A double-clicked frozen exe closes its console on crash, swallowing the
# traceback. These helpers make failures visible instead.

_console_hidden = False


def write_crash_log(text: str) -> str | None:
    """Append a crash report to <config>/netshare-crash.log; return the path."""
    try:
        path = os.path.join(config_dir(), "netshare-crash.log")
        os.makedirs(config_dir(), exist_ok=True)
        with open(path, "a") as f:
            f.write(f"\n===== {time.strftime('%Y-%m-%d %H:%M:%S')} "
                    f"netshare {os.environ.get('NETSHARE_VERSION', '')} =====\n{text}\n")
        return path
    except OSError:
        return None


def message_box(text: str, title: str = "netshare") -> None:
    """Show a native error dialog on Windows (no-op elsewhere)."""
    if os.name != "nt":
        return
    try:
        import ctypes
        MB_ICONERROR, MB_SETFOREGROUND = 0x10, 0x10000
        ctypes.windll.user32.MessageBoxW(None, text, title, MB_ICONERROR | MB_SETFOREGROUND)
    except Exception:
        pass


def hide_console() -> bool:
    """Hide our launcher console when we own it (double-click launch).

    If the console belongs to a terminal the user is typing in, do nothing.
    Returns True if a console we own was hidden.
    """
    global _console_hidden
    if os.name != "nt":
        return False
    try:
        import ctypes
        from ctypes import wintypes
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if not hwnd:
            return False
        pid = wintypes.DWORD()
        ctypes.windll.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if pid.value != os.getpid():
            return False  # user's own terminal window
        ctypes.windll.user32.ShowWindow(hwnd, 0)  # SW_HIDE
        _console_hidden = True
        return True
    except Exception:
        return False


def show_console() -> None:
    """Re-show a console window that hide_console() hid."""
    global _console_hidden
    if os.name != "nt" or not _console_hidden:
        return
    _console_hidden = False
    try:
        import ctypes
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 5)  # SW_SHOW
    except Exception:
        pass


def pause_interactive() -> None:
    """Keep a double-clicked console window open so output stays readable."""
    try:
        if sys.stdin is not None and sys.stdin.isatty():
            input("\nPress Enter to close...")
    except (EOFError, KeyboardInterrupt):
        pass
