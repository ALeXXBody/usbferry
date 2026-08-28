#!/usr/bin/env python3
"""usbferry loopback test suite.

Runs the real server + client in-process over TLS on 127.0.0.1 with:
  - a dummy TCP server standing in for usbipd (echo, verifies byte fidelity)
  - PipeTap pairs standing in for kernel TAP interfaces (verifies frame relay)
  - a fake UsbipManager device list

Usage: python3 tests/test_loopback.py
"""

import asyncio
import json
import os
import socket
import ssl
import sys
import tempfile

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(TESTS_DIR)
sys.path.insert(0, ROOT)

TMP = tempfile.mkdtemp(prefix="usbferry-test-")
os.environ["USBFERRY_CONFIG_DIR"] = TMP

from usbferry import certutil  # noqa: E402
from usbferry.client import UsbferryClient, SecurityError  # noqa: E402
from usbferry.common import (  # noqa: E402
    CH_CONTROL, FT_CLOSE, FT_CTRL, FT_DATA, FT_OPEN, FT_PING, frame,
    jframe, read_frame, send_frame,
)
from usbferry.server import LanManager, UsbferryServer, UsbipManager  # noqa: E402
from usbferry.tapw import pipe_tap_pair  # noqa: E402

PASS, FAIL = [], []


def check(name: str, cond: bool, extra: str = ""):
    (PASS if cond else FAIL).append(name)
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  [{extra}]" if extra and not cond else ""))
    return cond


# ---------------------------------------------------------------- fake usbip
class FakeUsbip(UsbipManager):
    DEVICES = [
        {"busid": "1-2", "vidpid": "045e:00cb", "desc": "Microsoft Corp. Optical Mouse", "exported": False},
        {"busid": "2-1", "vidpid": "1546:01a8", "desc": "U-Blox AG u-blox 8 GPS", "exported": True},
    ]

    def __init__(self, cfg):
        super().__init__(cfg)
        self.devices = [dict(d) for d in self.DEVICES]
        self.available = True
        self.error = None

    async def start(self):
        pass

    async def list_devices(self):
        return self.devices

    async def bind(self, busid):
        for d in self.devices:
            if d["busid"] == busid:
                d["exported"] = True
                return True, "ok"
        return False, "not found"

    async def unbind(self, busid):
        for d in self.devices:
            if d["busid"] == busid:
                d["exported"] = False
                return True, "ok"
        return False, "not found"

    async def stop(self):
        pass


# ---------------------------------------------------------------- helpers
async def echo_server():
    """Stand-in for usbipd: echoes bytes back."""
    async def handle(r, w):
        try:
            while True:
                data = await r.read(65536)
                if not data:
                    break
                w.write(data)
                await w.drain()
        except (ConnectionResetError, OSError):
            pass
        finally:
            w.close()
    srv = await asyncio.start_server(handle, "127.0.0.1", 0)
    return srv, srv.sockets[0].getsockname()[1]


class RawClient:
    """Minimal raw protocol client for direct wire tests."""

    def __init__(self, token):
        self.token = token

    async def connect(self, port, want=("usbip",), token=None):
        ctx = certutil.client_ssl_context()
        self.r, self.w = await asyncio.open_connection(
            "127.0.0.1", port, ssl=ctx, server_hostname="usbferry")
        hello = {"v": 1, "token": token or self.token, "hostname": "rawtest", "want": list(want)}
        self.w.write(json.dumps(hello).encode() + b"\n")
        await self.w.drain()
        line = await self.r.readline()
        return json.loads(line)

    async def frame(self, *a):
        await send_frame(self.w, *a)

    async def read(self):
        return await read_frame(self.r)

    def close(self):
        self.w.close()


async def http_api(port, path, token, method="GET", body=None):
    r, w = await asyncio.open_connection("127.0.0.1", port)
    req = f"{method} {path} HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer {token}\r\n"
    if body is not None:
        payload = json.dumps(body).encode()
        req += f"Content-Type: application/json\r\nContent-Length: {len(payload)}\r\n\r\n"
        raw = req.encode() + payload
    else:
        raw = (req + "Connection: close\r\n\r\n").encode()
    w.write(raw)
    await w.drain()
    data = b""
    while True:
        chunk = await r.read(65536)
        if not chunk:
            break
        data += chunk
    w.close()
    head, _, bodyout = data.partition(b"\r\n\r\n")
    code = int(head.split(b" ")[1])
    return code, bodyout


# ---------------------------------------------------------------- main
async def main():
    print(f"\nusbferry loopback tests (tmp dir {TMP})\n")

    # infrastructure ------------------------------------------------------
    echo_srv, echo_port = await echo_server()
    server_tap, test_server_side = pipe_tap_pair()

    cfg = {
        "bind": "127.0.0.1", "port": 0,
        "web": {"bind": "127.0.0.1", "port": 0},
        "usbip": {"host": "127.0.0.1", "port": echo_port, "start_daemon": False, "firewall": False},
        "lan": {"enabled": True, "mode": "nat", "subnet": "10.77.0.0/24", "configure": False},
        "tokens": [],
    }
    usbip = FakeUsbip(cfg["usbip"])
    lan = LanManager(cfg["lan"], os.path.join(TMP, "state.json"), tap_factory=lambda: server_tap)
    srv = UsbferryServer(os.path.join(TMP, "server.json"), usbip_manager=usbip, lan_manager=lan)
    srv.cfg = json.loads(json.dumps(cfg))  # force test config
    srv.cfg["tokens"] = []
    token = srv.add_token("testclient")
    await srv.start()
    port = srv._srv.sockets[0].getsockname()[1]
    web_port = srv.webui._srv.sockets[0].getsockname()[1]
    print(f"server up: tunnel :{port}  web :{web_port}  fake-usbip :{echo_port}\n")

    # 1. auth --------------------------------------------------------------
    print("[auth]")
    raw = RawClient(token)
    bad = RawClient("uf_wrongtoken")
    w1 = await bad.connect(port, want=[])
    check("bad token rejected", w1.get("ok") is False and w1.get("error") == "invalid token")
    bad.close()
    w2 = await raw.connect(port, want=["lan"])
    check("good token accepted", w2.get("ok") is True)
    check("usbip advertised", w2.get("usbip") is True)
    check("lan ip assigned", w2.get("lan", {}).get("ip", "").startswith("10.77.0."), str(w2.get("lan")))

    # 2. keepalive ---------------------------------------------------------
    await raw.frame(FT_PING, CH_CONTROL)
    ft, ch, _ = await raw.read()
    check("ping -> pong", ft == 0x05, f"got {ft}")

    # 3. control: usb.list ---------------------------------------------------
    rid = 7
    await raw.frame(FT_CTRL, CH_CONTROL, json.dumps({"id": rid, "cmd": "usb.list"}).encode())
    ft, ch, payload = await raw.read()
    obj = json.loads(payload)
    devs = obj.get("data", {}).get("devices", [])
    check("ctrl usb.list", ft == FT_CTRL and obj.get("id") == rid and len(devs) == 2)

    # 4. usbip channel byte fidelity ---------------------------------------
    await raw.frame(FT_OPEN, 100, b'{"type":"usbip"}')
    blob = bytes(range(256)) * 41  # 10496 bytes
    await raw.frame(FT_DATA, 100, blob)
    got = b""
    while len(got) < len(blob):
        ft, ch, payload = await raw.read()
        if ft == FT_DATA and ch == 100:
            got += payload
    check("usbip channel echoes 10KiB intact", got == blob)
    await raw.frame(FT_CLOSE, 100)
    raw.close()
    await asyncio.sleep(0.2)
    check("no sessions left after disconnect", len(srv.sessions) == 0)

    # 5. fingerprint pinning -------------------------------------------------
    print("[client]")
    state_path = os.path.join(TMP, "client.json")
    c = UsbferryClient("127.0.0.1", port, token, trust=False,
                       fingerprint="ab" * 32, forward_port=0, state_path=state_path)
    try:
        await asyncio.wait_for(c.run(), timeout=5)
        check("wrong fingerprint rejected", False)
    except SecurityError:
        check("wrong fingerprint rejected", True)
    except Exception as e:
        check("wrong fingerprint rejected", False, repr(e))

    c = UsbferryClient("127.0.0.1", port, token, trust=True, forward_port=0,
                       state_path=state_path)
    task = asyncio.create_task(c.run())
    await asyncio.sleep(0.5)
    stored = json.load(open(state_path))
    fp_ok = False
    for k, v in stored.get("servers", {}).items():
        fp_ok = fp_ok or v.get("fingerprint") == srv.fingerprint
    check("TOFU stores correct fingerprint", fp_ok)
    task.cancel()

    # 5b. on_ready + ctrl_request must not deadlock (regression: list-usb CLI
    # used to wait forever because the frame loop wasn't running yet)
    result = {}

    async def on_ready(cli: UsbferryClient):
        reply = await cli.ctrl_request("usb.list", timeout=5)
        result["devices"] = len(reply.get("data", {}).get("devices", []))
        cli.writer.close()

    c_rb = UsbferryClient("127.0.0.1", port, token, want_usb=False, want_lan=False,
                          trust=True, forward_port=0,
                          state_path=os.path.join(TMP, "rb.json"), on_ready=on_ready)
    try:
        await asyncio.wait_for(c_rb.run(), timeout=10)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError):
        pass
    check("on_ready ctrl_request does not deadlock", result.get("devices") == 2,
          str(result))

    # 6. client usb forward --------------------------------------------------
    fwd_port = 0
    c2 = UsbferryClient("127.0.0.1", port, token, forward_port=fwd_port,
                        state_path=state_path, want_usb=True, want_lan=False)
    t2 = asyncio.create_task(c2.run())
    await asyncio.sleep(0.5)
    fwd_actual = c2._fwd_srv.sockets[0].getsockname()[1]
    check("local usbip forward listening", fwd_actual > 0)

    rr, ww = await asyncio.open_connection("127.0.0.1", fwd_actual)
    payload = os.urandom(5000)
    ww.write(payload)
    await ww.drain()
    echoed = await rr.readexactly(len(payload))
    check("usb forward roundtrip via UsbferryClient", echoed == payload)
    ww.close()

    # 7. ctrl via client class ------------------------------------------------
    rep = await c2.ctrl_request("usb.list")
    check("client ctrl_request usb.list", rep.get("ok") and len(rep["data"]["devices"]) == 2)

    # 8. LAN relay both directions --------------------------------------------
    client_tap, test_client_side = pipe_tap_pair()
    c3 = UsbferryClient("127.0.0.1", port, token, forward_port=0,
                        state_path=os.path.join(TMP, "c3.json"),
                        want_usb=False, want_lan=True, trust=True,
                        tap_factory=lambda: client_tap)
    t3 = asyncio.create_task(c3.run())
    await asyncio.sleep(0.6)
    check("client got lan lease", c3.tap_ip and c3.tap_ip.startswith("10.77.0."), str(c3.tap_ip))

    frame_up = b"\xff" * 6 + b"\x02" * 6 + b"\x08\x00" + os.urandom(60)
    await test_client_side.write_frame(frame_up)          # client host -> client tap
    got_up = await asyncio.wait_for(test_server_side.read_frame(), 3)  # server side of server tap
    check("lan frame client -> server", got_up == frame_up)

    frame_down = b"\xff" * 6 + b"\x03" * 6 + b"\x08\x00" + os.urandom(60)
    await test_server_side.write_frame(frame_down)        # server tap -> broadcast
    got_down = await asyncio.wait_for(test_client_side.read_frame(), 3)
    check("lan frame server -> client", got_down == frame_down)

    # 9. web API ----------------------------------------------------------------
    print("[web ui]")
    code, body = await http_api(web_port, "/api/status", token)
    check("GET /api/status", code == 200 and json.loads(body)["version"], f"{code} {body[:80]}")
    code, body = await http_api(web_port, "/api/status", "uf_nothing")
    check("web rejects bad token", code == 401)
    code, body = await http_api(web_port, "/api/usb", token)
    check("GET /api/usb", code == 200 and len(json.loads(body)["devices"]) == 2)
    code, body = await http_api(web_port, "/api/usb/bind", token, "POST", {"busid": "1-2"})
    ok = json.loads(body)
    check("POST /api/usb/bind", code == 200 and ok["ok"] and usbip.devices[0]["exported"])
    code, body = await http_api(web_port, "/", token, "GET")
    check("GET / serves index.html", code == 200 and b"usbferry" in body[:20000])

    # shutdown -------------------------------------------------------------------
    for t in (t2, t3):
        t.cancel()
    await asyncio.sleep(0.3)
    echo_srv.close()
    await srv.stop()

    print(f"\n{'='*46}\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("failed:", ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
