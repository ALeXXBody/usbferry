#!/usr/bin/env python3
"""GUI backend test: profiles, trust flow, connect, usb list, LAN, detach-all."""

import asyncio
import json
import os
import sys
import tempfile

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(TESTS_DIR)
sys.path.insert(0, ROOT)

TMP = tempfile.mkdtemp(prefix="usbferry-gui-")
os.environ["USBFERRY_CONFIG_DIR"] = TMP

from test_loopback import FakeUsbip, echo_server, http_api  # noqa: E402
from usbferry.client import UsbferryClient  # noqa: E402
from usbferry.gui import GuiApp, run_gui  # noqa: E402
from usbferry.server import LanManager, UsbferryServer  # noqa: E402
from usbferry.tapw import pipe_tap_pair  # noqa: E402

PASS, FAIL = [], []


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  [{extra}]" if extra and not cond else ""))
    return cond


async def gui_api(port, path, method="GET", body=None):
    code, out = await http_api(port, "/api/" + path, "not-needed", method, body)
    return code, json.loads(out)


async def main():
    print(f"\nusbferry GUI tests (tmp {TMP})\n")
    echo_srv, echo_port = await echo_server()
    server_tap, _ = pipe_tap_pair()
    lan = LanManager({"mode": "nat", "subnet": "10.77.0.0/24", "configure": False},
                     os.path.join(TMP, "state.json"), tap_factory=lambda: server_tap)
    srv = UsbferryServer(os.path.join(TMP, "server.json"),
                         usbip_manager=FakeUsbip({"host": "127.0.0.1", "port": echo_port}),
                         lan_manager=lan)
    srv.cfg.update({"bind": "127.0.0.1", "port": 0,
                    "web": {"bind": "127.0.0.1", "port": 0},
                    "usbip": {"host": "127.0.0.1", "port": echo_port,
                              "start_daemon": False, "firewall": False},
                    "tokens": []})
    token = srv.add_token("guitest")
    await srv.start()
    port = srv._srv.sockets[0].getsockname()[1]

    def client_factory(host, port_, token_, want_usb, want_lan, trust, fwd, tap):
        # inject a pipe TAP so this works without /dev/net/tun
        a, _b = pipe_tap_pair()
        return UsbferryClient(host, port_, token_, want_usb=want_usb, want_lan=want_lan,
                              trust=trust, forward_port=fwd, tap_name=tap,
                              tap_factory=lambda: a)

    gui = GuiApp(state_path=os.path.join(TMP, "gui.json"), client_factory=client_factory)
    gui_port = await gui.start()

    print("[profiles]")
    c, r = await gui_api(gui_port, "status")
    check("initial status disconnected", c == 200 and r["status"] == "disconnected")
    c, r = await gui_api(gui_port, "profiles", "POST",
                         {"name": "lab", "host": "127.0.0.1", "port": port,
                          "token": token, "lan": True})
    check("add profile", c == 200 and r.get("ok"))
    c, r = await gui_api(gui_port, "profiles")
    check("list profiles (token hidden)", c == 200 and len(r["profiles"]) == 1
          and "token" not in r["profiles"][0])

    print("[trust flow]")
    c, r = await gui_api(gui_port, "connect", "POST", {"name": "lab"})
    check("first connect -> needs_trust", r["status"] == "needs_trust"
          and r["needed_fingerprint"] == srv.fingerprint, json.dumps(r)[:120])
    c, r = await gui_api(gui_port, "status")
    check("status stays needs_trust until decided", r["status"] == "needs_trust")

    print("[connect]")
    c, r = await gui_api(gui_port, "connect", "POST", {"name": "lab", "trust": True})
    check("trusted connect -> connected", r["status"] == "connected", json.dumps(r)[:160])
    check("welcome info present", r.get("server_name") and r.get("lan", {})
          and r.get("lan_local_ip", "").startswith("10.77.0."))

    print("[usb]")
    c, r = await gui_api(gui_port, "usb")
    check("usb list via tunnel (exported only)",
          c == 200 and r["ok"] and len(r["data"]["devices"]) == 1, str(r))
    c, r = await gui_api(gui_port, "attach", "POST", {"busid": "1-2"})
    check("attach call is graceful without usbip binary",
          c == 200 and r["ok"] is False and "usbip" in r.get("message", ""), str(r))
    c, r = await gui_api(gui_port, "detach", "POST")
    check("detach call is graceful", c == 200)

    print("[disconnect]")
    c, r = await gui_api(gui_port, "disconnect", "POST")
    check("disconnect -> disconnected", r["status"] == "disconnected")

    c, r = await gui_api(gui_port, "connect", "POST", {"name": "nope"})
    check("unknown profile -> error state", r["status"] == "error" and "no profile" in r["error"])

    code, body = await http_api(gui_port, "/", "x")
    check("GET / serves app.html", code == 200 and b"USB &amp; LAN" in body)

    await gui.stop()
    echo_srv.close()
    await srv.stop()

    # [webview crash -> browser fallback] — simulates the reported Windows bug:
    # pywebview import works but start() raises (e.g. WebView2 runtime missing).
    print("[webview crash fallback]")
    import contextlib
    import io
    import threading as _threading
    import types as _types
    import webbrowser as _wb

    class _Stop(Exception):
        pass

    opened = {}

    def _fake_open(u, *a, **k):
        opened["url"] = u
        return True

    def _wait_raises(timeout=None):
        raise _Stop()

    def _start_boom(*a, **k):
        raise RuntimeError("simulated WebView2 failure")

    fake_wv = _types.ModuleType("webview")
    fake_wv.create_window = lambda *a, **k: None
    fake_wv.start = _start_boom
    orig_open = _wb.open
    _wb.open = _fake_open
    sys.modules["webview"] = fake_wv
    buf = io.StringIO()
    result = {}

    def _runner():
        try:
            with contextlib.redirect_stdout(buf):
                run_gui(_wait=_wait_raises)
            result["ended"] = "returned"
        except _Stop:
            result["ended"] = "stopped-in-fallback"
        except BaseException as e:  # noqa: BLE001
            result["ended"] = f"crashed: {e!r}"

    t = _threading.Thread(target=_runner)
    t.start()
    t.join(timeout=10)
    _wb.open = orig_open
    sys.modules.pop("webview", None)
    out = buf.getvalue()
    check("webview.start() crash -> browser fallback, process survives",
          result.get("ended") == "stopped-in-fallback"
          and "127.0.0.1" in opened.get("url", "")
          and "unavailable" in out,
          f"ended={result.get('ended')} url={opened.get('url')} out={out[:100]!r}")
    check("fallback explains what happened", "simulated WebView2 failure" in out)

    print(f"\n{'='*46}\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("failed:", ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
