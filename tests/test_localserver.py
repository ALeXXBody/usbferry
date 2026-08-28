#!/usr/bin/env python3
"""Local server (GUI-embedded) tests + WindowsUsbipManager parser tests."""

import asyncio
import json
import os
import socket
import sys
import tempfile

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(TESTS_DIR)
sys.path.insert(0, ROOT)

TMP = tempfile.mkdtemp(prefix="netshare-ls-")
os.environ["NETSHARE_CONFIG_DIR"] = TMP

from test_loopback import FakeUsbip, http_api  # noqa: E402  (may reset NETSHARE_CONFIG_DIR)
os.environ["NETSHARE_CONFIG_DIR"] = TMP  # reclaim after test_loopback's module-level side effect

from netshare.gui import GuiApp  # noqa: E402
from netshare.server import LanManager, WindowsUsbipManager  # noqa: E402

PASS, FAIL = [], []


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  [{extra}]" if extra and not cond else ""))
    return cond


# --------------------------------------------------------------- parser
USBIPD_V4 = """
Connected:
BUSID  DEVICE                                                      STATE
1-1    Microsoft Corp. NetMD                                       Not shared
1-3    Silicon Labs CP210x USB to UART Bridge (COM3)              Shared
2-2    Intel Corp. Integrated Camera                              Attached (desktop-abc)
3-1    Generic Ultra Fast Media Reader  (090c:637b)               Shared (read-only)

Persisted:
GUID                                  DEVICE
7a6b3c8e-1f2d-4e5f-9a8b-              unknown
""".strip()

USBIPD_V2 = """
 - 192.168.1.9
        3-2: unknown vendor : unknown product (1005:b113)
           : /sys/devices/pci0000:00/0000:00:14.0/usb3/3-2
           : (Defined at Interface level) (00/00/00)
""".strip()


def test_parser():
    print("[usbipd-win parser]")
    devs = WindowsUsbipManager.parse_list(USBIPD_V4)
    check("v4: finds 4 devices", len(devs) == 4, str(devs))
    by_id = {d["busid"]: d for d in devs}
    check("v4: not shared -> private", by_id.get("1-1", {}).get("exported") is False)
    check("v4: shared -> exported", by_id.get("1-3", {}).get("exported") is True)
    check("v4: read-only shared -> exported", by_id.get("3-1", {}).get("exported") is True)
    check("v4: attached not exported", by_id.get("2-2", {}).get("exported") is False)
    check("v4: vidpid extracted", by_id.get("3-1", {}).get("vidpid") == "090c:637b")
    check("v4: desc without state", "CP210x" in by_id.get("1-3", {}).get("desc", ""))
    check("v4: persisted GUID ignored", all(d["busid"] != "7a6b3c8e-1f2d-4e5f-9a8b-" for d in devs))

    devs2 = WindowsUsbipManager.parse_list(USBIPD_V2)
    check("v2-style: one device", len(devs2) == 1, str(devs2))
    if devs2:
        check("v2-style: fields", devs2[0]["busid"] == "3-2"
              and devs2[0]["vidpid"] == "1005:b113")


# --------------------------------------------------------------- local server
async def gui_api(port, path, method="GET", body=None):
    code, out = await http_api(port, "/api/" + path, "x", method, body)
    return code, json.loads(out)


async def test_local_server():
    print("[GUI local server]")
    # pick free ports dynamically (immune to leftover listeners)
    def free_port():
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        p = s.getsockname()[1]
        s.close()
        return p
    srv_port, web_port = free_port(), free_port()

    lan = LanManager({"mode": "nat", "subnet": "10.77.0.0/24", "configure": False},
                     os.path.join(TMP, "state.json"),
                     tap_factory=None)
    gui = GuiApp(state_path=os.path.join(TMP, "gui.json"),
                 usbip_factory=lambda: FakeUsbip({"host": "127.0.0.1", "port": 3240}),
                 lan_manager=lan)
    gui_port = await gui.start()
    try:
        c, r = await gui_api(gui_port, "local-server")
        check("initial: not running", c == 200 and r["running"] is False)

        c, r = await gui_api(gui_port, "local-server/start", "POST",
                             {"port": srv_port, "web_port": web_port, "lan": False})
        check("start ok", c == 200 and r.get("ok") is True, str(r))

        c, r = await gui_api(gui_port, "local-server")
        check("status running with ports", r.get("running") and r.get("port") == srv_port
              and r.get("web_port") == web_port, str(r))
        check("usbip backend active", r.get("usbip", {}).get("available") is True)
        check("fingerprint present", len(r.get("fingerprint", "")) == 64)

        # token round-trip: create via GUI API, authenticate against the tunnel
        c, r = await gui_api(gui_port, "local-server/token", "POST", {"name": "laptop"})
        check("token created", c == 200 and r.get("token", "").startswith("ns_"), str(r))
        token = r.get("token", "")

        from netshare import certutil
        ctx = certutil.client_ssl_context()
        r2, w2 = await asyncio.open_connection("127.0.0.1", srv_port, ssl=ctx,
                                               server_hostname="netshare")
        w2.write(json.dumps({"v": 1, "token": token, "hostname": "gui-test",
                             "want": []}).encode() + b"\n")
        await w2.drain()
        line = await asyncio.wait_for(r2.readline(), 5)
        hello = json.loads(line)
        check("GUI-issued token authenticates on the tunnel",
              hello.get("ok") is True, str(hello))
        w2.close()

        # persisted for the CLI server too
        cfg = json.load(open(os.path.join(TMP, "server.json")))
        names = [t["name"] for t in cfg.get("tokens", [])]
        check("token persisted to server.json", "laptop" in names)

        c, r = await gui_api(gui_port, "local-server/usb")
        devs = (r.get("data") or {}).get("devices", [])
        check("usb list via GUI", c == 200 and r.get("ok") and len(devs) == 2)

        c, r = await gui_api(gui_port, "local-server/usb/bind", "POST", {"busid": "1-2"})
        check("bind via GUI", c == 200 and r.get("ok"))
        c, r = await gui_api(gui_port, "local-server/usb")
        devs = (r.get("data") or {}).get("devices", [])
        check("bind took effect", next(d["exported"] for d in devs if d["busid"] == "1-2"))

        c, r = await gui_api(gui_port, "local-server/start", "POST", {"port": srv_port})
        check("double start rejected", r.get("ok") is False)

        c, r = await gui_api(gui_port, "local-server/stop", "POST")
        check("stop ok", r.get("ok") is True)
        c, r = await gui_api(gui_port, "local-server")
        check("stopped", r.get("running") is False)
    finally:
        await gui.stop()  # also stops any local server, freeing its ports


async def main():
    print(f"\nnetshare local-server tests (tmp {TMP})\n")
    test_parser()
    await test_local_server()
    print(f"\n{'='*46}\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("failed:", ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
