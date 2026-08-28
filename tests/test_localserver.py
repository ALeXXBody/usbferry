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

TMP = tempfile.mkdtemp(prefix="usbferry-ls-")
os.environ["USBFERRY_CONFIG_DIR"] = TMP

from test_loopback import FakeUsbip, http_api  # noqa: E402  (may reset USBFERRY_CONFIG_DIR)
os.environ["USBFERRY_CONFIG_DIR"] = TMP  # reclaim after test_loopback's module-level side effect

from usbferry.gui import GuiApp  # noqa: E402
from usbferry.server import LanManager, WindowsUsbipManager  # noqa: E402

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


SC_RUNNING = """
SERVICE_NAME: usbipd
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
""".strip()

SC_STOPPED = """
SERVICE_NAME: usbipd
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 1  STOPPED
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

    print("[sc query parser]")
    q = WindowsUsbipManager.parse_service_query
    check("sc: running", q(0, SC_RUNNING) == "running")
    check("sc: stopped", q(0, SC_STOPPED) == "stopped")
    check("sc: missing (1060)", q(1060, "The specified service does not exist...") == "missing")
    check("sc: unknown", q(0, "garbage") == "unknown")


GITHUB_RELEASE = {
    "tag_name": "v4.3.0",
    "assets": [
        {"name": "usbipd-win_4.3.0.arm64.zip", "size": 12345,
         "browser_download_url": "https://x/arm64.zip"},
        {"name": "usbipd-win_4.3.0.x64.msi", "size": 5432109,
         "browser_download_url": "https://x/usbipd-win_4.3.0.x64.msi"},
        {"name": "usbipd-win_4.3.0.x64.zip", "size": 999,
         "browser_download_url": "https://x/x64.zip"},
    ],
}


def test_msi_picker():
    print("[msi asset picker]")
    from usbferry.winsetup import pick_msi_asset
    name, url, size = pick_msi_asset(GITHUB_RELEASE)
    check("picks the .msi (not zips)", name == "usbipd-win_4.3.0.x64.msi" and url.endswith(".msi"))
    check("size parsed", size == 5432109)
    try:
        pick_msi_asset({"assets": [{"name": "a.zip", "browser_download_url": "u"}]})
        check("no-msi release raises", False)
    except ValueError:
        check("no-msi release raises", True)


# --------------------------------------------------------------- local server
async def gui_api(port, path, method="GET", body=None):
    code, out = await http_api(port, "/api/" + path, "x", method, body)
    return code, json.loads(out)


async def _auth_ok(srv_port: int, token: str) -> bool:
    """Authenticate against the tunnel at srv_port with token; True if accepted."""
    from usbferry import certutil
    ctx = certutil.client_ssl_context()
    r2, w2 = await asyncio.open_connection("127.0.0.1", srv_port, ssl=ctx,
                                           server_hostname="usbferry")
    w2.write(json.dumps({"v": 1, "token": token, "hostname": "t",
                         "want": []}).encode() + b"\n")
    await w2.drain()
    line = await asyncio.wait_for(r2.readline(), 5)
    w2.close()
    return json.loads(line).get("ok") is True


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
        auto = r.get("auto_token") or {}
        check("auto token generated on first start",
              auto.get("token", "").startswith("uf_") and bool(auto.get("name")),
              str(r))
        auto_token = auto.get("token", "")
        check("auto token authenticates on the tunnel",
              (await _auth_ok(srv_port, auto_token)), "auth failed")

        c, r = await gui_api(gui_port, "local-server")
        check("status running with ports", r.get("running") and r.get("port") == srv_port
              and r.get("web_port") == web_port, str(r))
        check("usbip backend active", r.get("usbip", {}).get("available") is True)
        check("fingerprint present", len(r.get("fingerprint", "")) == 64)
        check("tokens listed in status", len(r.get("tokens", [])) == 1, str(r.get("tokens")))

        # token round-trip: create via GUI API, authenticate against the tunnel
        c, r = await gui_api(gui_port, "local-server/token", "POST", {"name": "laptop"})
        check("token created", c == 200 and r.get("token", "").startswith("uf_"), str(r))
        token = r.get("token", "")

        from usbferry import certutil
        ctx = certutil.client_ssl_context()
        r2, w2 = await asyncio.open_connection("127.0.0.1", srv_port, ssl=ctx,
                                               server_hostname="usbferry")
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

        # show-again route returns the token created this session
        c, r = await gui_api(gui_port, "local-server/token/last")
        check("token/last re-shows session token",
              r.get("ok") and r.get("token", "").startswith("uf_"), str(r))

        c, r = await gui_api(gui_port, "local-server/usb")
        devs = (r.get("data") or {}).get("devices", [])
        check("usb list via GUI", c == 200 and r.get("ok") and len(devs) == 2)

        c, r = await gui_api(gui_port, "local-server/usb/bind", "POST", {"busid": "1-2"})
        check("bind via GUI", c == 200 and r.get("ok"))
        c, r = await gui_api(gui_port, "local-server/usb")
        devs = (r.get("data") or {}).get("devices", [])
        check("bind took effect", next(d["exported"] for d in devs if d["busid"] == "1-2"))

        # retry route: simulate usbip being down, then recovered by retry
        gui.local_server.usbip.available = False
        gui.local_server.usbip.error = "service stopped (simulated)"
        c, r = await gui_api(gui_port, "local-server/usb/retry", "POST")
        check("usb retry returns ok", c == 200 and r.get("ok") is True, str(r))
        st = await gui_api(gui_port, "status")
        check("usb available again after retry",
              st[1]["local_server"]["usbip"]["available"] is True)

        # one-click install: faked download/install; verifies the state machine
        # and that the service comes up afterwards
        from usbferry import winsetup
        seen_progress = []

        async def fake_latest():
            return "usbipd-win_9.9.9.x64.msi", "http://vendor/usbipd.msi", 5432109

        async def fake_download(url, dest, progress=None):
            for p in (25, 60, 100):
                if progress:
                    progress(p)
                    seen_progress.append(p)

        async def fake_install(path):
            return True, "installed"

        orig = (winsetup.latest_msi, winsetup.download, winsetup.install_msi_elevated)
        winsetup.latest_msi = fake_latest
        winsetup.download = fake_download
        winsetup.install_msi_elevated = fake_install
        try:
            gui.is_windows = True  # route guard is a test seam
            gui.local_server.usbip.available = False
            gui.local_server.usbip.error = "usbipd-win is not installed (simulated)"
            c, r = await gui_api(gui_port, "local-server/usb/install", "POST")
            check("install kicked off", c == 200 and r.get("ok") is True, str(r))
            for _ in range(50):
                st = await gui_api(gui_port, "status")
                if st[1]["usbip_install"]["state"] in ("done", "error"):
                    break
                await asyncio.sleep(0.1)
            inst = st[1]["usbip_install"]
            check("install reaches done", inst["state"] == "done", str(inst))
            check("progress reported during download", seen_progress[-1] == 100)
            check("service available after install",
                  st[1]["local_server"]["usbip"]["available"] is True)
            c, r = await gui_api(gui_port, "local-server/usb/install", "POST")
            check("install not duplicated while done", c == 200 and r.get("ok") is True)
        finally:
            winsetup.latest_msi, winsetup.download, winsetup.install_msi_elevated = orig
            gui.is_windows = os.name == "nt"

        # non-Windows guard
        gui2 = GuiApp(state_path=os.path.join(TMP, "gui2.json"))
        p2 = await gui2.start()
        try:
            gui2.is_windows = False
            c, r = await gui_api(p2, "local-server/usb/install", "POST")
            check("install refused off-Windows",
                  c == 400 and "only" in r.get("error", ""), str(r))
        finally:
            await gui2.stop()

        c, r = await gui_api(gui_port, "local-server/start", "POST", {"port": srv_port})
        check("double start rejected", r.get("ok") is False)

        c, r = await gui_api(gui_port, "local-server/stop", "POST")
        check("stop ok", r.get("ok") is True)
        c, r = await gui_api(gui_port, "local-server")
        check("stopped", r.get("running") is False)
    finally:
        await gui.stop()  # also stops any local server, freeing its ports


async def test_running_service_token_reload():
    """Deployed scenario: service is running; add-token CLI (a separate
    NetshareServer instance) writes a new token to disk; the running service
    must accept it without a restart."""
    print("[token hot-reload]")
    from usbferry.server import UsbferryServer

    cfg_path = os.path.join(TMP, "server2.json")
    running = UsbferryServer(cfg_path)  # starts empty, like a fresh install
    running.cfg["tokens"] = []
    # separate instance == the add-token CLI process
    cli_side = UsbferryServer(cfg_path)
    cli_side.cfg["tokens"] = []
    token = cli_side.add_token("late-token")  # writes to disk only

    check("new token accepted without restart",
          running.verify_token(token) == "late-token")
    check("wrong token still rejected", running.verify_token("uf_bogus") is None)
    # removal propagates too
    cli_side.remove_token("late-token")
    check("removal propagates", running.verify_token(token) is None)


async def test_no_window_subprocesses():
    """Regression: on Windows every subprocess of the windowed exe must be
    spawned with CREATE_NO_WINDOW, or each usbipd list/sc query poll flashes
    a console window."""
    print("[subprocess windows]")
    import asyncio as aio
    from usbferry import common

    captured = []
    orig = aio.create_subprocess_exec

    async def fake_exec(*cmd, **kwargs):
        captured.append(kwargs)

        class P:
            returncode = 0

            async def communicate(self):
                return b"", b""
        return P()

    aio.create_subprocess_exec = fake_exec
    try:
        await common.run(["echo", "hi"])
    finally:
        aio.create_subprocess_exec = orig
    if os.name == "nt":
        check("run() passes CREATE_NO_WINDOW on Windows",
              captured and captured[0].get("creationflags") == common.CREATE_NO_WINDOW,
              str(captured))
    else:
        check("run() passes no creationflags on posix",
              captured and "creationflags" not in captured[0], str(captured))

    # certutil openssl path
    import subprocess as sp
    orig_call = sp.call
    cc = {}

    def fake_call(cmd, **kwargs):
        cc.update(kwargs)
        return 1  # pretend openssl failed -> caller falls back

    sp.call = fake_call
    try:
        from usbferry import certutil
        try:
            certutil._generate_openssl("x.crt", "x.key")
        except RuntimeError:
            pass  # fake openssl "failed"; we only care about the kwargs
    finally:
        sp.call = orig_call
    if os.name == "nt":
        check("certutil passes CREATE_NO_WINDOW on Windows",
              cc.get("creationflags") == common.CREATE_NO_WINDOW, str(cc))
    else:
        check("certutil passes no creationflags on posix",
              "creationflags" not in cc, str(cc))

    # server.py usbipd daemon spawn path
    src = open(os.path.join(ROOT, "usbferry", "server.py")).read()
    check("server daemon spawn uses the flag",
          "CREATE_NO_WINDOW" in src and "creationflags" in src)


async def main():
    print(f"\nusbferry local-server tests (tmp {TMP})\n")
    test_parser()
    test_msi_picker()
    await test_no_window_subprocesses()
    await test_local_server()
    await test_running_service_token_reload()
    print(f"\n{'='*46}\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("failed:", ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
