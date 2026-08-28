"""netshare desktop GUI.

Backend: a local (127.0.0.1) HTTP API managing server profiles, the tunnel
connection, usbip attach/detach and LAN. Frontend: web/app.html rendered in a
native window via pywebview when available (Edge WebView2 / WebKit), otherwise
the default browser. Run with:  python3 -m netshare gui   (or netshare.exe)
"""

import asyncio
import json
import os
import sys
import threading
import time
import webbrowser
from collections import deque

from . import __version__
from .client import NetshareClient, SecurityError, usbip_attach, usbip_detach_ours
from .common import human_bytes, load_json, log, save_json
from .httpd import parse_request, respond

APP_CANDIDATES = [
    os.path.join(getattr(sys, "_MEIPASS", ""), "web", "app.html"),
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web", "app.html"),
    "/usr/share/netshare/web/app.html",
]


class GuiApp:
    def __init__(self, state_path: str | None = None, client_factory=None):
        from .common import config_dir
        self.state_path = state_path or os.path.join(config_dir(), "gui.json")
        self.client_factory = client_factory  # test hook: (host,port,token,want_usb,want_lan,trust,forward_port,tap_name)
        state = load_json(self.state_path, {"profiles": []})
        self.profiles: list[dict] = state.get("profiles", [])
        self.client: NetshareClient | None = None
        self.client_task: asyncio.Task | None = None
        self.profile_name: str | None = None
        self.status = "disconnected"   # disconnected|connecting|connected|needs_trust|error
        self.error: str | None = None
        self.needed_fp: str | None = None
        self.attached: list[str] = []
        self.logs: deque = deque(maxlen=300)
        self.since = 0
        self.http = None
        self.port = 0
        self.app_path = next((p for p in APP_CANDIDATES if os.path.exists(p)), APP_CANDIDATES[1])

    # ----- lifecycle --------------------------------------------------------
    async def start(self):
        self.http = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.http.sockets[0].getsockname()[1]
        self.log("GUI ready on http://127.0.0.1:%d/", self.port)
        return self.port

    async def stop(self):
        await self.disconnect()
        if self.http:
            self.http.close()

    def log(self, msg: str, *args):
        line = time.strftime("%H:%M:%S ") + (msg % args if args else msg)
        self.logs.append(line)
        log.info("%s", line)

    def _save(self):
        save_json(self.state_path, {"profiles": self.profiles})

    # ----- connection -------------------------------------------------------
    async def connect_profile(self, name: str, trust: bool = False, lan: bool | None = None):
        await self.disconnect()
        p = next((x for x in self.profiles if x["name"] == name), None)
        if not p:
            self.status, self.error = "error", f"no profile named {name}"
            return
        self.status, self.error = "connecting", None
        self.needed_fp = None
        use_lan = p.get("lan", False) if lan is None else lan
        if self.client_factory:
            cli = self.client_factory(p["host"], int(p.get("port", 7575)), p.get("token", ""),
                                      True, use_lan, trust, 3240, "ns0")
        else:
            cli = NetshareClient(p["host"], int(p.get("port", 7575)), p.get("token", ""),
                                 want_usb=True, want_lan=use_lan, trust=trust,
                                 forward_port=3240, tap_name="ns0")
        try:
            await cli.connect()
        except SecurityError as e:
            if e.fingerprint:
                self.status, self.needed_fp = "needs_trust", e.fingerprint
                self.log("unknown certificate for %s - waiting for user trust decision", p["host"])
                return
            self.status, self.error = "error", str(e)
            return
        except Exception as e:
            self.status, self.error = "error", f"{type(e).__name__}: {e}"
            self.log("connect failed: %s", self.error)
            return

        self.client = cli
        self.profile_name = name
        self.since = time.time()
        self.client_task = asyncio.create_task(self._run_client(cli, use_lan))
        try:
            await asyncio.wait_for(cli.ready.wait(), timeout=8)
        except asyncio.TimeoutError:
            self.log("connection established; still bringing up forwards")
        self.status = "connected"
        w = cli.welcome or {}
        self.log("connected to %s (usbip=%s lan=%s)", w.get("server", "?"),
                 w.get("usbip", False), bool(w.get("lan")))

    async def _run_client(self, cli: NetshareClient, use_lan: bool):
        try:
            await cli.run_connected()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            self.log("connection lost: %s", f"{type(e).__name__}: {e}")
            self.error = f"connection lost: {e}"
            if self.status == "connected":
                self.status = "error"
        finally:
            self.attached = []
            self.client = None
            if self.status not in ("error", "needs_trust"):
                self.status = "disconnected"

    async def disconnect(self):
        if self.client_task:
            if self.attached:
                ports = await usbip_detach_ours()
                if ports:
                    self.log("detached vhci port(s): %s", ", ".join(ports))
            task, self.client_task = self.client_task, None
            if self.client:
                self.client.writer.close()
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        self.client = None
        self.attached = []
        self.error = None
        self.needed_fp = None
        if self.status != "error":
            self.status = "disconnected"

    # ----- usb ----------------------------------------------------------------
    async def usb_list(self) -> dict:
        if not self.client:
            return {"ok": False, "error": "not connected"}
        try:
            reply = await self.client.ctrl_request("usb.list")
            return {"ok": reply.get("ok", False),
                    "data": reply.get("data", {})}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    async def attach(self, busid: str) -> dict:
        if not self.client:
            return {"ok": False, "error": "not connected"}
        ok, msg = await usbip_attach(busid)
        if ok:
            if busid not in self.attached:
                self.attached.append(busid)
            self.log("attached %s", busid)
        else:
            self.log("attach %s failed: %s", busid, msg)
        return {"ok": ok, "message": msg}

    async def detach(self) -> dict:
        if not self.attached:
            return {"ok": True, "message": "nothing attached"}
        ports = await usbip_detach_ours()
        self.attached = []
        self.log("detached vhci port(s): %s", ", ".join(ports) or "none")
        return {"ok": True, "message": "detached " + ", ".join(ports) if ports else "nothing to detach"}

    # ----- status ---------------------------------------------------------------
    def status_payload(self) -> dict:
        cli = self.client
        w = cli.welcome if cli else {}
        return {
            "version": __version__,
            "status": self.status,
            "error": self.error,
            "needed_fingerprint": self.needed_fp,
            "profile": self.profile_name,
            "since": int(self.since) if cli else 0,
            "uptime": int(time.time() - self.since) if cli else 0,
            "server_name": w.get("server"),
            "lan": (w.get("lan") or None) if cli else None,
            "lan_local_ip": cli.tap_ip if cli else None,
            "rx": cli.rx if cli else 0,
            "tx": cli.tx if cli else 0,
            "attached": self.attached,
            "logs": list(self.logs)[-80:],
        }

    # ----- http -----------------------------------------------------------------
    async def _handle(self, reader, writer):
        try:
            req = await parse_request(reader)
            if not req:
                respond(writer, 400, {"error": "bad request"})
                return
            method, path, headers, body = req
            payload = {}
            if body:
                try:
                    payload = json.loads(body)
                except json.JSONDecodeError:
                    respond(writer, 400, {"error": "bad json"})
                    return

            if path in ("/", "/index.html"):
                try:
                    with open(self.app_path, "rb") as f:
                        html = f.read()
                    respond(writer, 200, html, "text/html; charset=utf-8")
                except OSError:
                    respond(writer, 500, {"error": "app.html not found"})
                return

            api = path[len("/api/"):] if path.startswith("/api/") else None
            if api is None:
                respond(writer, 404, {"error": "not found"})
                return

            if api == "status" and method == "GET":
                respond(writer, 200, self.status_payload())
            elif api == "profiles" and method == "GET":
                respond(writer, 200, {"profiles": [
                    {k: p.get(k) for k in ("name", "host", "port", "lan")} for p in self.profiles]})
            elif api == "profiles" and method == "POST":
                name = str(payload.get("name", "")).strip()
                host = str(payload.get("host", "")).strip()
                if not name or not host:
                    respond(writer, 400, {"error": "name and host required"})
                    return
                token = str(payload.get("token", "")).strip()
                port = int(payload.get("port", 7575) or 7575)
                use_lan = bool(payload.get("lan", False))
                existing = next((x for x in self.profiles if x["name"] == name), None)
                if existing:
                    existing.update({"host": host, "port": port, "lan": use_lan})
                    if token:
                        existing["token"] = token
                else:
                    self.profiles.append({"name": name, "host": host, "port": port,
                                          "token": token, "lan": use_lan})
                self._save()
                self.log("saved server profile '%s' (%s:%s)", name, host, port)
                respond(writer, 200, {"ok": True})
            elif api == "profiles/delete" and method == "POST":
                name = str(payload.get("name", ""))
                if self.profile_name == name:
                    await self.disconnect()
                self.profiles = [p for p in self.profiles if p["name"] != name]
                self._save()
                respond(writer, 200, {"ok": True})
            elif api == "connect" and method == "POST":
                name = str(payload.get("name", ""))
                await self.connect_profile(name, trust=bool(payload.get("trust")),
                                           lan=payload.get("lan"))
                respond(writer, 200, self.status_payload())
            elif api == "disconnect" and method == "POST":
                await self.disconnect()
                respond(writer, 200, self.status_payload())
            elif api == "usb" and method == "GET":
                respond(writer, 200, await self.usb_list())
            elif api == "attach" and method == "POST":
                respond(writer, 200, await self.attach(str(payload.get("busid", ""))))
            elif api == "detach" and method == "POST":
                respond(writer, 200, await self.detach())
            else:
                respond(writer, 404, {"error": f"no route {method} /api/{api}"})
        except (asyncio.IncompleteReadError, ConnectionResetError, asyncio.TimeoutError, OSError):
            pass
        except Exception as e:
            log.exception("gui api error")
            try:
                respond(writer, 500, {"error": str(e)})
            except Exception:
                pass
        finally:
            try:
                writer.close()
            except OSError:
                pass


def run_gui(no_window: bool = False) -> None:
    app = GuiApp()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    port = loop.run_until_complete(app.start())
    url = f"http://127.0.0.1:{port}/"
    threading.Thread(target=loop.run_forever, daemon=True).start()

    webview = None
    if not no_window:
        try:
            import webview  # pywebview (optional)
        except Exception as e:
            log.info("pywebview unavailable (%s) - using browser", e)

    if webview is not None:
        webview.create_window(
            f"netshare {__version__}", url, width=1020, height=700,
            min_size=(780, 540), background_color="#0d1117")
        webview.start()  # blocks until the window is closed
        try:
            asyncio.run_coroutine_threadsafe(app.stop(), loop).result(timeout=10)
        except Exception:
            pass
    else:
        print(f"\n  netshare GUI running at {url}\n  (Ctrl-C here to quit)\n")
        webbrowser.open(url)
        try:
            threading.Event().wait()  # forever; daemon threads die with process
        except KeyboardInterrupt:
            try:
                asyncio.run_coroutine_threadsafe(app.stop(), loop).result(timeout=10)
            except Exception:
                pass
