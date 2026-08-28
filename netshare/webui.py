"""Embedded web UI: a very small asyncio HTTP server (stdlib only).

Serves web/index.html and a JSON API authenticated with the same tokens as the
tunnel (Authorization: Bearer <token>). Meant for managing a netshare server.
"""

import asyncio
import json
import os

from .common import log

MAX_BODY = 1 << 20
INDEX_CANDIDATES = [
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web", "index.html"),
    "/usr/share/netshare/web/index.html",
]


class WebUI:
    def __init__(self, server, bind: str, port: int):
        self.server = server
        self.bind = bind
        self.port = port
        self._srv = None
        self.index_path = next((p for p in INDEX_CANDIDATES if os.path.exists(p)), INDEX_CANDIDATES[0])

    async def start(self):
        self._srv = await asyncio.start_server(self._handle, self.bind, self.port)

    async def stop(self):
        if self._srv:
            self._srv.close()
            await self._srv.wait_closed()

    # ----- http -------------------------------------------------------------
    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            await self._route(reader, writer)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionResetError, OSError):
            pass
        except Exception as e:
            log.debug("webui error: %r", e)
            try:
                self._respond(writer, 500, {"error": "internal error"})
            except Exception:
                pass
        finally:
            try:
                writer.close()
            except OSError:
                pass

    async def _route(self, reader, writer):
        request_line = await asyncio.wait_for(reader.readline(), timeout=10)
        parts = request_line.decode("latin1").split()
        if len(parts) < 2:
            self._respond(writer, 400, {"error": "bad request"})
            return
        method, path = parts[0].upper(), parts[1]

        headers = {}
        while True:
            line = await reader.readline()
            if line in (b"\r\n", b"\n", b""):
                break
            key, _, val = line.decode("latin1").partition(":")
            headers[key.strip().lower()] = val.strip()

        body = b""
        try:
            length = int(headers.get("content-length", "0") or 0)
        except ValueError:
            length = 0
        if 0 < length <= MAX_BODY:
            body = await reader.readexactly(length)

        if path == "/" or path.startswith("/index"):
            self._serve_index(writer)
            return

        if not path.startswith("/api/"):
            self._respond(writer, 404, {"error": "not found"})
            return

        token = ""
        auth = headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            token = auth[7:].strip()
        if not token:
            self._respond(writer, 401, {"error": "missing bearer token"})
            return
        if not self.server.verify_token(token):
            self._respond(writer, 401, {"error": "invalid token"})
            return

        api = path[len("/api/"):]
        payload = {}
        if body:
            try:
                payload = json.loads(body)
            except json.JSONDecodeError:
                self._respond(writer, 400, {"error": "bad json"})
                return

        await self._api(writer, method, api, payload)

    async def _api(self, writer, method, api, payload):
        srv = self.server
        if api == "status" and method == "GET":
            self._respond(writer, 200, srv.status())
        elif api == "usb" and method == "GET":
            self._respond(writer, 200, {
                "available": srv.usbip.available, "error": srv.usbip.error,
                "devices": await srv.usbip.list_devices()})
        elif api == "usb/bind" and method == "POST":
            ok, msg = await srv.usbip.bind(str(payload.get("busid", "")))
            self._respond(writer, 200 if ok else 400, {"ok": ok, "message": msg})
        elif api == "usb/unbind" and method == "POST":
            ok, msg = await srv.usbip.unbind(str(payload.get("busid", "")))
            self._respond(writer, 200 if ok else 400, {"ok": ok, "message": msg})
        elif api == "lan" and method == "GET":
            st = srv.status()["lan"]
            self._respond(writer, 200, st)
        elif api == "tokens" and method == "GET":
            self._respond(writer, 200, {"tokens": [
                {"name": t["name"], "created": t.get("created", "?")}
                for t in srv.cfg.get("tokens", [])]})
        elif api == "tokens" and method == "POST":
            name = str(payload.get("name", "")).strip()
            if not name:
                self._respond(writer, 400, {"error": "name required"})
                return
            token = srv.add_token(name)
            self._respond(writer, 200, {"ok": True, "name": name, "token": token})
        elif api == "tokens/delete" and method == "POST":
            ok = srv.remove_token(str(payload.get("name", "")))
            self._respond(writer, 200 if ok else 404, {"ok": ok})
        else:
            self._respond(writer, 404, {"error": f"no route {method} /api/{api}"})

    def _serve_index(self, writer):
        try:
            with open(self.index_path, "rb") as f:
                html = f.read()
        except OSError:
            self._respond(writer, 500, {"error": "index.html not found"})
            return
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n")
        writer.write(f"Content-Length: {len(html)}\r\nCache-Control: no-store\r\n\r\n".encode())
        writer.write(html)

    def _respond(self, writer, code: int, obj):
        body = json.dumps(obj).encode()
        reason = {200: "OK", 400: "Bad Request", 401: "Unauthorized",
                  404: "Not Found", 500: "Internal Error"}.get(code, "Error")
        writer.write(f"HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\n".encode())
        writer.write(f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode())
        writer.write(body)
