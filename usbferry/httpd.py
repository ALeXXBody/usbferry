"""Tiny asyncio HTTP helpers shared by the web UI and the local GUI."""

import asyncio
import json

MAX_BODY = 1 << 20
MAX_HEADER_LINES = 100
MAX_LINE = 16384
_REASONS = {200: "OK", 400: "Bad Request", 401: "Unauthorized", 404: "Not Found",
            413: "Payload Too Large", 500: "Internal Error"}


async def parse_request(reader: asyncio.StreamReader):
    """Parse one HTTP request. Returns (method, path, headers, body) or None."""
    line = await asyncio.wait_for(reader.readline(), timeout=10)
    if len(line) > MAX_LINE:
        return None
    parts = line.decode("latin1").split()
    if len(parts) < 2:
        return None
    method, path = parts[0].upper(), "/" + parts[1].lstrip("/")
    headers = {}
    for _ in range(MAX_HEADER_LINES):
        raw = await reader.readline()
        if raw in (b"\r\n", b"\n", b""):
            break
        if len(raw) > MAX_LINE:
            return None
        key, _, val = raw.decode("latin1").partition(":")
        headers[key.strip().lower()] = val.strip()
    else:
        return None  # header flood
    body = b""
    try:
        length = int(headers.get("content-length", "0") or 0)
    except ValueError:
        length = 0
    if length < 0 or length > MAX_BODY:
        return None
    if 0 < length <= MAX_BODY:
        body = await reader.readexactly(length)
    return method, path, headers, body


def respond(writer: asyncio.StreamWriter, code: int, obj, content_type: str = "application/json") -> None:
    if isinstance(obj, (dict, list)):
        body = json.dumps(obj).encode()
    elif isinstance(obj, str):
        body = obj.encode()
    else:
        body = obj
        content_type = content_type or "application/octet-stream"
    reason = _REASONS.get(code, "Error")
    head = (f"HTTP/1.1 {code} {reason}\r\nContent-Type: {content_type}\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n")
    writer.write(head.encode() + body)
