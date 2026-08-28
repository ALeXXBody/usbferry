"""On-demand download + install of usbipd-win (Windows server side).

usbferry does NOT bundle or redistribute usbipd-win (GPL-3.0, by Frans van
Dorssel). At the user's explicit request (a button in the app) it downloads
the official MSI from the vendor's GitHub releases and installs it via
msiexec with a UAC prompt. That is arm's-length interoperation, not
distribution: the file travels from the vendor to the user's machine on
demand, and no usbipd-win code is part of usbferry.
"""

import asyncio
import json
import os
import urllib.request

from . import __version__
from .common import run

RELEASES_API = "https://api.github.com/repos/dorssel/usbipd-win/releases/latest"
MSI_NAME = "usbferry-usbipd-win.msi"


def _ua() -> str:
    return f"usbferry/{__version__} (+https://github.com/ALeXXBody/usbferry)"


def pick_msi_asset(release: dict) -> tuple[str, str, int]:
    """Return (name, download_url, size_bytes) of the .msi asset in a GitHub
    release payload."""
    for asset in release.get("assets", []):
        name = str(asset.get("name", ""))
        if name.lower().endswith(".msi"):
            return name, str(asset["browser_download_url"]), int(asset.get("size") or 0)
    raise ValueError("no .msi asset found in the latest usbipd-win release")


async def latest_msi() -> tuple[str, str, int]:
    """Fetch the latest release metadata from GitHub and pick the MSI."""
    def _fetch():
        req = urllib.request.Request(RELEASES_API, headers={"User-Agent": _ua()})
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode())
    release = await asyncio.get_running_loop().run_in_executor(None, _fetch)
    return pick_msi_asset(release)


async def download(url: str, dest: str, progress=None) -> None:
    """Stream url to dest; calls progress(percent) when size is known."""
    def _fetch():
        req = urllib.request.Request(url, headers={"User-Agent": _ua()})
        with urllib.request.urlopen(req, timeout=120) as r, open(dest, "wb") as f:
            total = int(r.headers.get("Content-Length") or 0)
            got = 0
            while True:
                chunk = r.read(65536)
                if not chunk:
                    break
                f.write(chunk)
                got += len(chunk)
                if progress and total:
                    progress(min(100, int(got * 100 / total)))
    await asyncio.get_running_loop().run_in_executor(None, _fetch)


async def install_msi_elevated(msi_path: str) -> tuple[bool, str]:
    """Quiet-install an MSI, elevating via UAC. Returns (ok, message)."""
    if os.name != "nt":
        return False, "usbipd-win installation is only available on Windows"
    if '"' in msi_path or "'" in msi_path:
        return False, "unexpected characters in installer path"
    ps = (
        "try { $p = Start-Process -Verb RunAs -Wait -PassThru -WindowStyle Hidden "
        f"-FilePath msiexec.exe -ArgumentList '/i','{msi_path}','/qn','/norestart'; "
        "exit $p.ExitCode } catch { Write-Error $_; exit 1618 }"
    )
    rc, out, err = await run(["powershell", "-NoProfile", "-Command", ps], timeout=600)
    if rc in (0, 3010):  # 3010 = success, reboot recommended
        return True, "installed" + (" (reboot recommended)" if rc == 3010 else "")
    low = err.lower()
    if "canceled" in low or "cancelled" in low:
        return False, "the UAC prompt was declined — click Install again and allow it"
    return False, f"installer exited with code {rc}: {err.strip()[:200]}"
