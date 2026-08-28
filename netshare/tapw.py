"""TAP virtual NIC abstraction.

Three backends behind one async interface (read_frame / write_frame / close):

  - KernelTap         Linux /dev/net/tun (the normal case)
  - WinTap            Windows TAP-Windows adapter (tap0901, e.g. OpenVPN driver), experimental
  - PipeTapEndpoint   in-memory pair used by tests / fallbacks (pipe_tap_pair())
"""

import asyncio
import fcntl
import os
import struct

IFF_TAP = 0x0002
IFF_NO_PI = 0x1000
TUNSETIFF = 0x400454CA


class TapError(Exception):
    pass


class TapClosed(Exception):
    pass


class KernelTap:
    """A TAP interface on Linux. Caller configures IPs/routes with `ip(8)`."""

    def __init__(self, fd: int, name: str):
        self.fd = fd
        self.name = name
        self._closed = False
        self._readers: list[asyncio.Future] = []
        self._writers: list[asyncio.Future] = []

    @classmethod
    async def create(cls, name: str = "ns0") -> "KernelTap":
        try:
            fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
        except OSError as e:
            raise TapError(
                f"cannot open /dev/net/tun ({e}). On most distros it just needs to exist; "
                "on hardened systems (TrueNAS, unprivileged containers) TAP is unavailable."
            ) from e
        ifreq = struct.pack("16sH22s", name.encode()[:15], IFF_TAP | IFF_NO_PI, b"")
        try:
            res = fcntl.ioctl(fd, TUNSETIFF, ifreq)
        except OSError as e:
            os.close(fd)
            raise TapError(f"TUNSETIFF failed for {name}: {e}") from e
        actual = res[:16].split(b"\0", 1)[0].decode()
        return cls(fd, actual)

    def _wake(self, futures: list[asyncio.Future]) -> None:
        for fut in futures[:]:
            if not fut.done():
                fut.set_result(None)
            futures.remove(fut)

    async def _wait(self, futures: list[asyncio.Future], register) -> None:
        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        futures.append(fut)
        register(self.fd, lambda: self._wake(futures))
        try:
            await fut
        finally:
            try:
                futures.remove(fut)
            except ValueError:
                pass

    async def read_frame(self) -> bytes:
        if self._closed:
            raise TapClosed()
        while True:
            try:
                data = os.read(self.fd, 65536)
            except BlockingIOError:
                await self._wait(self._readers, asyncio.get_running_loop().add_reader)
                if self._closed:
                    raise TapClosed()
                continue
            if not data:
                raise TapClosed()
            return data

    async def write_frame(self, data: bytes) -> None:
        if self._closed:
            raise TapClosed()
        view = memoryview(data)
        while view:
            try:
                n = os.write(self.fd, view)
            except BlockingIOError:
                await self._wait(self._writers, asyncio.get_running_loop().add_writer)
                if self._closed:
                    raise TapClosed()
                continue
            view = view[n:]

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        loop = asyncio.get_event_loop()
        try:
            loop.remove_reader(self.fd)
            loop.remove_writer(self.fd)
        except (RuntimeError, NotImplementedError):
            pass
        try:
            self._wake(self._readers)
            self._wake(self._writers)
        except Exception:
            pass
        try:
            os.close(self.fd)
        except OSError:
            pass


class PipeTapEndpoint:
    """In-memory TAP endpoint; frames written here pop out of its twin."""

    def __init__(self, rx: asyncio.Queue, tx: asyncio.Queue, twin_close):
        self._rx = rx
        self._tx = tx
        self._twin_close = twin_close
        self._closed = False
        self.name = "pipe0"

    async def read_frame(self) -> bytes:
        item = await self._rx.get()
        if item is None:
            raise TapClosed()
        return item

    async def write_frame(self, data: bytes) -> None:
        if self._closed:
            raise TapClosed()
        self._tx.put_nowait(data)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._twin_close()


def pipe_tap_pair() -> tuple[PipeTapEndpoint, PipeTapEndpoint]:
    """Create two linked endpoints (a<->b). Used for tests and fallbacks."""
    q1: asyncio.Queue = asyncio.Queue()
    q2: asyncio.Queue = asyncio.Queue()

    def closer(queue: asyncio.Queue):
        def _close():
            queue.put_nowait(None)
        return _close

    a = PipeTapEndpoint(q1, q2, closer(q2))
    b = PipeTapEndpoint(q2, q1, closer(q1))
    return a, b


if os.name == "nt":
    import asyncio as _aio
    import ctypes

    TAP_CONTROL_CODE = lambda n: (0x22 << 16) | (n << 2)  # FILE_DEVICE_UNKNOWN, METHOD_BUFFERED, FILE_ANY_ACCESS
    TAP_IOCTL_GET_MTU = TAP_CONTROL_CODE(1)
    TAP_IOCTL_SET_MEDIA_STATUS = TAP_CONTROL_CODE(5)

    class WinTap:
        """TAP-Windows (tap0901) adapter via ctypes. Requires the OpenVPN TAP driver.

        Blocking device IO is pushed to the default executor.
        """

        def __init__(self, handle, guid: str, adapter_name: str, mtu: int):
            self._h = handle
            self.guid = guid
            self.name = adapter_name
            self.mtu = mtu
            self._closed = False
            self._lock = _aio.Lock()

        @classmethod
        def find_adapters(cls) -> list[tuple[str, str]]:
            import winreg
            out = []
            cls_key = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
            try:
                root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, cls_key)
            except OSError:
                return out
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(root, i)
                except OSError:
                    break
                i += 1
                try:
                    with winreg.OpenKey(root, sub) as k:
                        comp, _ = winreg.QueryValueEx(k, "ComponentId")
                        if comp.lower() != "tap0901":
                            continue
                        guid, _ = winreg.QueryValueEx(k, "NetCfgInstanceId")
                except OSError:
                    continue
                name = guid
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                        rf"SYSTEM\CurrentControlSet\Control\Network\{{4d36e972-e325-11ce-bfc1-08002be10318}}\{guid}\Connection") as k:
                        name, _ = winreg.QueryValueEx(k, "Name")
                except OSError:
                    pass
                out.append((guid, name))
            return out

        @classmethod
        def open(cls, guid: str | None = None) -> "WinTap":
            adapters = cls.find_adapters()
            if not adapters:
                raise TapError(
                    "no TAP-Windows adapter found. Install the OpenVPN TAP driver "
                    "(e.g. 'winget install OpenVPNTech.OpenVPN' or tap-windows installer)."
                )
            if guid is None:
                guid, name = adapters[0]
            else:
                name = next((n for g, n in adapters if g == guid), guid)
            k32 = ctypes.windll.kernel32
            path = f"\\\\.\\Global\\{guid}.tap"
            handle = k32.CreateFileW(ctypes.c_wchar_p(path), 0xC0000000, 0, None, 3, 0, None)  # RW, OPEN_EXISTING
            if handle == -1 or handle == 0xFFFFFFFFFFFFFFFF:
                raise TapError(f"cannot open TAP adapter {path}")
            mtu_buf = ctypes.create_string_buffer(4)
            ret = ctypes.c_ulong(0)
            ok = k32.DeviceIoControl(handle, TAP_IOCTL_GET_MTU, None, 0, mtu_buf, 4, ctypes.byref(ret), None)
            mtu = struct.unpack("<I", mtu_buf.raw)[0] if ok else 1500
            tap = cls(handle, guid, name, mtu)
            tap._set_media_status(True)
            return tap

        def _set_media_status(self, connected: bool) -> None:
            k32 = ctypes.windll.kernel32
            buf = struct.pack("<I", 1 if connected else 0)
            ret = ctypes.c_ulong(0)
            k32.DeviceIoControl(self._h, TAP_IOCTL_SET_MEDIA_STATUS,
                                buf, len(buf), None, 0, ctypes.byref(ret), None)

        async def _dev_io(self, fn, *args):
            if self._closed:
                raise TapClosed()
            return await asyncio.get_running_loop().run_in_executor(None, fn, *args)

        async def read_frame(self) -> bytes:
            k32 = ctypes.windll.kernel32
            buf = ctypes.create_string_buffer(65536)
            got = ctypes.c_ulong(0)

            def _rd():
                ok = k32.ReadFile(self._h, buf, len(buf), ctypes.byref(got), None)
                return ok, buf.raw[:got.value]
            while True:
                ok, data = await self._dev_io(_rd)
                if self._closed:
                    raise TapClosed()
                if ok and data:
                    return data

        async def write_frame(self, data: bytes) -> None:
            k32 = ctypes.windll.kernel32
            sent = ctypes.c_ulong(0)

            def _wr(payload):
                return k32.WriteFile(self._h, payload, len(payload), ctypes.byref(sent), None)
            ok = await self._dev_io(_wr, ctypes.create_string_buffer(data, len(data)))
            if not ok:
                raise TapError("TAP WriteFile failed")

        def close(self) -> None:
            if self._closed:
                return
            self._closed = True
            self._set_media_status(False)
            ctypes.windll.kernel32.CloseHandle(self._h)
else:
    WinTap = None  # type: ignore[assignment,misc]
