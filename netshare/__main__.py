"""CLI entrypoint: python3 -m netshare <command>"""

import argparse
import asyncio
import os
import signal
import sys

from . import __version__
from .common import DEFAULT_PORT, setup_logging


def need_root(why: str):
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print(f"[!] warning: {why} usually requires root; continuing anyway", file=sys.stderr)


def add_client_opts(p: argparse.ArgumentParser):
    p.add_argument("host", help="netshare server host")
    p.add_argument("-p", "--port", type=int, default=DEFAULT_PORT)
    p.add_argument("-t", "--token", default=os.environ.get("NETSHARE_TOKEN", ""),
                   help="auth token (or env NETSHARE_TOKEN)")
    p.add_argument("--fingerprint", help="expected server cert SHA-256 fingerprint")
    p.add_argument("--trust", action="store_true",
                   help="trust & pin unknown server certificate (TOFU)")
    p.add_argument("--forward-port", type=int, default=3240,
                   help="local port that forwards usbip through the tunnel (default 3240)")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="netshare",
        description="Share USB devices and LAN connectivity over the internet "
                    "(encrypted usbip + TAP tunnel).")
    ap.add_argument("-V", "--version", action="version", version=f"netshare {__version__}")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="run the netshare server (tunnel + web UI)")
    s.add_argument("--config", default=None)
    s.add_argument("--port", type=int, default=None)
    s.add_argument("--web-port", type=int, default=None)
    s.add_argument("--bind", default=None)
    s.add_argument("--no-lan", action="store_true")

    t = sub.add_parser("add-token", help="create a client auth token (server config)")
    t.add_argument("--name", required=True, help="token name, e.g. 'laptop'")
    t.add_argument("--config", default=None)

    t = sub.add_parser("rm-token", help="remove a client auth token")
    t.add_argument("--name", required=True)
    t.add_argument("--config", default=None)

    t = sub.add_parser("list-tokens", help="list token names")
    t.add_argument("--config", default=None)

    c = sub.add_parser("connect", help="connect: usb forward (+ optional LAN)")
    add_client_opts(c)
    c.add_argument("--lan", action="store_true", help="bring up the virtual NIC (LAN sharing)")
    c.add_argument("--no-usb", action="store_true", help="skip usbip forwarding")
    c.add_argument("--default-route", action="store_true",
                   help="route ALL traffic through the server (NAT mode)")
    c.add_argument("--tap", default="ns0", help="local TAP interface name")

    c = sub.add_parser("list-usb", help="list USB devices on the server, then exit")
    add_client_opts(c)

    c = sub.add_parser("attach", help="connect and attach a remote USB device by busid")
    add_client_opts(c)
    c.add_argument("-b", "--busid", required=True, help="server-side busid, e.g. 1-2")

    return ap


async def cmd_serve(args):
    from .server import NetshareServer
    need_root("running the server (usbip bind, TAP, NAT)")
    overrides = {}
    if args.port:
        overrides["port"] = args.port
    if args.web_port:
        overrides.setdefault("web", {})["port"] = args.web_port
    if args.bind:
        overrides["bind"] = args.bind
    if args.no_lan:
        overrides.setdefault("lan", {})["enabled"] = False
    server = NetshareServer(args.config, overrides)
    await server.start()
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass
    await stop.wait()
    print("\n[*] shutting down ...")
    await server.stop()


async def cmd_connect(args):
    from .client import NetshareClient
    if args.lan:
        need_root("LAN mode (creates a TAP interface)")
    cli = NetshareClient(
        args.host, args.port, args.token,
        want_usb=not args.no_usb, want_lan=args.lan,
        trust=args.trust, fingerprint=args.fingerprint,
        forward_port=args.forward_port, tap_name=args.tap,
        default_route=args.default_route)
    await cli.run()


async def cmd_list_usb(args):
    from .client import NetshareClient

    async def ready(cli: NetshareClient):
        reply = await cli.ctrl_request("usb.list")
        data = reply.get("data", {})
        if not data.get("available"):
            print(f"[!] usbip unavailable on server: {data.get('error')}")
        else:
            devices = data.get("devices", [])
            if not devices:
                print("no USB devices visible on the server")
            print(f"{'BUSID':<8} {'EXPORTED':<9} {'VID:PID':<10} DESCRIPTION")
            for d in devices:
                print(f"{d['busid']:<8} {'yes' if d['exported'] else 'no':<9} "
                      f"{d['vidpid']:<10} {d['desc']}")
        cli.writer.close()

    cli = NetshareClient(args.host, args.port, args.token,
                         want_usb=True, want_lan=False,
                         trust=args.trust, fingerprint=args.fingerprint,
                         forward_port=0, on_ready=ready)
    # forward_port=0 would try to bind :0; disable forwarding explicitly
    cli.want_usb = False
    await cli.run()


async def cmd_attach(args):
    from .client import NetshareClient, usbip_attach, usbip_detach_ours
    need_root("attaching usbip devices")
    stop = asyncio.Event()
    outcome = {}

    async def ready(cli: NetshareClient):
        await asyncio.sleep(0.3)  # let the forward listener settle
        ok, msg = await usbip_attach(args.busid)
        outcome["attached"] = ok
        if ok:
            print(f"[+] attached {args.busid} ({msg})")
            print("[*] Ctrl-C to detach and disconnect")
        else:
            print(f"[!] attach failed: {msg}")
            stop.set()

    cli = NetshareClient(args.host, args.port, args.token,
                         want_usb=True, want_lan=False,
                         trust=args.trust, fingerprint=args.fingerprint,
                         forward_port=args.forward_port, on_ready=ready)
    run_task = asyncio.create_task(cli.run())
    stop_task = asyncio.create_task(stop.wait())
    done, _ = await asyncio.wait({run_task, stop_task},
                                 return_when=asyncio.FIRST_COMPLETED)
    if stop_task in done and not run_task.done():
        run_task.cancel()
        try:
            await run_task
        except (asyncio.CancelledError, Exception):
            pass
    else:
        await run_task
    if outcome.get("attached"):
        ports = await usbip_detach_ours()
        if ports:
            print(f"[*] detached vhci port(s): {', '.join(ports)}")


async def _token_cmd(args, action):
    from .server import NetshareServer
    server = NetshareServer(args.config)
    if action == "add":
        token = server.add_token(args.name)
        print(f"token:      {token}")
        print(f"token name: {args.name}")
        print("\nclient usage:")
        print(f"  python3 -m netshare connect <host> --token {token} --trust --lan")
        print(f"  python3 -m netshare list-usb <host> --token {token} --trust")
    elif action == "rm":
        print("removed" if server.remove_token(args.name) else "not found")
    else:
        for t in server.cfg.get("tokens", []):
            print(f"{t['name']:<24} created {t.get('created', '?')}")


def main():
    args = build_parser().parse_args()
    setup_logging(args.verbose)
    try:
        if args.cmd == "serve":
            asyncio.run(cmd_serve(args))
        elif args.cmd == "connect":
            asyncio.run(cmd_connect(args))
        elif args.cmd == "list-usb":
            asyncio.run(cmd_list_usb(args))
        elif args.cmd == "attach":
            asyncio.run(cmd_attach(args))
        elif args.cmd == "add-token":
            asyncio.run(_token_cmd(args, "add"))
        elif args.cmd == "rm-token":
            asyncio.run(_token_cmd(args, "rm"))
        elif args.cmd == "list-tokens":
            asyncio.run(_token_cmd(args, "list"))
    except KeyboardInterrupt:
        print("\n[*] interrupted")
    except Exception as e:
        from .client import ClientError, SecurityError
        if isinstance(e, (ClientError, SecurityError)):
            print(f"[!] {e}", file=sys.stderr)
            sys.exit(1)
        raise


if __name__ == "__main__":
    main()
