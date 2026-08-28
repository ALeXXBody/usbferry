# Security & Stability Audit — usbferry v0.6.0

Scope: full review of the tunnel server, client, GUI backend, web admin, and
packaging. Findings marked **fixed** are covered by regression tests
(`tests/test_loopback.py`, `tests/test_gui.py`, `tests/test_localserver.py`).

## Security

### Fixed in this release

| # | Finding | Severity | Fix |
|---|---|---|---|
| S1 | **Auth brute-force had no throttling.** An attacker could try tokens unlimited (tunnel port *and* web admin). | medium | Per-IP failed-attempt tracking: 10 failures per 5 minutes → lockout for that IP; clean record on success. Applies to the TLS tunnel hello and every web-admin API call. |
| S2 | **Channel exhaustion DoS.** An *authenticated* client could open unlimited usbip channels, each holding a server socket to usbipd. | medium | `max_channels = 16` per session (configurable); excess OPENs get CLOSE `too many channels`. |
| S3 | **Device inventory disclosure** (fixed in v0.5.3, listed for completeness): clients only ever see *bound* devices; the server's full USB inventory never crosses the tunnel. Opt-in: `usbip.expose_unexported: true`. | medium | server-side filtering |
| S4 | **Header/request floods** against the HTTP servers (web admin, GUI): unbounded header count/size. | low | `parse_request` caps: 100 header lines, 16 KiB per line, 1 MiB body; oversized → dropped. |

### Reviewed and confirmed sound

- **Tokens**: 24-byte `secrets` values, stored **hashed** (SHA-256) only,
  constant-time comparison, revocable, per-device naming. Plaintext shown once
  in the GUI and kept in memory for the session only.
- **Transport**: TLS 1.2+ (ECDSA P-256 self-signed cert); clients pin the
  server cert SHA-256 fingerprint trust-on-first-use and hard-fail on any
  change (MITM indicator). Client-side cert validation is intentionally
  disabled *because* pinning replaces it.
- **usbipd exposure**: on Linux, an iptables REJECT rule blocks non-loopback
  TCP/3240 so only the tunnel can reach usbipd (fail-closed; rule persists
  after stop). On Windows, usbipd-win's own ACLs apply — the app never opens
  3240 to the internet; only the encrypted tunnel port (7575) is exposed.
- **Command injection**: all subprocess calls use argv lists (no shell);
  PowerShell elevation command rejects quote characters in paths; busids come
  from parsed tool output, not free-form user input.
- **XSS**: every dynamic value rendered in the web UIs goes through an
  HTML-escaping helper (checked all `innerHTML` sites).
- **GUI local API**: binds 127.0.0.1 with a random port. Note: like any local
  admin surface (Docker, etc.), other processes of the *same user* can reach
  it; it grants nothing beyond what that user can already do by reading the
  config files.
- **Crash logs / app logs**: verified no tokens are ever written to logs or
  tracebacks (tokens appear only in stdout of `add-token` by design).

### Accepted risks / notes

- **No per-device ACLs**: any valid token can attach any *bound* device.
  Mitigation: bind only what you share, per-person tokens, revoke on loss.
- **Token on the CLI** (`--token`) is visible in `ps` output; prefer
  `USBFERRY_TOKEN` env or the GUI profiles.
- **Unsigned Windows exes** → SmartScreen warning (documented; user accepted).
  Checksums published per release.
- **TLS 1.2 minimum** (not 1.3): acceptable — AEAD ciphers only, both ends are
  ours; revisit if needed.

## Stability

### Fixed in this release

| # | Finding | Severity | Fix |
|---|---|---|---|
| T1 | **Non-atomic config writes.** A crash mid-`save_json` could truncate `server.json` → all tokens silently lost. | high | write-to-temp + `fsync` + atomic `os.replace`. |
| T2 | **Handler crash on edge inputs.** Oversized hello lines (`LimitOverrunError`/`ValueError`), LAN pool exhaustion (`TapError`) and similar escaped the except clause (server survived, but sessions leaked logs/sockets). | medium | catch-all in every connection handler; verified with a 200 KB garbage-line attack test. |
| T3 | **No auto-reconnect in the GUI.** A dropped tunnel left the client dead until manually reconnected; attached devices could linger. | medium | auto-reconnect with backoff (4 s → 10 s, max 6 attempts, stops on manual disconnect or profile switch) + best-effort vhci detach on loss. |
| T4 | **Token hot-reload correctness** (from v0.4.1, re-verified): add/remove via CLI while the service runs is picked up via mtime check on every auth. | — | covered by tests |

### Reviewed and confirmed sound

- Frame parsing enforces `MAX_FRAME` (70 000 B); `readexactly` everywhere;
  backpressure on usbip pumps (256 KiB buffer threshold with `await drain()`).
- Keepalive (20 s ping / 60 s timeout) reaps dead sessions; sessions and their
  channels are fully torn down on disconnect (writers closed, pumps cancelled).
- `run()` subprocess helper never raises (timeouts → kill, missing binary →
  rc 127) — used for every external tool call.
- The server survives: channel floods, oversized lines, brute-force lockouts,
  abrupt client disconnects (all covered by tests).
- Windows-specific: `CREATE_NO_WINDOW` on all subprocess spawns; UAC declines
  and installer failures handled as retryable states.

## Verification

```bash
python3 tests/test_loopback.py      # 30 checks: framing, auth, throttle,
                                    # channel cap, flood robustness, web API
python3 tests/test_gui.py           # 19 checks: GUI backend + auto-reconnect
python3 tests/test_localserver.py   # 49 checks: local server, installer flow
```

Report date: 2026-08-28. Auditor: usbferry maintainers (self-audit, full
source review + adversarial tests).
