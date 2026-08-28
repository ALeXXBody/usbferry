# Security Policy

## Reporting a vulnerability

Please report privately via
[GitHub security advisories](https://github.com/ALeXXBody/usbferry/security/advisories/new)
("Report a vulnerability"). Include reproduction steps; the tunnel server,
client, web admin, and installer automation are all in scope. Please avoid
opening public issues for suspected vulnerabilities.

## Audits

- [AUDIT.md](AUDIT.md) — full security & stability self-audit (v0.6.0),
  including threat model notes and known accepted risks.

## Security model summary

- TLS 1.2+ tunnel with SHA-256 certificate fingerprint pinning (TOFU)
- Per-device tokens, stored hashed, constant-time compare, per-IP lockout
  after 10 failed auths
- Clients only see devices the operator explicitly shared
- usbipd unreachable except through the encrypted tunnel (loopback +
  firewall rule on Linux)
- usbipd-win / usbip-win2 are downloaded on demand from their official
  releases; never bundled (GPL separation)
