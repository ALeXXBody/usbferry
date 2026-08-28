# netshare

Share USB devices and a LAN connection across networks or the internet.

- **USB over IP**: exports real USB devices via the kernel-standard `usbip`
  protocol, tunneled through an encrypted TLS connection.
- **LAN over IP**: gives the client a virtual NIC (TAP) with NAT or bridge
  access to the server's network.
- Token auth, cert fingerprint pinning (TOFU), embedded web UI for management.

> Work in progress — being built now. See README for full docs once complete.
