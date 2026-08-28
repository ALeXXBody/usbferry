"""netshare — share USB devices and LAN connectivity over the internet.

Server/client app: encrypted multiplexed tunnel (TLS + token auth) carrying
the kernel-standard usbip protocol and raw ethernet frames (TAP virtual NIC).
"""

__version__ = "0.2.0"
PROTOCOL_VERSION = 1
