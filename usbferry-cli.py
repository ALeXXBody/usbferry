#!/usr/bin/env python3
"""Standalone CLI entry point for PyInstaller builds.

Usage when frozen:  usbferry.exe connect <host> --token ns_... --trust --lan
"""

from usbferry.__main__ import main

if __name__ == "__main__":
    main()
