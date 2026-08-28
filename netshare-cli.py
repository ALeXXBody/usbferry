#!/usr/bin/env python3
"""Standalone CLI entry point for PyInstaller builds.

Usage when frozen:  netshare.exe connect <host> --token ns_... --trust --lan
"""

from netshare.__main__ import main

if __name__ == "__main__":
    main()
