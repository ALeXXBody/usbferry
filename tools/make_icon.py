#!/usr/bin/env python3
"""Generate usbferry icons (assets/usbferry.ico + assets/icon.png) with stdlib only.

Design: rounded dark square with two opposing arrows (device travels both ways),
matching the app's palette. PNG entries are packed into a Windows .ico.
"""

import struct
import zlib
from pathlib import Path

SIZE = 256
BG = (22, 27, 34, 255)       # #161b22 panel
BORDER = (48, 54, 61, 255)   # #30363d
ARROW = (88, 166, 255, 255)  # #58a6ff accent
ARROW2 = (121, 192, 255, 255)


def lerp(a, b, t):
    return a + (b - a) * t


def rounded_square_mask(x, y, size, margin, radius):
    ix, iy = x - margin, y - margin
    if ix < 0 or iy < 0 or ix > size or iy > size:
        return 0.0
    cx = min(max(ix, radius), size - radius)
    cy = min(max(iy, radius), size - radius)
    dx, dy = ix - cx, iy - cy
    d = (dx * dx + dy * dy) ** 0.5
    if d <= radius - 1:
        return 1.0
    if d <= radius:
        return radius - d
    return 0.0


def in_tri(px, py, a, b, c):
    def sign(p1, p2, p3):
        return (p1[0] - p3[0]) * (p2[1] - p3[1]) - (p2[0] - p3[0]) * (p1[1] - p3[1])
    d1, d2, d3 = sign((px, py), a, b), sign((px, py), b, c), sign((px, py), c, a)
    neg = d1 < 0 or d2 < 0 or d3 < 0
    pos = d1 > 0 or d2 > 0 or d3 > 0
    return not (neg and pos)


def draw(size):
    px = [[(0, 0, 0, 0)] * size for _ in range(size)]
    scale = size / SIZE
    margin, radius, bw = 24 * scale, 46 * scale, 5 * scale

    # geometry (in 256-space, scaled)
    ty, by = 104 * scale, 168 * scale          # arrow center lines
    sh_h = 11 * scale                          # half shaft height
    # right arrow (top): shaft 64..168, head tip 196
    r_shaft = (64 * scale, 172 * scale)
    r_tip = (198 * scale, ty)
    # left arrow (bottom): shaft 84..192, head tip 58
    l_shaft = (84 * scale, 192 * scale)
    l_tip = (58 * scale, by)

    for y in range(size):
        for x in range(size):
            m = rounded_square_mask(x + 0.5, y + 0.5, size - 2 * margin, 0, radius)
            if m <= 0:
                continue
            # border ring
            m2 = rounded_square_mask(x + 0.5, y + 0.5, size - 2 * margin, 0, radius - bw)
            ring = m2 < 1.0 and m > 0
            if ring:
                c = BORDER
            else:
                c = BG
                # top arrow →
                if (abs(y + 0.5 - ty) <= sh_h and r_shaft[0] <= x <= r_shaft[1]) or \
                   in_tri(x + 0.5, y + 0.5, (172 * scale, ty - 26 * scale),
                          (172 * scale, ty + 26 * scale), r_tip):
                    c = ARROW
                # bottom arrow ←
                elif (abs(y + 0.5 - by) <= sh_h and l_shaft[0] <= x <= l_shaft[1]) or \
                        in_tri(x + 0.5, y + 0.5, (84 * scale, by - 26 * scale),
                               (84 * scale, by + 26 * scale), l_tip):
                    c = ARROW2
            r, g, b, a = c
            if m < 1.0:
                a = int(a * m)
            px[y][x] = (r, g, b, a)
    return px


def png_encode(px):
    size = len(px)
    raw = b"".join(b"\x00" + bytes(v for p in row for v in p) for row in px)

    def chunk(tag, data):
        c = tag + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c))

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(raw, 9))
            + chunk(b"IEND", b""))


def downscale(px, size):
    src = len(px)
    step = src / size
    return [[px[int((y + 0.5) * step) - 1][int((x + 0.5) * step) - 1]
             for x in range(size)] for y in range(size)]


def ico_encode(images):
    # images: list of (size, png_bytes)
    n = len(images)
    out = struct.pack("<HHH", 0, 1, n)
    offset = 6 + 16 * n
    for size, data in images:
        w = 0 if size >= 256 else size
        out += struct.pack("<BBBBHHII", w, w, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
    for _, data in images:
        out += data
    return out


def main():
    here = Path(__file__).resolve().parent.parent
    pkg_assets = here / "usbferry" / "assets"   # ships inside the package
    repo_assets = here / "assets"               # build-time only (pyinstaller --icon)
    pkg_assets.mkdir(exist_ok=True)
    repo_assets.mkdir(exist_ok=True)
    big = draw(SIZE)
    images = [(SIZE, png_encode(big))]
    for s in (48, 32, 16):
        images.append((s, png_encode(downscale(big, s))))
    ico = ico_encode(images)
    (repo_assets / "usbferry.ico").write_bytes(ico)
    (pkg_assets / "usbferry.ico").write_bytes(ico)
    (pkg_assets / "icon.png").write_bytes(images[0][1])
    (pkg_assets / "favicon.png").write_bytes(png_encode(downscale(big, 32)))
    for f in sorted(pkg_assets.iterdir()):
        print("wrote", f, f.stat().st_size, "bytes")
    print("wrote", repo_assets / "usbferry.ico")


if __name__ == "__main__":
    main()
