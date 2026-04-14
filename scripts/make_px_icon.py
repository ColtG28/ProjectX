#!/usr/bin/env python3
import math
import os
import struct
import sys
import zlib


BACKGROUND = (17, 80, 63, 255)
ACCENT = (228, 117, 49, 255)
LIGHT = (245, 239, 225, 255)
SHADOW = (12, 42, 34, 255)


def set_pixel(buf, size, x, y, color):
    index = (y * size + x) * 4
    buf[index:index + 4] = bytes(color)


def fill_rect(buf, size, x, y, width, height, color):
    for yy in range(y, y + height):
        for xx in range(x, x + width):
            set_pixel(buf, size, xx, yy, color)


def fill_circle(buf, size, cx, cy, radius, color):
    radius_sq = radius * radius
    for yy in range(max(0, cy - radius), min(size, cy + radius + 1)):
        for xx in range(max(0, cx - radius), min(size, cx + radius + 1)):
            dx = xx - cx
            dy = yy - cy
            if dx * dx + dy * dy <= radius_sq:
                set_pixel(buf, size, xx, yy, color)


def fill_rounded_rect(buf, size, x, y, width, height, radius, color):
    radius_sq = radius * radius
    for yy in range(y, y + height):
        for xx in range(x, x + width):
            local_x = xx - x
            local_y = yy - y
            dx = 0
            dy = 0
            if local_x < radius:
                dx = radius - local_x
            elif local_x >= width - radius:
                dx = local_x - (width - radius - 1)
            if local_y < radius:
                dy = radius - local_y
            elif local_y >= height - radius:
                dy = local_y - (height - radius - 1)
            if dx == 0 or dy == 0 or dx * dx + dy * dy <= radius_sq:
                set_pixel(buf, size, xx, yy, color)


def draw_p(buf, size, x, y, width, height, color):
    stroke = max(2, size // 13)
    fill_rect(buf, size, x, y, stroke, height, color)
    fill_rect(buf, size, x, y, width, stroke, color)
    fill_rect(buf, size, x, y + height // 2 - stroke // 2, width - stroke // 3, stroke, color)
    fill_rect(buf, size, x + width - stroke, y + stroke, stroke, height // 2 - stroke, color)


def draw_x(buf, size, x, y, width, height, color):
    thickness = max(2, size // 26)
    slope = (width - 1) / max(1, height - 1)
    for yy in range(height):
        left = yy * slope
        right = (width - 1) - left
        for xx in range(width):
            if abs(xx - left) <= thickness or abs(xx - right) <= thickness:
                set_pixel(buf, size, x + xx, y + yy, color)


def render_icon(size):
    buf = bytearray(size * size * 4)
    fill_rounded_rect(buf, size, 0, 0, size, size, max(6, size // 5), BACKGROUND)
    fill_circle(buf, size, int(size * 0.8), int(size * 0.22), max(4, size // 6), ACCENT)
    fill_circle(buf, size, int(size * 0.2), int(size * 0.82), max(3, size // 8), SHADOW)
    draw_p(
        buf,
        size,
        int(size * 0.2),
        int(size * 0.18),
        int(size * 0.25),
        int(size * 0.6),
        LIGHT,
    )
    draw_x(
        buf,
        size,
        int(size * 0.56),
        int(size * 0.2),
        int(size * 0.22),
        int(size * 0.58),
        LIGHT,
    )
    return bytes(buf)


def png_chunk(tag, data):
    return (
        struct.pack(">I", len(data))
        + tag
        + data
        + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    )


def write_png(path, size, rgba):
    raw = bytearray()
    stride = size * 4
    for y in range(size):
        raw.append(0)
        start = y * stride
        raw.extend(rgba[start:start + stride])

    png = bytearray(b"\x89PNG\r\n\x1a\n")
    png.extend(png_chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)))
    png.extend(png_chunk(b"IDAT", zlib.compress(bytes(raw), 9)))
    png.extend(png_chunk(b"IEND", b""))
    with open(path, "wb") as handle:
        handle.write(png)


def main():
    if len(sys.argv) != 2:
        print("usage: make_px_icon.py <iconset-dir>", file=sys.stderr)
        return 1

    out_dir = sys.argv[1]
    os.makedirs(out_dir, exist_ok=True)
    sizes = {
        "icon_16x16.png": 16,
        "icon_16x16@2x.png": 32,
        "icon_32x32.png": 32,
        "icon_32x32@2x.png": 64,
        "icon_128x128.png": 128,
        "icon_128x128@2x.png": 256,
        "icon_256x256.png": 256,
        "icon_256x256@2x.png": 512,
        "icon_512x512.png": 512,
        "icon_512x512@2x.png": 1024,
    }

    for name, size in sizes.items():
        write_png(os.path.join(out_dir, name), size, render_icon(size))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
