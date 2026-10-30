#!/usr/bin/env python3
"""Generates modern high-resolution application icons for IOC Workbench.

Creates:
- assets/icon_1024.png, assets/icon_512.png, assets/icon.png
- assets/icon.ico  (multi-resolution Windows icon)
- assets/icon.icns (Apple Icon Image for macOS via iconutil)
"""

from __future__ import annotations

import math
import os
from pathlib import Path
import shutil
import subprocess
import sys

from PIL import Image, ImageDraw, ImageFilter

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ASSETS_DIR = PROJECT_ROOT / "assets"


def draw_master_icon(size: int = 1024) -> Image.Image:
    """Draws a crisp, modern blue-and-white security shield icon at the given size."""
    # Render at 2x resolution with supersampling for smooth subpixel edges
    scale = 2
    dim = size * scale
    img = Image.new("RGBA", (dim, dim), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    pad = int(dim * 0.08)
    rect = [pad, pad, dim - pad, dim - pad]
    radius = int(dim * 0.22)

    # 1. Soft ambient shadow behind squircle
    shadow_pad = pad + int(dim * 0.02)
    shadow_img = Image.new("RGBA", (dim, dim), (0, 0, 0, 0))
    s_draw = ImageDraw.Draw(shadow_img)
    s_draw.rounded_rectangle(
        [shadow_pad, shadow_pad + int(dim * 0.03), dim - shadow_pad, dim - shadow_pad + int(dim * 0.03)],
        radius=radius,
        fill=(11, 31, 75, 140),
    )
    shadow_img = shadow_img.filter(ImageFilter.GaussianBlur(int(dim * 0.04)))
    img = Image.alpha_composite(img, shadow_img)
    draw = ImageDraw.Draw(img)

    # 2. Base Squircle with rich vertical gradient (Royal Blue #2563EB to Deep Navy #0B1F4B)
    squircle_mask = Image.new("L", (dim, dim), 0)
    m_draw = ImageDraw.Draw(squircle_mask)
    m_draw.rounded_rectangle(rect, radius=radius, fill=255)

    gradient = Image.new("RGBA", (dim, dim), (0, 0, 0, 0))
    g_draw = ImageDraw.Draw(gradient)
    top_color = (37, 99, 235)      # #2563EB
    mid_color = (29, 78, 216)      # #1D4ED8
    bot_color = (11, 31, 75)       # #0B1F4B
    
    y0, y1 = rect[1], rect[3]
    h = y1 - y0
    for y in range(y0, y1):
        ratio = (y - y0) / float(h)
        if ratio < 0.5:
            t = ratio / 0.5
            r = int(top_color[0] + (mid_color[0] - top_color[0]) * t)
            g = int(top_color[1] + (mid_color[1] - top_color[1]) * t)
            b = int(top_color[2] + (mid_color[2] - top_color[2]) * t)
        else:
            t = (ratio - 0.5) / 0.5
            r = int(mid_color[0] + (bot_color[0] - mid_color[0]) * t)
            g = int(mid_color[1] + (bot_color[1] - mid_color[1]) * t)
            b = int(mid_color[2] + (bot_color[2] - mid_color[2]) * t)
        g_draw.line([(rect[0], y), (rect[2], y)], fill=(r, g, b, 255))

    gradient.putalpha(squircle_mask)
    img = Image.alpha_composite(img, gradient)
    draw = ImageDraw.Draw(img)

    # 3. Inner border rim specular highlight
    draw.rounded_rectangle(
        rect,
        radius=radius,
        outline=(255, 255, 255, 60),
        width=int(dim * 0.008),
    )

    # 4. Subtle cyber grid / radar arcs in background
    cx, cy = dim // 2, int(dim * 0.49)
    radar_color = (255, 255, 255, 22)
    for r_arc in [int(dim * 0.22), int(dim * 0.33)]:
        draw.arc(
            [cx - r_arc, cy - r_arc, cx + r_arc, cy + r_arc],
            start=210,
            end=330,
            fill=radar_color,
            width=int(dim * 0.006),
        )

    # 5. Shield Geometry
    # Center shield
    sw = int(dim * 0.46)  # shield width
    sh = int(dim * 0.56)  # shield height
    sx = cx
    sy = int(dim * 0.25)

    # Points for classic security shield
    shield_pts = [
        (sx - sw // 2, sy),
        (sx + sw // 2, sy),
        (sx + sw // 2, sy + int(sh * 0.46)),
        (sx, sy + sh),
        (sx - sw // 2, sy + int(sh * 0.46)),
    ]

    # Shield soft shadow
    sh_shadow = Image.new("RGBA", (dim, dim), (0, 0, 0, 0))
    sh_s_draw = ImageDraw.Draw(sh_shadow)
    sh_s_draw.polygon(
        [(p[0], p[1] + int(dim * 0.02)) for p in shield_pts],
        fill=(0, 0, 0, 100),
    )
    sh_shadow = sh_shadow.filter(ImageFilter.GaussianBlur(int(dim * 0.03)))
    img = Image.alpha_composite(img, sh_shadow)
    draw = ImageDraw.Draw(img)

    # Shield outer body (Pure White with subtle silver-blue sheen)
    draw.polygon(shield_pts, fill=(255, 255, 255, 255))
    # Beveled rim
    draw.polygon(shield_pts, outline=(226, 232, 240, 255), width=int(dim * 0.01))

    # Inner shield emblem (Deep Cyber Navy & Blue)
    in_margin = int(dim * 0.038)
    in_pts = [
        (shield_pts[0][0] + in_margin, shield_pts[0][1] + in_margin),
        (shield_pts[1][0] - in_margin, shield_pts[1][1] + in_margin),
        (shield_pts[2][0] - in_margin, shield_pts[2][1] - int(in_margin * 0.4)),
        (shield_pts[3][0], shield_pts[3][1] - in_margin),
        (shield_pts[4][0] + in_margin, shield_pts[4][1] - int(in_margin * 0.4)),
    ]

    # Inner shield gradient (Dark Sapphire to Electric Blue)
    in_mask = Image.new("L", (dim, dim), 0)
    in_m_draw = ImageDraw.Draw(in_mask)
    in_m_draw.polygon(in_pts, fill=255)

    in_grad = Image.new("RGBA", (dim, dim), (0, 0, 0, 0))
    in_g_draw = ImageDraw.Draw(in_grad)
    iy0, iy1 = in_pts[0][1], in_pts[3][1]
    ih = iy1 - iy0
    for y in range(iy0, iy1):
        t = (y - iy0) / float(max(1, ih))
        # from #0F172A (dark slate) to #1E3A8A (deep navy blue)
        r = int(15 + (30 - 15) * t)
        g = int(23 + (58 - 23) * t)
        b = int(42 + (138 - 42) * t)
        in_g_draw.line([(in_pts[0][0], y), (in_pts[1][0], y)], fill=(r, g, b, 255))
    in_grad.putalpha(in_mask)
    img = Image.alpha_composite(img, in_grad)
    draw = ImageDraw.Draw(img)

    # 6. Center Emblem: Threat Intelligence Radar & Verified Checkmark
    # High-tech concentric search crosshair
    center_y = int(sy + sh * 0.42)
    radius_ring = int(dim * 0.12)
    draw.ellipse(
        [cx - radius_ring, center_y - radius_ring, cx + radius_ring, center_y + radius_ring],
        outline=(56, 189, 248, 80),  # Cyan glow
        width=int(dim * 0.008),
    )

    # Verified Checkmark with sharp, bold geometry (Glowing Emerald / Sky Blue accent)
    # Checkmark points
    cp1 = (cx - int(dim * 0.075), center_y + int(dim * 0.005))
    cp2 = (cx - int(dim * 0.02), center_y + int(dim * 0.065))
    cp3 = (cx + int(dim * 0.085), center_y - int(dim * 0.065))

    check_width = int(dim * 0.034)
    # Draw checkmark glow
    draw.line([cp1, cp2, cp3], fill=(56, 189, 248, 120), width=check_width + int(dim * 0.015), joint="round")
    # Draw primary vibrant checkmark (White-cyan bright center)
    draw.line([cp1, cp2, cp3], fill=(255, 255, 255, 255), width=check_width, joint="round")
    draw.line([cp1, cp2, cp3], fill=(56, 189, 248, 255), width=int(check_width * 0.7), joint="round")
    draw.line([cp1, cp2, cp3], fill=(255, 255, 255, 255), width=int(check_width * 0.35), joint="round")

    # 7. Downsample with high-quality Lanczos resampling
    final_img = img.resize((size, size), Image.Resampling.LANCZOS)
    return final_img


def build_icns(master_img: Image.Image, output_icns: Path) -> bool:
    """Uses macOS iconutil to construct a native Apple .icns file."""
    iconset_dir = ASSETS_DIR / "icon.iconset"
    if iconset_dir.exists():
        shutil.rmtree(iconset_dir)
    iconset_dir.mkdir(parents=True, exist_ok=True)

    sizes = [
        (16, "icon_16x16.png"),
        (32, "icon_16x16@2x.png"),
        (32, "icon_32x32.png"),
        (64, "icon_32x32@2x.png"),
        (128, "icon_128x128.png"),
        (256, "icon_128x128@2x.png"),
        (256, "icon_256x256.png"),
        (512, "icon_256x256@2x.png"),
        (512, "icon_512x512.png"),
        (1024, "icon_512x512@2x.png"),
    ]

    for s, name in sizes:
        resized = master_img.resize((s, s), Image.Resampling.LANCZOS)
        resized.save(iconset_dir / name, format="PNG")

    if output_icns.exists():
        output_icns.unlink()

    if shutil.which("iconutil"):
        res = subprocess.run(
            ["iconutil", "-c", "icns", str(iconset_dir), "-o", str(output_icns)],
            capture_output=True,
            text=True,
        )
        shutil.rmtree(iconset_dir, ignore_errors=True)
        return res.returncode == 0 and output_icns.is_file()

    shutil.rmtree(iconset_dir, ignore_errors=True)
    return False


def build_ico(master_img: Image.Image, output_ico: Path) -> None:
    """Creates a Windows multi-resolution .ico icon containing standard sizes."""
    sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    master_img.save(output_ico, format="ICO", sizes=sizes)


def main() -> int:
    ASSETS_DIR.mkdir(parents=True, exist_ok=True)
    print("Generating master application icon (1024x1024)...")
    master = draw_master_icon(1024)

    png_1024 = ASSETS_DIR / "icon_1024.png"
    png_512 = ASSETS_DIR / "icon_512.png"
    png_default = ASSETS_DIR / "icon.png"

    master.save(png_1024, format="PNG")
    master.resize((512, 512), Image.Resampling.LANCZOS).save(png_512, format="PNG")
    master.resize((256, 256), Image.Resampling.LANCZOS).save(png_default, format="PNG")

    print(f"  Saved PNG icons to {ASSETS_DIR}")

    ico_path = ASSETS_DIR / "icon.ico"
    build_ico(master, ico_path)
    print(f"  Saved Windows icon to {ico_path}")

    icns_path = ASSETS_DIR / "icon.icns"
    if build_icns(master, icns_path):
        print(f"  Saved macOS icon to {icns_path}")
    else:
        print("  Notice: iconutil not available or failed; skipping .icns")

    print("All application icons generated successfully!")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
