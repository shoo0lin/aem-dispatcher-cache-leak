#!/usr/bin/env python3
"""
render_media.py — turns a terminal transcript into the stills and the clip used in
the write-up. Kept in the repository so the media is reproducible and its provenance
is not a mystery.

    python3 lab/reproduce.py > evidence/lab-run.txt
    python3 tools/render_media.py --transcript evidence/lab-run.txt --out ../shoo0lin.github.io/assets/img/aem

Fonts: JetBrains Mono if present, DejaVu Sans Mono otherwise. Requires Pillow and
ffmpeg for the clip; the stills only need Pillow.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

BG = (11, 13, 18)
PANEL = (20, 24, 33)
BAR = (16, 19, 26)
LINE = (38, 44, 58)
TEXT = (231, 227, 217)
MUTED = (154, 163, 178)
FAINT = (107, 116, 132)
AMBER = (240, 180, 41)
TEAL = (87, 194, 180)
RED = (229, 83, 75)
BLUE = (122, 162, 247)

WIDTH = 1500
FONT_SIZE = 30
LINE_H = 46
PAD_X = 56
PAD_Y = 34
TITLE_H = 54
FOOTER_H = 46

FONT_CANDIDATES = [
    "/usr/share/fonts/TTF/JetBrainsMonoNerdFont-Regular.ttf",
    "/usr/share/fonts/TTF/JetBrainsMonoNLNerdFont-Regular.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
]
BOLD_CANDIDATES = [
    "/usr/share/fonts/TTF/JetBrainsMonoNerdFont-Bold.ttf",
    "/usr/share/fonts/TTF/JetBrainsMonoNLNerdFont-Bold.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
]


def _font(paths, size):
    for p in paths:
        if os.path.exists(p):
            return ImageFont.truetype(p, size)
    return ImageFont.load_default()


REG = _font(FONT_CANDIDATES, FONT_SIZE)
BOLD = _font(BOLD_CANDIDATES, FONT_SIZE)


def wrap_line(line: str, max_chars: int) -> list[str]:
    if len(line) <= max_chars:
        return [line]
    indent = " " * 4
    parts = textwrap.wrap(line, width=max_chars, subsequent_indent=indent,
                          break_long_words=True, break_on_hyphens=False)
    return parts or [line]


def style_line(line: str):
    """Return (colour, font, text) for one physical line — a tiny highlighter."""
    s = line.rstrip("\n")
    stripped = s.strip()

    if stripped.startswith("RESULT: VULNERABLE"):
        return RED, BOLD, s
    if stripped.startswith("RESULT: FIXED"):
        return TEAL, BOLD, s
    if stripped.startswith("RESULT:"):
        return AMBER, BOLD, s
    if stripped.startswith("mode:"):
        return AMBER, BOLD, s
    if stripped.startswith(("origin:", "run:", "targets:", "path:", "started:", "summary:")):
        return FAINT, REG, s
    if stripped.startswith("[") and "]" in stripped:
        return AMBER, BOLD, s
    if stripped.startswith("$"):
        return AMBER, REG, s
    if set(stripped) <= set("-") and len(stripped) > 8:
        return LINE, REG, s
    if "-> 200" in s:
        return RED, REG, s
    if "-> 302" in s or "-> 401" in s:
        return TEAL, REG, s
    if "cache=HIT" in s:
        return RED, REG, s
    if "cache=MISS" in s or "cache=BYPASS" in s:
        return MUTED, REG, s
    if stripped.startswith(("GET ", "identity:")):
        return MUTED, REG, s
    if stripped.startswith("verdict:"):
        return (RED if "VULNERABLE" in s else TEAL), BOLD, s
    if stripped.startswith(("body:", "note:")):
        return FAINT, REG, s
    return TEXT, REG, s


def draw_frame(lines: list[str], title: str, footer: str, visible: int | None = None,
               cursor: bool = False, window: int | None = None) -> Image.Image:
    wrapped: list[tuple[str, tuple[int, int, int], ImageFont.FreeTypeFont]] = []
    max_chars = int((WIDTH - 2 * PAD_X - 40) / (FONT_SIZE * 0.6))
    for raw in lines:
        colour, font, text = style_line(raw)
        for part in wrap_line(text, max_chars):
            wrapped.append((part, colour, font))

    show = wrapped if visible is None else wrapped[:visible]
    if window is not None:
        show = show[-window:]
        height = TITLE_H + PAD_Y + window * LINE_H + PAD_Y + FOOTER_H
    else:
        height = TITLE_H + PAD_Y + len(wrapped) * LINE_H + PAD_Y + FOOTER_H
    img = Image.new("RGB", (WIDTH, height), BG)
    d = ImageDraw.Draw(img)

    # title bar
    d.rectangle([0, 0, WIDTH, TITLE_H], fill=BAR)
    d.line([0, TITLE_H, WIDTH, TITLE_H], fill=LINE, width=1)
    for i, c in enumerate(((255, 95, 86), (255, 189, 46), (39, 201, 63))):
        cx = 26 + i * 26
        d.ellipse([cx - 6, TITLE_H // 2 - 6, cx + 6, TITLE_H // 2 + 6], fill=c)
    d.text((120, TITLE_H // 2), title, font=_font(FONT_CANDIDATES, 20), fill=FAINT,
           anchor="lm")

    # body
    y = TITLE_H + PAD_Y
    for text, colour, font in show:
        d.text((PAD_X, y), text, font=font, fill=colour)
        y += LINE_H

    if cursor:
        w = d.textlength("█", font=REG)
        d.rectangle([PAD_X, y + 4, PAD_X + w * 0.55, y + LINE_H - 4], fill=AMBER)

    # footer
    fy = height - FOOTER_H
    d.line([0, fy, WIDTH, fy], fill=LINE, width=1)
    d.text((PAD_X, fy + FOOTER_H // 2), footer, font=_font(FONT_CANDIDATES, 17),
           fill=FAINT, anchor="lm")
    return img


def split_sections(text: str):
    """Split the reproduction transcript into the three stills we publish."""
    lines = text.splitlines()
    i_control = next(i for i, l in enumerate(lines) if l.startswith("[2]"))
    i_result = next(i for i, l in enumerate(lines) if l.startswith("RESULT:"))
    i_patched = next(i for i, l in enumerate(lines) if l.startswith("mode: patched"))
    return {
        "cache-hit": lines[:i_control],
        "cache-miss": lines[i_control:i_result],
        "patched": lines[i_patched:],
    }


def render_stills(sections, out_dir: Path):
    footers = {
        "cache-hit": "local lab · anonymous client reads a session's identity · no customer system contacted",
        "cache-miss": "local lab · the query string changes the cache key, so the origin is asked and refuses",
        "patched": "local lab · deny rule for /libs/granite/security/* · no cache entry is created",
    }
    titles = {
        "cache-hit": "aem-dispatcher-cache — lab · vulnerable",
        "cache-miss": "aem-dispatcher-cache — lab · controls",
        "patched": "aem-dispatcher-cache — lab · patched",
    }
    names = {"cache-hit": "01-cache-hit.png", "cache-miss": "02-cache-miss.png",
             "patched": "03-patched.png"}
    out_dir.mkdir(parents=True, exist_ok=True)
    for key, lines in sections.items():
        img = draw_frame(lines, titles[key], footers[key])
        img.save(out_dir / names[key], optimize=True)
        print("wrote", out_dir / names[key], img.size)


def draw_fleet(out_dir: Path):
    """The field table, rendered as a card rather than a terminal dump."""
    rows = [
        ("author-<customer-a>-65a", "production", "dispatcher1uswest2", "~20 mo"),
        ("author-<customer-b>-65-prod", "production", "dispatcher2useast1", "~9 mo"),
        ("author-<customer-b>-65-preprod", "pre-production", "dispatcher2useast1", "~9 mo"),
        ("author-<customer-b>-65-dev", "development", "dispatcher1useast1", "~20 mo"),
        ("author-<customer-b>-65a-qa", "qa", "dispatcher1useast1", "~21 mo"),
    ]
    cols = [("host", 640), ("env", 250), ("dispatcher", 330), ("age", 160)]
    width, height = WIDTH, 640
    img = Image.new("RGB", (width, height), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, width, TITLE_H], fill=BAR)
    d.line([0, TITLE_H, width, TITLE_H], fill=LINE, width=1)
    for i, c in enumerate(((255, 95, 86), (255, 189, 46), (39, 201, 63))):
        cx = 26 + i * 26
        d.ellipse([cx - 6, TITLE_H // 2 - 6, cx + 6, TITLE_H // 2 + 6], fill=c)
    d.text((120, TITLE_H // 2), "field capture — five hosts, two customers", font=_font(FONT_CANDIDATES, 20),
           fill=FAINT, anchor="lm")

    x0, y0 = PAD_X, TITLE_H + 40
    header_font = _font(BOLD_CANDIDATES, 20)
    body_font = _font(FONT_CANDIDATES, 22)
    x = x0
    for name, w in cols:
        d.text((x, y0), name.upper(), font=header_font, fill=FAINT)
        x += w
    d.line([x0, y0 + 34, width - PAD_X, y0 + 34], fill=LINE, width=1)

    y = y0 + 58
    for host, env, disp, age in rows:
        d.text((x0, y), host, font=body_font, fill=TEXT)
        d.text((x0 + 640, y), env, font=body_font, fill=MUTED)
        d.text((x0 + 890, y), disp, font=body_font, fill=MUTED)
        d.text((x0 + 1220, y), age, font=body_font, fill=RED)
        y += 54
        d.line([x0, y - 12, width - PAD_X, y - 12], fill=(30, 35, 46), width=1)

    d.text((x0, y + 18),
           "cache ages at capture, 2026-06-30 · identities and instance suffixes redacted",
           font=_font(FONT_CANDIDATES, 18), fill=FAINT)
    d.text((x0, y + 52),
           "4 dispatcher instances · 2 AWS regions · 4 environments · still live 2026-10-29",
           font=_font(FONT_CANDIDATES, 18), fill=FAINT)

    path = out_dir / "04-field-fleet.png"
    img.save(path, optimize=True)
    print("wrote", path, img.size)


def render_video(lines, out_dir: Path, per_line=0.42, hold=5.0):
    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg:
        print("ffmpeg not found — skipping the clip", file=sys.stderr)
        return

    title = "aem-dispatcher-cache — lab · reproduced"
    footer = "local lab · mock AEM origin + dispatcher · no customer system contacted"
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        wrapped_total = 0
        max_chars = int((WIDTH - 2 * PAD_X - 40) / (FONT_SIZE * 0.6))
        for raw in lines:
            wrapped_total += len(wrap_line(style_line(raw)[2], max_chars))

        frames = []
        # reveal line by line, then hold on the finished frame
        step = max(1, wrapped_total // 90)
        window = 20
        for i in range(1, wrapped_total + 1, step):
            img = draw_frame(lines, title, footer, visible=i, cursor=True, window=window)
            p = tmp / f"f{len(frames):04d}.png"
            img.save(p)
            frames.append(p)
        final = draw_frame(lines, title, footer, visible=None, window=window)
        final_path = tmp / "final.png"
        final.save(final_path)
        frames.append(final_path)

        listing = tmp / "list.txt"
        with listing.open("w") as fh:
            for i, p in enumerate(frames):
                fh.write(f"file '{p}'\n")
                fh.write(f"duration {hold if i == len(frames) - 1 else per_line}\n")
            fh.write(f"file '{frames[-1]}'\n")

        out = out_dir / "demo-cache-leak.mp4"
        subprocess.run([
            ffmpeg, "-y", "-loglevel", "error",
            "-f", "concat", "-safe", "0", "-i", str(listing),
            "-vf", "fps=30,format=yuv420p",
            "-c:v", "libx264", "-preset", "slow", "-crf", "22",
            "-movflags", "+faststart", str(out),
        ], check=True)
        print("wrote", out)

        poster = out_dir / "demo-poster.jpg"
        final.convert("RGB").save(poster, quality=88, optimize=True)
        print("wrote", poster)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--transcript", required=True)
    ap.add_argument("--out", required=True, help="output directory for the media")
    args = ap.parse_args()

    text = Path(args.transcript).read_text(encoding="utf-8")
    sections = split_sections(text)
    out_dir = Path(args.out)
    render_stills(sections, out_dir)
    draw_fleet(out_dir)
    render_video(text.splitlines(), out_dir)


if __name__ == "__main__":
    main()
