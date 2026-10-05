"""Render the hackable demo video from a real captured scan (--color=always).

Frames -> ffmpeg -> mp4. Everything on screen is genuine scanner output.
"""

import os
import re
import subprocess

from PIL import Image, ImageDraw, ImageFont

RAW = "/tmp/demo_raw.txt"
OUTDIR = "/tmp/demo_frames"
MP4 = "/home/hatch/workspace/hackable/demo/hackable-demo.mp4"

W, H = 1280, 720
BG = (13, 17, 23)
FG = (230, 237, 243)
DIM = (138, 143, 152)
GREEN = (63, 185, 80)
RED = (255, 85, 85)
RED2 = (255, 123, 114)
YELLOW = (241, 196, 15)
BLUE = (90, 169, 255)

FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
FONTB = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
FS = 19
LH = 24

ANSI_RE = re.compile(r"\x1b\[([0-9;]*)m")


def parse_line(line):
    """Split a line into (text, color, bold) segments."""
    segs = []
    color, bold, dim = FG, False, False
    pos = 0
    for m in ANSI_RE.finditer(line):
        if m.start() > pos:
            segs.append((line[pos:m.start()], color, bold, dim))
        codes = [c for c in m.group(1).split(";") if c != ""]
        if not codes or codes == ["0"]:
            color, bold, dim = FG, False, False
        else:
            for c in codes:
                if c == "1":
                    bold = True
                elif c == "2":
                    dim = True
                elif c == "31":
                    color = RED2
                elif c == "33":
                    color = YELLOW
                elif c == "34":
                    color = BLUE
                elif c == "90":
                    color = DIM
        pos = m.end()
    if pos < len(line):
        segs.append((line[pos:], color, bold, dim))
    out = []
    for text, color, bold, dim in segs:
        if dim:
            color = DIM
        if bold and color == FG:
            color = (255, 255, 255)
        if bold and color == RED2:
            color = RED
        out.append((text, color, bold))
    return out


def wrap_segments(segs, font, max_w):
    """Wrap segments into lines of (text, color, bold) not exceeding max_w."""
    lines, cur, cur_w = [], [], 0
    for text, color, bold in segs:
        f = ImageFont.truetype(FONTB if bold else FONT, FS)
        for word in re.split(r"(\s+)", text):
            if not word:
                continue
            w = f.getlength(word)
            if cur_w + w > max_w and cur:
                lines.append(cur)
                cur, cur_w = [], 0
                if word.strip() == "":
                    continue
            cur.append((word, color, bold))
            cur_w += w
    if cur:
        lines.append(cur)
    return lines


def draw_card(draw, lines, y0=0, x0=60, big=False):
    y = y0
    for text, color, bold in lines:
        f = ImageFont.truetype(FONTB if bold else FONT, 34 if big else FS)
        draw.text((x0, y), text, font=f, fill=color)
        y += 52 if big else LH + 6
    return y


frames = []
n = 0


def main():
    global n
    os.makedirs(OUTDIR, exist_ok=True)
    with open(RAW) as fh:
        raw_lines = [ln.rstrip("\n") for ln in fh]

    # Build wrapped terminal lines: list of segment-lists
    term_lines = []
    for ln in raw_lines:
        if ln.strip() == "":
            term_lines.append([])
            continue
        segs = parse_line(ln)
        f = ImageFont.truetype(FONT, FS)
        wrapped = wrap_segments(segs, f, W - 80)
        term_lines.extend(wrapped if wrapped else [[]])

    frames = []
    n = 0

    def new_frame():
        global n
        img = Image.new("RGB", (W, H), BG)
        n += 1
        path = os.path.join(OUTDIR, "f_%04d.png" % n)
        frames.append(path)
        return img, path

    def save(img, path):
        img.save(path)

    # 1. Title card
    for _ in range(24):  # 2s @ 12fps
        img, path = new_frame()
        d = ImageDraw.Draw(img)
        y = 250
        y = draw_card(d, [("I built a shop app with AI in a weekend.", FG, True)], y, big=True)
        draw_card(d, [("I have no idea if it's secure. Let's find out.", DIM, False)], y + 10)
        save(img, path)

    # 2. Type the command
    cmd = "$ hackable --yes http://127.0.0.1:5000"
    for i in range(1, len(cmd) + 1, 2):
        img, path = new_frame()
        d = ImageDraw.Draw(img)
        f = ImageFont.truetype(FONT, FS)
        d.text((40, 40), "$", font=f, fill=GREEN)
        d.text((60, 40), cmd[2:i], font=f, fill=FG)
        save(img, path)
    # hold full command briefly
    for _ in range(6):
        img, path = new_frame()
        d = ImageDraw.Draw(img)
        f = ImageFont.truetype(FONT, FS)
        d.text((40, 40), "$", font=f, fill=GREEN)
        d.text((60, 40), cmd[2:], font=f, fill=FG)
        save(img, path)

    # 3. Play the scan output (sliding window, 2 lines per frame)
    VISIBLE = 26
    shown = []  # terminal segment-lines already revealed
    idx = 0
    prompt_lines = [[("$", GREEN, True), (" hackable --yes http://127.0.0.1:5000", FG, False)]]
    while idx < len(term_lines):
        for _ in range(2):
            if idx < len(term_lines):
                shown.append(term_lines[idx])
                idx += 1
        window = (prompt_lines + shown)[-VISIBLE:]
        img, path = new_frame()
        d = ImageDraw.Draw(img)
        y = 36
        for segs in window:
            x = 40
            for text, color, bold in segs:
                f = ImageFont.truetype(FONTB if bold else FONT, FS)
                d.text((x, y), text, font=f, fill=color)
                x += f.getlength(text)
            y += LH
        save(img, path)

    # 4. Hold the final score
    for _ in range(36):  # 3s
        window = (prompt_lines + shown)[-VISIBLE:]
        img, path = new_frame()
        d = ImageDraw.Draw(img)
        y = 36
        for segs in window:
            x = 40
            for text, color, bold in segs:
                f = ImageFont.truetype(FONTB if bold else FONT, FS)
                d.text((x, y), text, font=f, fill=color)
                x += f.getlength(text)
            y += LH
        save(img, path)

    # 5. End card
    for _ in range(30):
        img, path = new_frame()
        d = ImageDraw.Draw(img)
        y = 250
        y = draw_card(d, [("hackable", FG, True)], y, big=True)
        y = draw_card(d, [("hack yourself before they do.", DIM, False)], y + 8)
        draw_card(d, [("pip install hackable", GREEN, True)], y + 20)
        save(img, path)

    print("rendered %d frames" % len(frames))
    subprocess.run(
        ["ffmpeg", "-y", "-framerate", "12", "-i", os.path.join(OUTDIR, "f_%04d.png"),
         "-c:v", "libx264", "-pix_fmt", "yuv420p", "-crf", "20", MP4],
        check=True, capture_output=True,
    )
    print("wrote", MP4, os.path.getsize(MP4), "bytes")


if __name__ == "__main__":
    main()
