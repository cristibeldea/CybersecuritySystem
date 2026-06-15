"""Etapa 9: suprapunere de watermark diagonal si grila de linii subtiri."""
import numpy as np
from PIL import Image, ImageDraw, ImageFont

def watermark_overlay(img: np.ndarray, opacity: float = 0.13,
                      line_opacity: float = 0.10) -> np.ndarray:
    h, w = img.shape[:2]
    rng = np.random.default_rng()

    text = "CAPTCHA"
    diag = int(np.sqrt(h ** 2 + w ** 2))
    canvas = Image.new("L", (diag, diag), 0)
    draw = ImageDraw.Draw(canvas)

    try:
        font = ImageFont.truetype("arial.ttf", max(18, min(h, w) // 10))
    except Exception:
        font = ImageFont.load_default()

    bbox = draw.textbbox((0, 0), text, font=font)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]

    spacing_x = tw + max(30, tw // 2)
    spacing_y = th + max(40, th)
    for ty in range(0, diag, spacing_y):
        for tx in range(0, diag, spacing_x):
            draw.text((tx, ty), text, fill=255, font=font)

    angle = rng.uniform(30, 40) * rng.choice([-1, 1])
    canvas = canvas.rotate(angle, resample=Image.BILINEAR, expand=False)

    cx, cy = canvas.width // 2, canvas.height // 2
    text_layer = np.asarray(canvas.crop((
        cx - w // 2, cy - h // 2,
        cx - w // 2 + w, cy - h // 2 + h
    ))).astype(np.float32) / 255.0

    if text_layer.shape[0] != h or text_layer.shape[1] != w:
        text_pil = Image.fromarray((text_layer * 255).astype(np.uint8))
        text_pil = text_pil.resize((w, h), Image.BILINEAR)
        text_layer = np.asarray(text_pil).astype(np.float32) / 255.0

    line_canvas = Image.new("L", (w, h), 0)
    line_draw = ImageDraw.Draw(line_canvas)

    num_lines = rng.integers(10, 14)
    for _ in range(num_lines):
        side_start = rng.integers(0, 4)
        side_end = (side_start + rng.integers(1, 3)) % 4

        def edge_point(side):
            if side == 0:    return (rng.integers(0, w), 0)
            elif side == 1:  return (w - 1, rng.integers(0, h))
            elif side == 2:  return (rng.integers(0, w), h - 1)
            else:            return (0, rng.integers(0, h))

        p1 = edge_point(side_start)
        p2 = edge_point(side_end)
        line_draw.line([p1, p2], fill=255, width=1)

    line_layer = np.asarray(line_canvas).astype(np.float32) / 255.0

    result = img.astype(np.float32)
    wm = text_layer * opacity + line_layer * line_opacity
    if img.ndim == 3:
        wm = wm[:, :, np.newaxis]
    result = result * (1.0 - wm) + 255.0 * wm

    return np.clip(result, 0, 255).astype(np.uint8)
