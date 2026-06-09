#!/usr/bin/env python3
"""
Distortion pipeline for CAPTCHA images.

Reads every image from  CAPTCHA_photos/originals/<category>/*
and CAPTCHA_photos/originals/<category>/fake/*
Writes distorted copies to CAPTCHA_photos/grid/<category>/*
and CAPTCHA_photos/grid/<category>/fake/*
preserving the exact folder hierarchy.

Pipeline (applied in order):
  [1]  Per-channel elastic warp      — each RGB channel warped independently
  [2]  Fourier mid+high band erosion — frequency destruction
  [3]  Patch jitter                  — cut into blocks, randomly offset each
  [4]  Swirl distortion              — local rotational vortex warps
  [5]  Halftone overlay              — dense rotated dot grid
  [6]  Chromatic aberration          — randomised radial RGB shifts
  [7]  Color space rotation          — rotate the RGB cube by a random angle
  [8]  Color jitter                  — random brightness / contrast / saturation
  [9]  Watermark overlay             — diagonal text + thin line grid
  [10] JPEG artifact simulation      — lossy compress → decompress
  [11] FGSM-style perturbation       — gradient-weighted edge noise (last)

Usage:
    python distort.py                  # process all
    python distort.py --category cats  # process one category
"""

import argparse
import io
import os
import sys

import numpy as np
from PIL import Image, ImageFilter

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ORIGINALS_DIR = os.path.join(BASE_DIR, "CAPTCHA_photos", "originals")
GRID_DIR = os.path.join(BASE_DIR, "CAPTCHA_photos", "grid")

IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".bmp", ".gif"}

# ---------------------------------------------------------------------------
# lessDistorted factor: 0.0 = no distortion, 1.0 = same as normal images
# ---------------------------------------------------------------------------
LESS_DISTORTED_FACTOR = 0.5


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _smooth_field(field: np.ndarray, sigma_px: float) -> np.ndarray:
    """Gaussian-smooth a 2D float field using PIL (avoids scipy)."""
    fmin, fmax = field.min(), field.max()
    span = max(fmax - fmin, 1e-6)
    normalized = ((field - fmin) / span * 255).astype(np.uint8)
    pil_img = Image.fromarray(normalized, mode="L")
    radius = max(1, int(sigma_px))
    pil_img = pil_img.filter(ImageFilter.GaussianBlur(radius=radius))
    return np.asarray(pil_img).astype(np.float32) / 255.0 * span + fmin


def _bilinear_remap(img_2d: np.ndarray, map_x: np.ndarray, map_y: np.ndarray) -> np.ndarray:
    """Bilinear interpolation remap for a single 2D array."""
    h, w = img_2d.shape
    map_x = np.clip(map_x, 0, w - 1.001)
    map_y = np.clip(map_y, 0, h - 1.001)
    x0 = np.floor(map_x).astype(np.intp)
    y0 = np.floor(map_y).astype(np.intp)
    x1 = np.minimum(x0 + 1, w - 1)
    y1 = np.minimum(y0 + 1, h - 1)
    wx = map_x - x0
    wy = map_y - y0
    return (
        img_2d[y0, x0] * (1 - wx) * (1 - wy) +
        img_2d[y0, x1] * wx * (1 - wy) +
        img_2d[y1, x0] * (1 - wx) * wy +
        img_2d[y1, x1] * wx * wy
    ).astype(np.uint8)


# ===================================================================
# [1] Per-channel elastic warp
#     Each RGB channel gets its OWN random displacement field.
#     Humans still see the shape; AI feature extractors break because
#     edges don't align across channels.
# ===================================================================
def per_channel_elastic_warp(img: np.ndarray,
                              alpha_range: tuple = (10.0, 14.8),
                              sigma_range: tuple = (4.0, 5.2)) -> np.ndarray:
    h, w = img.shape[:2]
    rng = np.random.default_rng()
    y_coords, x_coords = np.mgrid[0:h, 0:w]

    if img.ndim == 2:
        # Grayscale: single warp
        alpha = rng.uniform(*alpha_range)
        sigma = rng.uniform(*sigma_range)
        dx = _smooth_field(rng.standard_normal((h, w)).astype(np.float32), sigma) * alpha
        dy = _smooth_field(rng.standard_normal((h, w)).astype(np.float32), sigma) * alpha
        return _bilinear_remap(img, (x_coords + dx).astype(np.float32),
                               (y_coords + dy).astype(np.float32))

    result = np.empty_like(img)
    # Shared base warp (keeps overall structure coherent for humans)
    base_alpha = rng.uniform(*alpha_range)
    base_sigma = rng.uniform(*sigma_range)
    base_dx = _smooth_field(rng.standard_normal((h, w)).astype(np.float32), base_sigma) * base_alpha
    base_dy = _smooth_field(rng.standard_normal((h, w)).astype(np.float32), base_sigma) * base_alpha

    for c in range(img.shape[2]):
        # Per-channel offset on top of the base warp
        chan_alpha = rng.uniform(2.8, 4.2)
        chan_sigma = rng.uniform(3.0, 4.0)
        cdx = _smooth_field(rng.standard_normal((h, w)).astype(np.float32), chan_sigma) * chan_alpha
        cdy = _smooth_field(rng.standard_normal((h, w)).astype(np.float32), chan_sigma) * chan_alpha
        mx = (x_coords + base_dx + cdx).astype(np.float32)
        my = (y_coords + base_dy + cdy).astype(np.float32)
        result[:, :, c] = _bilinear_remap(img[:, :, c], mx, my)

    return result


# ===================================================================
# [2] Fourier band erosion (aggressive)
#     Wipes out mid AND high frequencies, leaving only coarse structure.
# ===================================================================
def fourier_band_erosion(img: np.ndarray,
                          mid_low: float = 0.12,
                          mid_high: float = 0.50,
                          mid_atten: float = 0.30,
                          high_start: float = 0.75,
                          high_atten: float = 0.45) -> np.ndarray:
    h, w = img.shape[:2]
    cy, cx = h // 2, w // 2
    max_radius = min(cy, cx)
    rng = np.random.default_rng()

    # Randomise band edges
    mid_low = np.clip(mid_low + rng.uniform(-0.015, 0.015), 0.05, 0.20)
    mid_high = np.clip(mid_high + rng.uniform(-0.025, 0.025), 0.40, 0.65)

    Y, X = np.ogrid[:h, :w]
    dist = np.sqrt((X - cx) ** 2 + (Y - cy) ** 2)

    mask = np.ones((h, w), dtype=np.float32)

    # Mid-band erosion
    r_ml, r_mh = max_radius * mid_low, max_radius * mid_high
    mid_band = (dist >= r_ml) & (dist <= r_mh)
    mask[mid_band] = mid_atten

    # High-frequency erosion
    r_hs = max_radius * high_start
    high_band = dist >= r_hs
    mask[high_band] = high_atten

    # Smooth transitions
    trans = 0.04 * max_radius
    for edge_r, atten_val in [(r_ml, mid_atten), (r_mh, mid_atten), (r_hs, high_atten)]:
        inner = (dist >= edge_r - trans) & (dist < edge_r)
        outer = (dist > edge_r) & (dist <= edge_r + trans)
        if trans > 0:
            mask[inner] = np.clip(atten_val + (1.0 - atten_val) * (edge_r - dist[inner]) / trans, 0, 1)
            mask[outer] = np.clip(atten_val + (1.0 - atten_val) * (dist[outer] - edge_r) / trans, 0, 1)

    result = np.empty_like(img)
    channels = img.shape[2] if img.ndim == 3 else 1
    for c in range(channels):
        ch = img[:, :, c] if img.ndim == 3 else img
        f = np.fft.fftshift(np.fft.fft2(ch.astype(np.float32)))
        f *= mask
        recon = np.fft.ifft2(np.fft.ifftshift(f)).real
        recon = np.clip(recon, 0, 255).astype(np.uint8)
        if img.ndim == 3:
            result[:, :, c] = recon
        else:
            result = recon
    return result


# ===================================================================
# [3] Patch jitter
#     Cuts image into small blocks and randomly offsets each by a few
#     pixels.  Humans use gestalt to see through it; AI local features
#     get scrambled.
# ===================================================================
def patch_jitter(img: np.ndarray, block_size: int = 20,
                 max_offset: int = 2) -> np.ndarray:
    h, w = img.shape[:2]
    rng = np.random.default_rng()
    result = img.copy()

    for by in range(0, h, block_size):
        for bx in range(0, w, block_size):
            # Random offset for this block
            ox = rng.integers(-max_offset, max_offset + 1)
            oy = rng.integers(-max_offset, max_offset + 1)

            # Source region (clamped)
            sy = max(0, by + oy)
            sx = max(0, bx + ox)
            ey = min(h, by + block_size + oy)
            ex = min(w, bx + block_size + ox)

            # Destination region
            dy = by + max(0, -oy)
            dx = bx + max(0, -ox)
            dey = dy + (ey - sy)
            dex = dx + (ex - sx)

            if dey > h or dex > w or ey <= sy or ex <= sx:
                continue

            result[dy:dey, dx:dex] = img[sy:ey, sx:ex]

    return result


# ===================================================================
# [4] Swirl distortion
#     Creates multiple local rotational vortex warps at random points.
#     Locally bends lines while keeping global structure readable.
# ===================================================================
def swirl_distortion(img: np.ndarray, num_swirls: int = 2,
                     strength_range: tuple = (0.4, 0.6),
                     radius_frac: tuple = (0.12, 0.18)) -> np.ndarray:
    h, w = img.shape[:2]
    rng = np.random.default_rng()
    y_coords, x_coords = np.mgrid[0:h, 0:w]
    map_x = x_coords.astype(np.float32).copy()
    map_y = y_coords.astype(np.float32).copy()

    for _ in range(num_swirls):
        # Random centre
        scx = rng.uniform(w * 0.2, w * 0.8)
        scy = rng.uniform(h * 0.2, h * 0.8)
        strength = rng.uniform(*strength_range) * rng.choice([-1, 1])
        radius = rng.uniform(*radius_frac) * min(h, w)

        # Distance from swirl centre
        dx = map_x - scx
        dy = map_y - scy
        dist = np.sqrt(dx ** 2 + dy ** 2)

        # Rotation angle decays with distance from centre
        mask = dist < radius
        angle = np.zeros_like(dist)
        angle[mask] = strength * (1.0 - dist[mask] / radius)

        cos_a = np.cos(angle)
        sin_a = np.sin(angle)

        new_x = cos_a * dx - sin_a * dy + scx
        new_y = sin_a * dx + cos_a * dy + scy

        map_x = np.where(mask, new_x, map_x)
        map_y = np.where(mask, new_y, map_y)

    if img.ndim == 3:
        result = np.empty_like(img)
        for c in range(img.shape[2]):
            result[:, :, c] = _bilinear_remap(img[:, :, c], map_x, map_y)
        return result
    return _bilinear_remap(img, map_x, map_y)


# ===================================================================
# [5] Halftone overlay
#     Dense rotated dot grid.  Dot size varies with local brightness.
# ===================================================================
def halftone_overlay(img: np.ndarray, dot_spacing: int = 5,
                     blend: float = 0.22) -> np.ndarray:
    h, w = img.shape[:2]
    rng = np.random.default_rng()
    angle_rad = np.radians(rng.uniform(35, 55))

    if img.ndim == 3:
        gray = 0.299 * img[:, :, 0] + 0.587 * img[:, :, 1] + 0.114 * img[:, :, 2]
    else:
        gray = img.astype(np.float32)

    ys, xs = np.mgrid[0:h, 0:w]
    cos_a, sin_a = np.cos(angle_rad), np.sin(angle_rad)
    u = xs * cos_a + ys * sin_a
    v = -xs * sin_a + ys * cos_a

    u_mod = np.remainder(u, dot_spacing) - dot_spacing / 2.0
    v_mod = np.remainder(v, dot_spacing) - dot_spacing / 2.0
    dist_sq = u_mod ** 2 + v_mod ** 2

    brightness = gray / 255.0
    radius = dot_spacing * 0.50 * (1.0 - brightness)
    pattern = np.where(dist_sq <= radius ** 2, 0.0, 1.0).astype(np.float32)

    pattern_nd = pattern[:, :, np.newaxis] if img.ndim == 3 else pattern
    result = img.astype(np.float32) * (1.0 - blend + blend * pattern_nd)
    return np.clip(result, 0, 255).astype(np.uint8)


# ===================================================================
# [6] Chromatic aberration (heavy)
#     Large randomised radial RGB channel shifts.
# ===================================================================
def chromatic_aberration(img: np.ndarray, max_shift: int = 3) -> np.ndarray:
    if img.ndim != 3 or img.shape[2] < 3 or max_shift <= 0:
        return img

    h, w = img.shape[:2]
    rng = np.random.default_rng()

    def rand_shift():
        s = (0, 0)
        while s == (0, 0):
            s = (rng.integers(-max_shift, max_shift + 1),
                 rng.integers(-max_shift, max_shift + 1))
        return s

    sr, sb = rand_shift(), rand_shift()

    cy, cx = h / 2.0, w / 2.0
    max_r = np.sqrt(cx ** 2 + cy ** 2)
    ys, xs = np.mgrid[0:h, 0:w]
    radial = np.sqrt((xs - cx) ** 2 + (ys - cy) ** 2).astype(np.float32) / max_r
    weight = 0.25 + 0.75 * radial  # 25% even at center

    result = img.astype(np.float32).copy()
    r_shifted = np.roll(np.roll(img[:, :, 0], sr[0], axis=1), sr[1], axis=0).astype(np.float32)
    b_shifted = np.roll(np.roll(img[:, :, 2], sb[0], axis=1), sb[1], axis=0).astype(np.float32)
    result[:, :, 0] = img[:, :, 0].astype(np.float32) * (1 - weight) + r_shifted * weight
    result[:, :, 2] = img[:, :, 2].astype(np.float32) * (1 - weight) + b_shifted * weight
    return np.clip(result, 0, 255).astype(np.uint8)


# ===================================================================
# [7] Color space rotation
#     Rotates the RGB cube by a random angle around the gray axis.
#     A red car becomes greenish, a blue sky becomes pinkish — but
#     humans instantly adapt; classifiers trained on normal colors fail.
# ===================================================================
def color_space_rotation(img: np.ndarray, max_angle_deg: float = 22.0) -> np.ndarray:
    if img.ndim != 3 or img.shape[2] < 3:
        return img

    rng = np.random.default_rng()
    angle = np.radians(rng.uniform(-max_angle_deg, max_angle_deg))

    # Rotation around the (1,1,1) gray axis in RGB space
    cos_a = np.cos(angle)
    sin_a = np.sin(angle)
    k = 1.0 / 3.0  # component along gray axis

    # Rodrigues' rotation formula for axis (1,1,1)/sqrt(3)
    inv3 = 1.0 / 3.0
    rot = np.array([
        [cos_a + inv3 * (1 - cos_a),
         inv3 * (1 - cos_a) - sin_a / np.sqrt(3),
         inv3 * (1 - cos_a) + sin_a / np.sqrt(3)],
        [inv3 * (1 - cos_a) + sin_a / np.sqrt(3),
         cos_a + inv3 * (1 - cos_a),
         inv3 * (1 - cos_a) - sin_a / np.sqrt(3)],
        [inv3 * (1 - cos_a) - sin_a / np.sqrt(3),
         inv3 * (1 - cos_a) + sin_a / np.sqrt(3),
         cos_a + inv3 * (1 - cos_a)],
    ], dtype=np.float32)

    flat = img.reshape(-1, 3).astype(np.float32)
    rotated = flat @ rot.T
    return np.clip(rotated, 0, 255).astype(np.uint8).reshape(img.shape)


# ===================================================================
# [8] Color jitter (aggressive)
# ===================================================================
def color_jitter(img: np.ndarray,
                 brightness_range: tuple = (-15, 15),
                 contrast_range: tuple = (0.88, 1.12),
                 saturation_range: tuple = (0.82, 1.18)) -> np.ndarray:
    rng = np.random.default_rng()
    result = img.astype(np.float32)

    result += rng.uniform(*brightness_range)

    contrast = rng.uniform(*contrast_range)
    if img.ndim == 3:
        for c in range(img.shape[2]):
            mean_c = result[:, :, c].mean()
            result[:, :, c] = (result[:, :, c] - mean_c) * contrast + mean_c
    else:
        mean_v = result.mean()
        result = (result - mean_v) * contrast + mean_v

    if img.ndim == 3 and img.shape[2] >= 3:
        gray = 0.299 * result[:, :, 0] + 0.587 * result[:, :, 1] + 0.114 * result[:, :, 2]
        sat = rng.uniform(*saturation_range)
        for c in range(3):
            result[:, :, c] = gray * (1 - sat) + result[:, :, c] * sat

    return np.clip(result, 0, 255).astype(np.uint8)


# ===================================================================
# [9] Watermark overlay
#     Tiles repeating diagonal text + a grid of thin lines at random
#     angles across the image.  Semi-transparent so humans look past
#     it, but it injects false edges and texture that confuse
#     classifiers.
# ===================================================================
def watermark_overlay(img: np.ndarray, opacity: float = 0.13,
                      line_opacity: float = 0.10) -> np.ndarray:
    h, w = img.shape[:2]
    rng = np.random.default_rng()

    from PIL import ImageDraw, ImageFont

    # --- Diagonal text watermark ---
    # Create a larger canvas, draw text, rotate, then crop to image size
    text = "CAPTCHA"
    diag = int(np.sqrt(h ** 2 + w ** 2))
    canvas = Image.new("L", (diag, diag), 0)
    draw = ImageDraw.Draw(canvas)

    try:
        font = ImageFont.truetype("arial.ttf", max(18, min(h, w) // 10))
    except Exception:
        font = ImageFont.load_default()

    # Measure text size
    bbox = draw.textbbox((0, 0), text, font=font)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]

    # Tile text across the canvas
    spacing_x = tw + max(30, tw // 2)
    spacing_y = th + max(40, th)
    for ty in range(0, diag, spacing_y):
        for tx in range(0, diag, spacing_x):
            draw.text((tx, ty), text, fill=255, font=font)

    # Random rotation angle
    angle = rng.uniform(30, 40) * rng.choice([-1, 1])
    canvas = canvas.rotate(angle, resample=Image.BILINEAR, expand=False)

    # Crop center to image size
    cx, cy = canvas.width // 2, canvas.height // 2
    text_layer = np.asarray(canvas.crop((
        cx - w // 2, cy - h // 2,
        cx - w // 2 + w, cy - h // 2 + h
    ))).astype(np.float32) / 255.0

    # Ensure correct size (handle rounding)
    if text_layer.shape[0] != h or text_layer.shape[1] != w:
        text_pil = Image.fromarray((text_layer * 255).astype(np.uint8))
        text_pil = text_pil.resize((w, h), Image.BILINEAR)
        text_layer = np.asarray(text_pil).astype(np.float32) / 255.0

    # --- Thin line grid ---
    line_canvas = Image.new("L", (w, h), 0)
    line_draw = ImageDraw.Draw(line_canvas)

    # Draw 8-15 thin lines at random angles across the image
    num_lines = rng.integers(10, 14)
    for _ in range(num_lines):
        # Random start/end points along image edges
        side_start = rng.integers(0, 4)
        side_end = (side_start + rng.integers(1, 3)) % 4

        def edge_point(side):
            if side == 0:    return (rng.integers(0, w), 0)          # top
            elif side == 1:  return (w - 1, rng.integers(0, h))      # right
            elif side == 2:  return (rng.integers(0, w), h - 1)      # bottom
            else:            return (0, rng.integers(0, h))           # left

        p1 = edge_point(side_start)
        p2 = edge_point(side_end)
        line_draw.line([p1, p2], fill=255, width=1)

    line_layer = np.asarray(line_canvas).astype(np.float32) / 255.0

    # --- Composite both watermark layers onto image ---
    result = img.astype(np.float32)
    # Text watermark: blend toward white where text exists
    wm = text_layer * opacity + line_layer * line_opacity
    if img.ndim == 3:
        wm = wm[:, :, np.newaxis]
    # Push toward white (255) under the watermark
    result = result * (1.0 - wm) + 255.0 * wm

    return np.clip(result, 0, 255).astype(np.uint8)


# ===================================================================
# [10] JPEG artifact simulation
# ===================================================================
def jpeg_artifact(img: np.ndarray, quality_range: tuple = (33, 42)) -> np.ndarray:
    rng = np.random.default_rng()
    quality = int(rng.uniform(*quality_range))
    pil = Image.fromarray(img)
    buf = io.BytesIO()
    pil.save(buf, format="JPEG", quality=quality)
    buf.seek(0)
    return np.asarray(Image.open(buf).convert("RGB")).copy()


# ===================================================================
# [11] FGSM-style perturbation
#      Gradient-magnitude-weighted edge noise.  Applied LAST.
# ===================================================================
def fgsm_perturbation(img: np.ndarray, epsilon: float = 7.0) -> np.ndarray:
    h, w = img.shape[:2]
    rng = np.random.default_rng()
    result = img.astype(np.float32)
    channels = img.shape[2] if img.ndim == 3 else 1

    for c in range(channels):
        ch = (img[:, :, c] if img.ndim == 3 else img).astype(np.float32)

        gx = np.zeros_like(ch)
        gx[:, 1:-1] = ch[:, 2:] - ch[:, :-2]
        gy = np.zeros_like(ch)
        gy[1:-1, :] = ch[2:, :] - ch[:-2, :]

        grad_mag = np.sqrt(gx ** 2 + gy ** 2)
        grad_mag_norm = grad_mag / (grad_mag.max() + 1e-6)

        # Strong perturbation along edges
        perturbation = epsilon * np.sign(gx + gy) * (0.4 + 0.6 * grad_mag_norm)
        # Heavier uniform noise everywhere
        perturbation += rng.uniform(-epsilon * 0.25, epsilon * 0.25, (h, w)).astype(np.float32)

        if img.ndim == 3:
            result[:, :, c] = ch + perturbation
        else:
            result = ch + perturbation

    return np.clip(result, 0, 255).astype(np.uint8)


# ===================================================================
# Quality assessment
# ===================================================================
TILE_SIZE = 256  # output square size in pixels


def _laplacian_variance(arr: np.ndarray) -> float:
    """Compute Laplacian variance as a sharpness/quality proxy."""
    if arr.ndim == 3:
        gray = (0.299 * arr[:, :, 0] + 0.587 * arr[:, :, 1]
                + 0.114 * arr[:, :, 2])
    else:
        gray = arr.astype(np.float32)
    # 3x3 Laplacian kernel via finite differences
    lap = (
        gray[:-2, 1:-1] + gray[2:, 1:-1]
        + gray[1:-1, :-2] + gray[1:-1, 2:]
        - 4.0 * gray[1:-1, 1:-1]
    )
    return float(np.var(lap))


def _quality_strength(arr: np.ndarray) -> float:
    """Map image quality to a distortion strength multiplier.
    High quality (sharp) -> stronger distortion (1.15)
    Low quality (blurry) -> gentler distortion (0.85)
    """
    var = _laplacian_variance(arr)
    # Typical range: ~50 (blurry) to ~2000+ (sharp/detailed)
    # Map linearly: var<=100 -> 0.85, var>=1500 -> 1.15
    t = np.clip((var - 100.0) / 1400.0, 0.0, 1.0)
    return 0.85 + 0.30 * t


def _scale_range(base: tuple, s: float) -> tuple:
    """Scale a (low, high) range by strength factor around its midpoint."""
    mid = (base[0] + base[1]) / 2.0
    half = (base[1] - base[0]) / 2.0
    return (mid - half * s, mid + half * s)


# ===================================================================
# Pre-processing: crop to square + resize to TILE_SIZE
# ===================================================================
def _prepare_square(img: Image.Image) -> Image.Image:
    """Center-crop to the largest square, then resize to TILE_SIZE."""
    w, h = img.size
    side = min(w, h)
    left = (w - side) // 2
    top = (h - side) // 2
    img = img.crop((left, top, left + side, top + side))
    return img.resize((TILE_SIZE, TILE_SIZE), Image.LANCZOS)


# ===================================================================
# Full pipeline
# ===================================================================
def distort_image(img: Image.Image, less_distorted: bool = False) -> Image.Image:
    """Center-crop to square, resize to TILE_SIZE, assess quality,
    then apply the 11-stage distortion pipeline.
    All distortion runs at a uniform TILE_SIZE x TILE_SIZE resolution.

    If less_distorted=True, all layers use fixed parameters at the minimum
    of their usual distortion range (deterministic, not random interval).
    """

    # Step 0: crop to square + resize — before any distortion
    img = _prepare_square(img)
    arr = np.asarray(img).copy()

    if less_distorted:
        s = 0.85  # minimum quality strength
    else:
        s = _quality_strength(arr)

    def _r(base: tuple, neutral: float = 0.0) -> tuple:
        """Scale range; if less_distorted, collapse to lower bound then
        reduce 50% toward the neutral (no-distortion) point."""
        scaled = _scale_range(base, s)
        if less_distorted:
            low = scaled[0]
            v = neutral + LESS_DISTORTED_FACTOR * (low - neutral)
            return (v, v)
        return scaled

    # [1] Per-channel elastic warp
    arr = per_channel_elastic_warp(
        arr,
        alpha_range=_r((10.0, 14.8)),
        sigma_range=_r((4.0, 5.2)),
    )

    # [2] Fourier band erosion (mid + high)
    mid_att = max(0.10, 0.30 * s)
    high_att = max(0.15, 0.45 * s)
    if less_distorted:
        mid_att = 1.0 - LESS_DISTORTED_FACTOR * (1.0 - mid_att)
        high_att = 1.0 - LESS_DISTORTED_FACTOR * (1.0 - high_att)
    arr = fourier_band_erosion(arr, mid_atten=mid_att, high_atten=high_att)

    # [3] Patch jitter
    pj_offset = max(1, int(round(2 * s)))
    if less_distorted:
        pj_offset = max(1, int(round(pj_offset * LESS_DISTORTED_FACTOR)))
    arr = patch_jitter(arr, block_size=20, max_offset=pj_offset)

    # [4] Swirl distortion
    arr = swirl_distortion(
        arr, num_swirls=2,
        strength_range=_r((0.4, 0.6)),
        radius_frac=_r((0.12, 0.18)),
    )

    # [5] Halftone overlay
    ht_blend = min(0.25, 0.12 * s)
    if less_distorted:
        ht_blend *= LESS_DISTORTED_FACTOR
    arr = halftone_overlay(arr, dot_spacing=6, blend=ht_blend)

    # [6] Chromatic aberration
    ca_shift = max(2, int(round(3 * s)))
    if less_distorted:
        ca_shift = max(1, int(round(ca_shift * LESS_DISTORTED_FACTOR)))
    arr = chromatic_aberration(arr, max_shift=ca_shift)

    # [7] Color space rotation
    cs_angle = 22.0 * s
    if less_distorted:
        cs_angle *= LESS_DISTORTED_FACTOR
    arr = color_space_rotation(arr, max_angle_deg=cs_angle)

    # [8] Color jitter
    arr = color_jitter(
        arr,
        brightness_range=_r((-15, 15)),
        contrast_range=_r((0.88, 1.12), neutral=1.0),
        saturation_range=_r((0.82, 1.18), neutral=1.0),
    )

    # [9] Watermark overlay
    wm_opacity = min(0.20, 0.13 * s)
    wm_line_opacity = min(0.16, 0.10 * s)
    if less_distorted:
        wm_opacity *= LESS_DISTORTED_FACTOR
        wm_line_opacity *= LESS_DISTORTED_FACTOR
    arr = watermark_overlay(arr, opacity=wm_opacity, line_opacity=wm_line_opacity)

    # [10] JPEG artifact simulation
    q_low = max(20, int(33 - (s - 1.0) * 15))
    q_high = max(q_low + 3, int(42 - (s - 1.0) * 10))
    if less_distorted:
        q_less = min(95, int(round(q_high + (1.0 - LESS_DISTORTED_FACTOR) * (100 - q_high))))
        arr = jpeg_artifact(arr, quality_range=(q_less, q_less))
    else:
        arr = jpeg_artifact(arr, quality_range=(q_low, q_high))

    # [11] FGSM perturbation (LAST)
    fgsm_eps = 7.0 * s
    if less_distorted:
        fgsm_eps *= LESS_DISTORTED_FACTOR
    arr = fgsm_perturbation(arr, epsilon=fgsm_eps)

    return Image.fromarray(arr)


# ===================================================================
# File walker
# ===================================================================
def _distort_directory(src_dir: str, dst_dir: str) -> int:
    """Distort all images in src_dir, saving to dst_dir. Returns count."""
    os.makedirs(dst_dir, exist_ok=True)
    files = sorted(
        f for f in os.listdir(src_dir)
        if os.path.splitext(f)[1].lower() in IMAGE_EXTENSIONS
    )
    count = 0
    for fname in files:
        src_path = os.path.join(src_dir, fname)
        dst_path = os.path.join(dst_dir, fname)
        less = "lessdistorted" in fname.lower()
        try:
            img = Image.open(src_path).convert("RGB")
            distorted = distort_image(img, less_distorted=less)
            distorted.save(dst_path, quality=92)
            count += 1
        except Exception as e:
            print(f"    SKIP {fname}: {e}")
    return count


def process_all(category_filter: str = None):
    if not os.path.isdir(ORIGINALS_DIR):
        print(f"ERROR: originals directory not found: {ORIGINALS_DIR}")
        sys.exit(1)

    os.makedirs(GRID_DIR, exist_ok=True)

    total = 0

    # Process top-level categories (e.g. cats, cars, abstract)
    categories = sorted(
        d for d in os.listdir(ORIGINALS_DIR)
        if os.path.isdir(os.path.join(ORIGINALS_DIR, d)) and d != "questions"
    )

    if category_filter:
        categories = [c for c in categories if c == category_filter]
        if not categories:
            print(f"ERROR: category '{category_filter}' not found in {ORIGINALS_DIR}")
            sys.exit(1)

    for cat in categories:
        src_dir = os.path.join(ORIGINALS_DIR, cat)
        dst_dir = os.path.join(GRID_DIR, cat)
        files = [f for f in os.listdir(src_dir)
                 if os.path.splitext(f)[1].lower() in IMAGE_EXTENSIONS]
        if not files:
            continue
        print(f"  [{cat}] {len(files)} images ...")
        total += _distort_directory(src_dir, dst_dir)

        # Process fake subfolder if it exists
        fake_src = os.path.join(src_dir, "fake")
        fake_dst = os.path.join(dst_dir, "fake")
        if os.path.isdir(fake_src):
            fake_files = [f for f in os.listdir(fake_src)
                          if os.path.splitext(f)[1].lower() in IMAGE_EXTENSIONS]
            if fake_files:
                print(f"  [{cat}/fake] {len(fake_files)} images ...")
                total += _distort_directory(fake_src, fake_dst)

    print(f"\nDone. {total} images distorted into {GRID_DIR}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Distort CAPTCHA images")
    parser.add_argument("--category", type=str, default=None,
                        help="Process only this category folder")
    args = parser.parse_args()

    print(f"Source:  {ORIGINALS_DIR}")
    print(f"Output:  {GRID_DIR}\n")
    process_all(args.category)
