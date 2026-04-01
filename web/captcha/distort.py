#!/usr/bin/env python3
"""
Distortion pipeline for CAPTCHA images.

Reads every image from  CAPTCHA_photos/originals/<category>/*
Writes distorted copies to CAPTCHA_photos/grid/<category>/*
preserving the exact folder hierarchy.

Pipeline (applied in order):
  [1] Elastic micro-warp          — smooth random displacement field
  [2] Fourier mid-band erosion    — attenuate mid-frequencies via FFT
  [3] Halftone overlay            — rotated dot grid, brightness-scaled
  [4] Chromatic aberration        — randomised radial RGB channel shifts
  [5] Color jitter                — random brightness / contrast / saturation
  [6] JPEG artifact simulation    — lossy compress → decompress
  [7] FGSM-style perturbation     — gradient-magnitude-weighted edge noise (last)

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


# ===================================================================
# [1] Elastic micro-warp
#     Smooth random displacement field with bilinear interpolation.
#     Alpha and sigma are randomised per image for variety.
# ===================================================================
def elastic_micro_warp(img: np.ndarray,
                       alpha_range: tuple = (12.0, 22.0),
                       sigma_range: tuple = (4.0, 7.0)) -> np.ndarray:
    h, w = img.shape[:2]
    rng = np.random.default_rng()

    alpha = rng.uniform(*alpha_range)
    sigma = rng.uniform(*sigma_range)

    # Random displacement fields
    dx = rng.standard_normal((h, w)).astype(np.float32)
    dy = rng.standard_normal((h, w)).astype(np.float32)

    def smooth_field(field: np.ndarray, sigma_px: float) -> np.ndarray:
        fmin, fmax = field.min(), field.max()
        span = max(fmax - fmin, 1e-6)
        normalized = ((field - fmin) / span * 255).astype(np.uint8)
        pil_img = Image.fromarray(normalized, mode="L")
        radius = max(1, int(sigma_px))
        pil_img = pil_img.filter(ImageFilter.GaussianBlur(radius=radius))
        result = np.asarray(pil_img).astype(np.float32) / 255.0 * span + fmin
        return result

    dx = smooth_field(dx, sigma) * alpha
    dy = smooth_field(dy, sigma) * alpha

    # Coordinate grids
    y_coords, x_coords = np.mgrid[0:h, 0:w]
    map_x = (x_coords + dx).astype(np.float32)
    map_y = (y_coords + dy).astype(np.float32)

    # Clamp to valid range (leave room for bilinear)
    map_x = np.clip(map_x, 0, w - 1.001)
    map_y = np.clip(map_y, 0, h - 1.001)

    # Bilinear interpolation (smoother than nearest-neighbor)
    x0 = np.floor(map_x).astype(np.intp)
    y0 = np.floor(map_y).astype(np.intp)
    x1 = np.minimum(x0 + 1, w - 1)
    y1 = np.minimum(y0 + 1, h - 1)
    wx = map_x - x0
    wy = map_y - y0

    if img.ndim == 3:
        wx = wx[:, :, np.newaxis]
        wy = wy[:, :, np.newaxis]

    result = (
        img[y0, x0] * (1 - wx) * (1 - wy) +
        img[y0, x1] * wx * (1 - wy) +
        img[y1, x0] * (1 - wx) * wy +
        img[y1, x1] * wx * wy
    )
    return np.clip(result, 0, 255).astype(np.uint8)


# ===================================================================
# [2] Fourier mid-band erosion
#     FFT → attenuate a randomised ring of mid-frequencies → IFFT.
#     Softens texture detail without blurring edges like a Gaussian.
# ===================================================================
def fourier_mid_band_erosion(img: np.ndarray,
                              low_ratio: float = 0.15,
                              high_ratio: float = 0.45,
                              attenuation: float = 0.20) -> np.ndarray:
    h, w = img.shape[:2]
    cy, cx = h // 2, w // 2
    max_radius = min(cy, cx)

    # Slight randomisation of the band edges
    rng = np.random.default_rng()
    low_ratio = np.clip(low_ratio + rng.uniform(-0.03, 0.03), 0.08, 0.25)
    high_ratio = np.clip(high_ratio + rng.uniform(-0.05, 0.05), 0.30, 0.55)

    Y, X = np.ogrid[:h, :w]
    dist = np.sqrt((X - cx) ** 2 + (Y - cy) ** 2)
    r_low = max_radius * low_ratio
    r_high = max_radius * high_ratio

    mask = np.ones((h, w), dtype=np.float32)
    band = (dist >= r_low) & (dist <= r_high)
    mask[band] = attenuation

    # Smooth transitions to avoid ringing
    transition = 0.05 * max_radius
    inner_edge = (dist >= r_low - transition) & (dist < r_low)
    outer_edge = (dist > r_high) & (dist <= r_high + transition)
    if transition > 0:
        mask[inner_edge] = attenuation + (1.0 - attenuation) * (r_low - dist[inner_edge]) / transition
        mask[outer_edge] = attenuation + (1.0 - attenuation) * (dist[outer_edge] - r_high) / transition

    result = np.empty_like(img)
    channels = img.shape[2] if img.ndim == 3 else 1

    for c in range(channels):
        channel = img[:, :, c] if img.ndim == 3 else img
        f = np.fft.fft2(channel.astype(np.float32))
        f_shifted = np.fft.fftshift(f)
        f_shifted *= mask
        f_back = np.fft.ifftshift(f_shifted)
        reconstructed = np.fft.ifft2(f_back).real
        reconstructed = np.clip(reconstructed, 0, 255).astype(np.uint8)
        if img.ndim == 3:
            result[:, :, c] = reconstructed
        else:
            result = reconstructed

    return result


# ===================================================================
# [3] Halftone overlay
#     Rotated dot grid whose dot size varies with local brightness.
#     Fully vectorised — no Python pixel loops.
# ===================================================================
def halftone_overlay(img: np.ndarray, dot_spacing: int = 5,
                     blend: float = 0.25) -> np.ndarray:
    h, w = img.shape[:2]
    rng = np.random.default_rng()

    # Random grid rotation angle (15–75°) for variety
    angle_deg = rng.uniform(15, 75)
    angle_rad = np.radians(angle_deg)

    # Grayscale luminance
    if img.ndim == 3:
        gray = 0.299 * img[:, :, 0] + 0.587 * img[:, :, 1] + 0.114 * img[:, :, 2]
    else:
        gray = img.astype(np.float32)

    # Build pixel coordinate arrays
    ys, xs = np.mgrid[0:h, 0:w]

    # Rotate coordinates into the halftone grid frame
    cos_a, sin_a = np.cos(angle_rad), np.sin(angle_rad)
    u = xs * cos_a + ys * sin_a
    v = -xs * sin_a + ys * cos_a

    # Distance from each pixel to its nearest dot centre in the rotated grid
    u_mod = np.remainder(u, dot_spacing) - dot_spacing / 2.0
    v_mod = np.remainder(v, dot_spacing) - dot_spacing / 2.0
    dist_sq = u_mod ** 2 + v_mod ** 2

    # Radius varies with brightness: darker → bigger dot (more ink)
    brightness = gray / 255.0
    radius = dot_spacing * 0.45 * (1.0 - brightness)
    radius_sq = radius ** 2

    # Pattern: 0.0 where inside a dot, 1.0 outside
    pattern = np.where(dist_sq <= radius_sq, 0.0, 1.0).astype(np.float32)

    # Blend
    pattern_nd = pattern[:, :, np.newaxis] if img.ndim == 3 else pattern
    result = img.astype(np.float32) * (1.0 - blend + blend * pattern_nd)
    return np.clip(result, 0, 255).astype(np.uint8)


# ===================================================================
# [4] Chromatic aberration
#     Randomised per-image RGB channel shifts with radial falloff
#     (stronger at corners, like a real cheap lens).
# ===================================================================
def chromatic_aberration(img: np.ndarray,
                         max_shift: int = 5) -> np.ndarray:
    if img.ndim != 3 or img.shape[2] < 3:
        return img

    h, w = img.shape[:2]
    rng = np.random.default_rng()

    # Random shift for R and B channels (G stays put)
    sr = (rng.integers(-max_shift, max_shift + 1),
          rng.integers(-max_shift, max_shift + 1))
    sb = (rng.integers(-max_shift, max_shift + 1),
          rng.integers(-max_shift, max_shift + 1))

    # Ensure at least some shift
    while sr == (0, 0):
        sr = (rng.integers(-max_shift, max_shift + 1),
              rng.integers(-max_shift, max_shift + 1))
    while sb == (0, 0):
        sb = (rng.integers(-max_shift, max_shift + 1),
              rng.integers(-max_shift, max_shift + 1))

    # Radial weight: 0 at center, 1 at corners
    cy, cx = h / 2.0, w / 2.0
    max_r = np.sqrt(cx ** 2 + cy ** 2)
    ys, xs = np.mgrid[0:h, 0:w]
    radial = np.sqrt((xs - cx) ** 2 + (ys - cy) ** 2).astype(np.float32) / max_r
    # Smooth ramp: shift is 30% at center, 100% at corners
    weight = 0.3 + 0.7 * radial

    result = img.copy().astype(np.float32)

    # Shifted versions
    r_shifted = np.roll(np.roll(img[:, :, 0], sr[0], axis=1), sr[1], axis=0).astype(np.float32)
    b_shifted = np.roll(np.roll(img[:, :, 2], sb[0], axis=1), sb[1], axis=0).astype(np.float32)

    # Blend original and shifted channels by radial weight
    result[:, :, 0] = img[:, :, 0].astype(np.float32) * (1 - weight) + r_shifted * weight
    result[:, :, 2] = img[:, :, 2].astype(np.float32) * (1 - weight) + b_shifted * weight

    return np.clip(result, 0, 255).astype(np.uint8)


# ===================================================================
# [5] Color jitter
#     Random brightness, contrast, and saturation shifts.
#     Breaks colour histogram assumptions that classifiers rely on.
# ===================================================================
def color_jitter(img: np.ndarray,
                 brightness_range: tuple = (-30, 30),
                 contrast_range: tuple = (0.75, 1.25),
                 saturation_range: tuple = (0.70, 1.30)) -> np.ndarray:
    rng = np.random.default_rng()
    result = img.astype(np.float32)

    # Brightness
    result += rng.uniform(*brightness_range)

    # Contrast (around per-channel mean)
    contrast = rng.uniform(*contrast_range)
    if img.ndim == 3:
        for c in range(img.shape[2]):
            mean_c = result[:, :, c].mean()
            result[:, :, c] = (result[:, :, c] - mean_c) * contrast + mean_c
    else:
        mean_v = result.mean()
        result = (result - mean_v) * contrast + mean_v

    # Saturation (only for colour images)
    if img.ndim == 3 and img.shape[2] >= 3:
        gray = 0.299 * result[:, :, 0] + 0.587 * result[:, :, 1] + 0.114 * result[:, :, 2]
        sat = rng.uniform(*saturation_range)
        for c in range(3):
            result[:, :, c] = gray * (1 - sat) + result[:, :, c] * sat

    return np.clip(result, 0, 255).astype(np.uint8)


# ===================================================================
# [6] JPEG artifact simulation
#     Compress and decompress at low quality to introduce blocking
#     artifacts and quantisation noise.
# ===================================================================
def jpeg_artifact(img: np.ndarray, quality_range: tuple = (15, 35)) -> np.ndarray:
    rng = np.random.default_rng()
    quality = int(rng.uniform(*quality_range))

    pil = Image.fromarray(img)
    buf = io.BytesIO()
    pil.save(buf, format="JPEG", quality=quality)
    buf.seek(0)
    compressed = Image.open(buf).convert("RGB")
    return np.asarray(compressed).copy()


# ===================================================================
# [7] FGSM-style perturbation
#     Uses gradient magnitude to weight noise — stronger perturbation
#     along edges where classifiers are most sensitive, weaker in flat
#     regions.  Applied LAST on the final composite.
# ===================================================================
def fgsm_perturbation(img: np.ndarray, epsilon: float = 10.0) -> np.ndarray:
    h, w = img.shape[:2]
    rng = np.random.default_rng()
    result = img.astype(np.float32)
    channels = img.shape[2] if img.ndim == 3 else 1

    for c in range(channels):
        channel = img[:, :, c] if img.ndim == 3 else img
        ch = channel.astype(np.float32)

        # Sobel-like gradients
        gx = np.zeros_like(ch)
        gx[:, 1:-1] = ch[:, 2:] - ch[:, :-2]
        gy = np.zeros_like(ch)
        gy[1:-1, :] = ch[2:, :] - ch[:-2, :]

        # Gradient magnitude (proper L2 norm, not sum)
        grad_mag = np.sqrt(gx ** 2 + gy ** 2)
        grad_mag_norm = grad_mag / (grad_mag.max() + 1e-6)  # normalise to [0, 1]

        # FGSM: epsilon * sign(gradient), but weighted by magnitude
        # Strong at edges, weak in flat areas
        grad_sum = gx + gy
        perturbation = epsilon * np.sign(grad_sum) * (0.3 + 0.7 * grad_mag_norm)

        # Add small random noise to flat regions too
        uniform_noise = rng.uniform(-epsilon * 0.25, epsilon * 0.25, (h, w)).astype(np.float32)
        perturbation += uniform_noise * (1.0 - grad_mag_norm)

        if img.ndim == 3:
            result[:, :, c] = ch + perturbation
        else:
            result = ch + perturbation

    return np.clip(result, 0, 255).astype(np.uint8)


# ===================================================================
# Full pipeline
# ===================================================================
def distort_image(img: Image.Image) -> Image.Image:
    """Apply the full 7-stage distortion pipeline to a PIL Image."""
    arr = np.asarray(img).copy()

    # [1] Elastic micro-warp (randomised alpha/sigma)
    arr = elastic_micro_warp(arr)

    # [2] Fourier mid-band erosion
    arr = fourier_mid_band_erosion(arr)

    # [3] Halftone overlay (rotated grid)
    arr = halftone_overlay(arr, dot_spacing=5, blend=0.25)

    # [4] Chromatic aberration (randomised radial)
    arr = chromatic_aberration(arr, max_shift=5)

    # [5] Color jitter
    arr = color_jitter(arr)

    # [6] JPEG artifact simulation
    arr = jpeg_artifact(arr)

    # [7] FGSM perturbation (LAST — on the final composite)
    arr = fgsm_perturbation(arr, epsilon=10.0)

    return Image.fromarray(arr)


# ===================================================================
# File walker
# ===================================================================
def process_all(category_filter: str = None):
    if not os.path.isdir(ORIGINALS_DIR):
        print(f"ERROR: originals directory not found: {ORIGINALS_DIR}")
        sys.exit(1)

    os.makedirs(GRID_DIR, exist_ok=True)

    categories = sorted(
        d for d in os.listdir(ORIGINALS_DIR)
        if os.path.isdir(os.path.join(ORIGINALS_DIR, d))
    )

    if category_filter:
        categories = [c for c in categories if c == category_filter]
        if not categories:
            print(f"ERROR: category '{category_filter}' not found in {ORIGINALS_DIR}")
            sys.exit(1)

    total = 0
    for cat in categories:
        src_dir = os.path.join(ORIGINALS_DIR, cat)
        dst_dir = os.path.join(GRID_DIR, cat)
        os.makedirs(dst_dir, exist_ok=True)

        files = sorted(
            f for f in os.listdir(src_dir)
            if os.path.splitext(f)[1].lower() in IMAGE_EXTENSIONS
        )

        if not files:
            continue

        print(f"  [{cat}] {len(files)} images ...")

        for fname in files:
            src_path = os.path.join(src_dir, fname)
            dst_path = os.path.join(dst_dir, fname)

            try:
                img = Image.open(src_path).convert("RGB")
                distorted = distort_image(img)
                distorted.save(dst_path, quality=92)
                total += 1
            except Exception as e:
                print(f"    SKIP {fname}: {e}")

    print(f"\nDone. {total} images distorted into {GRID_DIR}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Distort CAPTCHA images")
    parser.add_argument("--category", type=str, default=None,
                        help="Process only this category folder")
    args = parser.parse_args()

    print(f"Source:  {ORIGINALS_DIR}")
    print(f"Output:  {GRID_DIR}\n")
    process_all(args.category)
