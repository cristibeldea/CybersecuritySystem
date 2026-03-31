#!/usr/bin/env python3
"""
Distortion pipeline for CAPTCHA images.

Reads every image from  CAPTCHA_photos/originals/<category>/*
Writes distorted copies to CAPTCHA_photos/grid/<category>/*
preserving the exact folder hierarchy.

Pipeline (applied in order):
  [1] Elastic micro-warp
  [2] Fourier mid-band erosion
  [3] Halftone overlay
  [4] Chromatic aberration
  [5] FGSM-style perturbation (applied last, on the final composite)

Usage:
    python distort.py                  # process all
    python distort.py --category cats  # process one category
"""

import argparse
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
#     Creates a smooth random displacement field and remaps every
#     pixel by a small offset, producing subtle organic warping.
# ===================================================================
def elastic_micro_warp(img: np.ndarray, alpha: float = 8.0, sigma: float = 4.0) -> np.ndarray:
    h, w = img.shape[:2]

    # Random displacement fields
    rng = np.random.default_rng()
    dx = rng.standard_normal((h, w)).astype(np.float32)
    dy = rng.standard_normal((h, w)).astype(np.float32)

    # Smooth with a Gaussian-like kernel via repeated box blurs
    # (approximation that avoids scipy dependency)
    from PIL import ImageFilter as _IF

    def smooth_field(field: np.ndarray, sigma_px: float) -> np.ndarray:
        # Convert to PIL grayscale image, blur, convert back
        fmin, fmax = field.min(), field.max()
        span = max(fmax - fmin, 1e-6)
        normalized = ((field - fmin) / span * 255).astype(np.uint8)
        pil_img = Image.fromarray(normalized, mode="L")
        radius = max(1, int(sigma_px))
        pil_img = pil_img.filter(_IF.GaussianBlur(radius=radius))
        result = np.asarray(pil_img).astype(np.float32) / 255.0 * span + fmin
        return result

    dx = smooth_field(dx, sigma) * alpha
    dy = smooth_field(dy, sigma) * alpha

    # Build coordinate grids
    y_coords, x_coords = np.mgrid[0:h, 0:w]
    map_x = (x_coords + dx).astype(np.float32)
    map_y = (y_coords + dy).astype(np.float32)

    # Clamp to image bounds
    map_x = np.clip(map_x, 0, w - 1)
    map_y = np.clip(map_y, 0, h - 1)

    # Nearest-neighbor remap (avoids opencv dependency)
    ix = np.round(map_x).astype(np.intp)
    iy = np.round(map_y).astype(np.intp)

    return img[iy, ix]


# ===================================================================
# [2] Fourier mid-band erosion
#     Applies FFT, attenuates a ring of mid-frequencies, then IFFT.
#     This softens texture detail without blurring edges the way a
#     simple Gaussian would.
# ===================================================================
def fourier_mid_band_erosion(img: np.ndarray, low_ratio: float = 0.15,
                              high_ratio: float = 0.45,
                              attenuation: float = 0.35) -> np.ndarray:
    h, w = img.shape[:2]
    cy, cx = h // 2, w // 2
    max_radius = min(cy, cx)

    # Build radial mask
    Y, X = np.ogrid[:h, :w]
    dist = np.sqrt((X - cx) ** 2 + (Y - cy) ** 2)
    r_low = max_radius * low_ratio
    r_high = max_radius * high_ratio

    # 1.0 everywhere, attenuated in the mid-band ring
    mask = np.ones((h, w), dtype=np.float32)
    band = (dist >= r_low) & (dist <= r_high)
    mask[band] = attenuation

    # Smooth the mask edges to avoid ringing
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
#     Simulates a print halftone pattern by creating a dot grid whose
#     dot size varies with local brightness, then blends it over the
#     image.
# ===================================================================
def halftone_overlay(img: np.ndarray, dot_spacing: int = 6,
                     blend: float = 0.12) -> np.ndarray:
    h, w = img.shape[:2]

    # Grayscale luminance
    if img.ndim == 3:
        gray = (0.299 * img[:, :, 0] + 0.587 * img[:, :, 1] + 0.114 * img[:, :, 2])
    else:
        gray = img.astype(np.float32)

    pattern = np.ones((h, w), dtype=np.float32)

    # Create dot centers on a grid
    for cy in range(0, h, dot_spacing):
        for cx in range(0, w, dot_spacing):
            # Local brightness determines dot radius
            region = gray[max(0, cy-1):cy+2, max(0, cx-1):cx+2]
            brightness = region.mean() / 255.0  # 0=dark, 1=bright
            # Darker areas get bigger dots (more ink)
            radius = dot_spacing * 0.45 * (1.0 - brightness)

            if radius < 0.5:
                continue

            # Draw filled circle into pattern
            y_min = max(0, int(cy - radius - 1))
            y_max = min(h, int(cy + radius + 2))
            x_min = max(0, int(cx - radius - 1))
            x_max = min(w, int(cx + radius + 2))

            for py in range(y_min, y_max):
                for px in range(x_min, x_max):
                    d = ((py - cy) ** 2 + (px - cx) ** 2) ** 0.5
                    if d <= radius:
                        pattern[py, px] = 0.0  # black dot

    # Blend: result = img * (1-blend) + img*pattern * blend
    pattern_3d = pattern[:, :, np.newaxis] if img.ndim == 3 else pattern
    result = img.astype(np.float32) * (1.0 - blend + blend * pattern_3d)
    return np.clip(result, 0, 255).astype(np.uint8)


# ===================================================================
# [4] Chromatic aberration
#     Shifts the R, G, B channels by different pixel offsets,
#     simulating lens dispersion.
# ===================================================================
def chromatic_aberration(img: np.ndarray, shift_r: tuple = (2, 1),
                         shift_b: tuple = (-2, -1)) -> np.ndarray:
    if img.ndim != 3 or img.shape[2] < 3:
        return img

    h, w = img.shape[:2]
    result = np.empty_like(img)

    # Green channel stays put
    result[:, :, 1] = img[:, :, 1]

    # Shift red
    result[:, :, 0] = np.roll(np.roll(img[:, :, 0], shift_r[0], axis=1), shift_r[1], axis=0)
    # Shift blue
    result[:, :, 2] = np.roll(np.roll(img[:, :, 2], shift_b[0], axis=1), shift_b[1], axis=0)

    return result


# ===================================================================
# [5] FGSM-style perturbation
#     Uses the image's own gradient (Sobel edges) as a proxy for
#     the gradient of a loss function — this concentrates noise
#     around edges where classifiers are most sensitive, mimicking
#     real FGSM output without needing a model.
#     Applied LAST on the final composite.
# ===================================================================
def fgsm_perturbation(img: np.ndarray, epsilon: float = 6.0) -> np.ndarray:
    h, w = img.shape[:2]
    result = img.astype(np.float32)

    channels = img.shape[2] if img.ndim == 3 else 1

    for c in range(channels):
        channel = img[:, :, c] if img.ndim == 3 else img
        ch = channel.astype(np.float32)

        # Sobel-like gradient approximation
        # Horizontal gradient
        gx = np.zeros_like(ch)
        gx[:, 1:-1] = ch[:, 2:] - ch[:, :-2]

        # Vertical gradient
        gy = np.zeros_like(ch)
        gy[1:-1, :] = ch[2:, :] - ch[:-2, :]

        # Gradient magnitude as "importance" and sign as direction
        grad = gx + gy

        # FGSM: perturbation = epsilon * sign(gradient)
        perturbation = epsilon * np.sign(grad)

        # Add small uniform noise to flat regions so the perturbation
        # isn't zero where the image is constant
        rng = np.random.default_rng()
        uniform_noise = rng.uniform(-epsilon * 0.3, epsilon * 0.3, (h, w)).astype(np.float32)
        perturbation += uniform_noise

        if img.ndim == 3:
            result[:, :, c] = ch + perturbation
        else:
            result = ch + perturbation

    return np.clip(result, 0, 255).astype(np.uint8)


# ===================================================================
# Full pipeline
# ===================================================================
def distort_image(img: Image.Image) -> Image.Image:
    """Apply the full 5-stage distortion pipeline to a PIL Image."""
    arr = np.asarray(img)

    # Ensure we work with a writable copy
    arr = arr.copy()

    # [1] Elastic micro-warp
    arr = elastic_micro_warp(arr, alpha=8.0, sigma=4.0)

    # [2] Fourier mid-band erosion
    arr = fourier_mid_band_erosion(arr, low_ratio=0.15, high_ratio=0.45, attenuation=0.35)

    # [3] Halftone overlay
    arr = halftone_overlay(arr, dot_spacing=6, blend=0.12)

    # [4] Chromatic aberration
    arr = chromatic_aberration(arr, shift_r=(2, 1), shift_b=(-2, -1))

    # [5] FGSM perturbation (LAST — on the final composite)
    arr = fgsm_perturbation(arr, epsilon=6.0)

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
