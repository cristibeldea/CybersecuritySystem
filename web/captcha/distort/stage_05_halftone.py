"""
Stage 5 — Halftone overlay.

A dense rotated dot grid is blended over the image.  Dot size varies
with local brightness (darker areas produce bigger dots), mimicking
analogue offset printing.  The grid is rotated 35-55 degrees so it
isn't axis-aligned and stays perceptually plausible to humans but
injects a periodic texture that CNN texture detectors do not expect.
"""
import numpy as np


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
