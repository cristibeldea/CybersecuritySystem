"""
Stage 6 — Chromatic aberration.

Simulates the optical aberration of real camera lenses by shifting the
R and B channels independently with a magnitude that grows radially
from the image centre.  The G channel is the "reference" because the
human eye is most sensitive to it and real lens designs are optimised
around green wavelengths.
"""
import numpy as np


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
