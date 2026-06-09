"""
Stage 3 — Patch jitter.

Cuts the image into small blocks and randomly offsets each by a few pixels.
Humans use Gestalt continuity to look through it; AI local-feature
extractors (convolution kernels with fixed receptive fields) get scrambled.
"""
import numpy as np


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
