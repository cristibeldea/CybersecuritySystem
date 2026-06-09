"""
Image quality assessment + range-scaling utilities.

Quality is measured via the Laplacian variance — a classic sharpness proxy.
Sharp images receive stronger distortion (multiplier > 1), blurry images
receive gentler distortion (multiplier < 1).
"""
import numpy as np


# Output square size in pixels for every distorted tile.
TILE_SIZE = 256


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
