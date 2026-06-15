"""Etapa 1: deformare elastica per canal RGB."""
import numpy as np

from .helpers import _bilinear_remap, _smooth_field

def per_channel_elastic_warp(img: np.ndarray,
                              alpha_range: tuple = (10.0, 14.8),
                              sigma_range: tuple = (4.0, 5.2)) -> np.ndarray:
    h, w = img.shape[:2]
    rng = np.random.default_rng()
    y_coords, x_coords = np.mgrid[0:h, 0:w]

    if img.ndim == 2:
        alpha = rng.uniform(*alpha_range)
        sigma = rng.uniform(*sigma_range)
        dx = _smooth_field(rng.standard_normal((h, w)).astype(np.float32), sigma) * alpha
        dy = _smooth_field(rng.standard_normal((h, w)).astype(np.float32), sigma) * alpha
        return _bilinear_remap(img, (x_coords + dx).astype(np.float32),
                               (y_coords + dy).astype(np.float32))

    result = np.empty_like(img)
    base_alpha = rng.uniform(*alpha_range)
    base_sigma = rng.uniform(*sigma_range)
    base_dx = _smooth_field(rng.standard_normal((h, w)).astype(np.float32), base_sigma) * base_alpha
    base_dy = _smooth_field(rng.standard_normal((h, w)).astype(np.float32), base_sigma) * base_alpha

    for c in range(img.shape[2]):
        chan_alpha = rng.uniform(2.8, 4.2)
        chan_sigma = rng.uniform(3.0, 4.0)
        cdx = _smooth_field(rng.standard_normal((h, w)).astype(np.float32), chan_sigma) * chan_alpha
        cdy = _smooth_field(rng.standard_normal((h, w)).astype(np.float32), chan_sigma) * chan_alpha
        mx = (x_coords + base_dx + cdx).astype(np.float32)
        my = (y_coords + base_dy + cdy).astype(np.float32)
        result[:, :, c] = _bilinear_remap(img[:, :, c], mx, my)

    return result
