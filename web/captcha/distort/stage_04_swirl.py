"""Etapa 4: distorsiune in forma de vartej rotational local."""
import numpy as np

from .helpers import _bilinear_remap

def swirl_distortion(img: np.ndarray, num_swirls: int = 2,
                     strength_range: tuple = (0.4, 0.6),
                     radius_frac: tuple = (0.12, 0.18)) -> np.ndarray:
    h, w = img.shape[:2]
    rng = np.random.default_rng()
    y_coords, x_coords = np.mgrid[0:h, 0:w]
    map_x = x_coords.astype(np.float32).copy()
    map_y = y_coords.astype(np.float32).copy()

    for _ in range(num_swirls):
        scx = rng.uniform(w * 0.2, w * 0.8)
        scy = rng.uniform(h * 0.2, h * 0.8)
        strength = rng.uniform(*strength_range) * rng.choice([-1, 1])
        radius = rng.uniform(*radius_frac) * min(h, w)

        dx = map_x - scx
        dy = map_y - scy
        dist = np.sqrt(dx ** 2 + dy ** 2)

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
