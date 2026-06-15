"""Helper-i de nivel jos folositi de etapele de distorsiune."""
import os

import numpy as np
from PIL import Image, ImageFilter

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ORIGINALS_DIR = os.path.join(BASE_DIR, "CAPTCHA_photos", "originals")
GRID_DIR = os.path.join(BASE_DIR, "CAPTCHA_photos", "grid")

IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".bmp", ".gif"}

LESS_DISTORTED_FACTOR = 0.5

def _smooth_field(field: np.ndarray, sigma_px: float) -> np.ndarray:
    """Aplica blur gaussian pe un camp 2D float folosind PIL."""
    fmin, fmax = field.min(), field.max()
    span = max(fmax - fmin, 1e-6)
    normalized = ((field - fmin) / span * 255).astype(np.uint8)
    pil_img = Image.fromarray(normalized, mode="L")
    radius = max(1, int(sigma_px))
    pil_img = pil_img.filter(ImageFilter.GaussianBlur(radius=radius))
    return np.asarray(pil_img).astype(np.float32) / 255.0 * span + fmin

def _bilinear_remap(img_2d: np.ndarray, map_x: np.ndarray, map_y: np.ndarray) -> np.ndarray:
    """Remap bilinear pentru un singur array 2D."""
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
