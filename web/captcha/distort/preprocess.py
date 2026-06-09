"""Pre-processing applied before the 11-stage pipeline."""
from PIL import Image

from .quality import TILE_SIZE


def _prepare_square(img: Image.Image) -> Image.Image:
    """Center-crop to the largest square, then resize to TILE_SIZE."""
    w, h = img.size
    side = min(w, h)
    left = (w - side) // 2
    top = (h - side) // 2
    img = img.crop((left, top, left + side, top + side))
    return img.resize((TILE_SIZE, TILE_SIZE), Image.LANCZOS)
