"""
Stage 10 — JPEG artifact simulation.

Round-trips the image through aggressive JPEG compression (quality 33-42).
This injects the characteristic 8x8 blocking, mid/high-frequency
quantisation, mosquito noise and colour banding that real low-quality
JPEGs carry — features absent from the high-quality training data of
typical ImageNet-class CNNs.
"""
import io

import numpy as np
from PIL import Image


def jpeg_artifact(img: np.ndarray, quality_range: tuple = (33, 42)) -> np.ndarray:
    rng = np.random.default_rng()
    quality = int(rng.uniform(*quality_range))
    pil = Image.fromarray(img)
    buf = io.BytesIO()
    pil.save(buf, format="JPEG", quality=quality)
    buf.seek(0)
    return np.asarray(Image.open(buf).convert("RGB")).copy()
