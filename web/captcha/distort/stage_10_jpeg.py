"""Etapa 10: simulare de artefacte JPEG prin compresie agresiva."""
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
