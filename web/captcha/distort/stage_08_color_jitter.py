"""
Stage 8 — Photometric color jitter.

Independent random perturbations on brightness, contrast and saturation.
Each is mild on its own (~6%, ~12%, ~18% maximum respectively), but the
three combined push the image slightly outside the training-time
photometric distribution of typical CNN classifiers.

The same technique is used as training-time data augmentation by model
builders; here it is repurposed defensively with slightly more
aggressive ranges than typical augmentation settings.
"""
import numpy as np


def color_jitter(img: np.ndarray,
                 brightness_range: tuple = (-15, 15),
                 contrast_range: tuple = (0.88, 1.12),
                 saturation_range: tuple = (0.82, 1.18)) -> np.ndarray:
    rng = np.random.default_rng()
    result = img.astype(np.float32)

    result += rng.uniform(*brightness_range)

    contrast = rng.uniform(*contrast_range)
    if img.ndim == 3:
        for c in range(img.shape[2]):
            mean_c = result[:, :, c].mean()
            result[:, :, c] = (result[:, :, c] - mean_c) * contrast + mean_c
    else:
        mean_v = result.mean()
        result = (result - mean_v) * contrast + mean_v

    if img.ndim == 3 and img.shape[2] >= 3:
        gray = 0.299 * result[:, :, 0] + 0.587 * result[:, :, 1] + 0.114 * result[:, :, 2]
        sat = rng.uniform(*saturation_range)
        for c in range(3):
            result[:, :, c] = gray * (1 - sat) + result[:, :, c] * sat

    return np.clip(result, 0, 255).astype(np.uint8)
