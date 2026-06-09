"""
Stage 11 — FGSM-style adversarial perturbation (model-agnostic).

The classic Fast Gradient Sign Method (Goodfellow et al., 2015) requires
white-box access to a target classifier in order to compute the loss
gradient.  Since the defender has no such target, this variant computes
the gradient of the IMAGE itself (intensity gradient via finite
differences) and concentrates the perturbation on the strongest edges —
exactly the pixels any CNN exploits most heavily for classification.

Two components are summed per pixel:
  - structured edge-weighted noise:  epsilon * sign(gx + gy) * (0.4 + 0.6 * grad_norm)
  - uniform background noise:        Uniform(-epsilon/4, +epsilon/4)

This stage is applied LAST in the pipeline so that any edges surviving
the earlier nine stages still receive a final adversarial nudge.
"""
import numpy as np


def fgsm_perturbation(img: np.ndarray, epsilon: float = 7.0) -> np.ndarray:
    h, w = img.shape[:2]
    rng = np.random.default_rng()
    result = img.astype(np.float32)
    channels = img.shape[2] if img.ndim == 3 else 1

    for c in range(channels):
        ch = (img[:, :, c] if img.ndim == 3 else img).astype(np.float32)

        gx = np.zeros_like(ch)
        gx[:, 1:-1] = ch[:, 2:] - ch[:, :-2]
        gy = np.zeros_like(ch)
        gy[1:-1, :] = ch[2:, :] - ch[:-2, :]

        grad_mag = np.sqrt(gx ** 2 + gy ** 2)
        grad_mag_norm = grad_mag / (grad_mag.max() + 1e-6)

        # Strong perturbation along edges
        perturbation = epsilon * np.sign(gx + gy) * (0.4 + 0.6 * grad_mag_norm)
        # Heavier uniform noise everywhere
        perturbation += rng.uniform(-epsilon * 0.25, epsilon * 0.25, (h, w)).astype(np.float32)

        if img.ndim == 3:
            result[:, :, c] = ch + perturbation
        else:
            result = ch + perturbation

    return np.clip(result, 0, 255).astype(np.uint8)
