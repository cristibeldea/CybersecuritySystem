"""Etapa 11: perturbare adversariala de tip FGSM, model-agnostic."""
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

        perturbation = epsilon * np.sign(gx + gy) * (0.4 + 0.6 * grad_mag_norm)
        perturbation += rng.uniform(-epsilon * 0.25, epsilon * 0.25, (h, w)).astype(np.float32)

        if img.ndim == 3:
            result[:, :, c] = ch + perturbation
        else:
            result = ch + perturbation

    return np.clip(result, 0, 255).astype(np.uint8)
