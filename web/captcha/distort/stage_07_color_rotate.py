"""Etapa 7: rotatia spatiului de culoare RGB in jurul axei gri."""
import numpy as np

def color_space_rotation(img: np.ndarray, max_angle_deg: float = 22.0) -> np.ndarray:
    if img.ndim != 3 or img.shape[2] < 3:
        return img

    rng = np.random.default_rng()
    angle = np.radians(rng.uniform(-max_angle_deg, max_angle_deg))

    cos_a = np.cos(angle)
    sin_a = np.sin(angle)
    k = 1.0 / 3.0

    inv3 = 1.0 / 3.0
    rot = np.array([
        [cos_a + inv3 * (1 - cos_a),
         inv3 * (1 - cos_a) - sin_a / np.sqrt(3),
         inv3 * (1 - cos_a) + sin_a / np.sqrt(3)],
        [inv3 * (1 - cos_a) + sin_a / np.sqrt(3),
         cos_a + inv3 * (1 - cos_a),
         inv3 * (1 - cos_a) - sin_a / np.sqrt(3)],
        [inv3 * (1 - cos_a) - sin_a / np.sqrt(3),
         inv3 * (1 - cos_a) + sin_a / np.sqrt(3),
         cos_a + inv3 * (1 - cos_a)],
    ], dtype=np.float32)

    flat = img.reshape(-1, 3).astype(np.float32)
    rotated = flat @ rot.T
    return np.clip(rotated, 0, 255).astype(np.uint8).reshape(img.shape)
