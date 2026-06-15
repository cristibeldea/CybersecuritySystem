"""Estimarea calitatii imaginii prin varianta Laplacian si scalare de intervale."""
import numpy as np

TILE_SIZE = 256

def _laplacian_variance(arr: np.ndarray) -> float:
    """Calculeaza varianta Laplacian ca proxy de claritate."""
    if arr.ndim == 3:
        gray = (0.299 * arr[:, :, 0] + 0.587 * arr[:, :, 1]
                + 0.114 * arr[:, :, 2])
    else:
        gray = arr.astype(np.float32)
    lap = (
        gray[:-2, 1:-1] + gray[2:, 1:-1]
        + gray[1:-1, :-2] + gray[1:-1, 2:]
        - 4.0 * gray[1:-1, 1:-1]
    )
    return float(np.var(lap))

def _quality_strength(arr: np.ndarray) -> float:
    """Mapeaza calitatea imaginii la un multiplicator de intensitate."""
    var = _laplacian_variance(arr)
    t = np.clip((var - 100.0) / 1400.0, 0.0, 1.0)
    return 0.85 + 0.30 * t

def _scale_range(base: tuple, s: float) -> tuple:
    """Scaleaza un interval (low, high) cu un factor in jurul mijlocului."""
    mid = (base[0] + base[1]) / 2.0
    half = (base[1] - base[0]) / 2.0
    return (mid - half * s, mid + half * s)
