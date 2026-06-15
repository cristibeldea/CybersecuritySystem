"""Etapa 2: eroziunea benzilor de frecvente medii si inalte in domeniul Fourier."""
import numpy as np

def fourier_band_erosion(img: np.ndarray,
                          mid_low: float = 0.12,
                          mid_high: float = 0.50,
                          mid_atten: float = 0.30,
                          high_start: float = 0.75,
                          high_atten: float = 0.45) -> np.ndarray:
    h, w = img.shape[:2]
    cy, cx = h // 2, w // 2
    max_radius = min(cy, cx)
    rng = np.random.default_rng()

    mid_low = np.clip(mid_low + rng.uniform(-0.015, 0.015), 0.05, 0.20)
    mid_high = np.clip(mid_high + rng.uniform(-0.025, 0.025), 0.40, 0.65)

    Y, X = np.ogrid[:h, :w]
    dist = np.sqrt((X - cx) ** 2 + (Y - cy) ** 2)

    mask = np.ones((h, w), dtype=np.float32)

    r_ml, r_mh = max_radius * mid_low, max_radius * mid_high
    mid_band = (dist >= r_ml) & (dist <= r_mh)
    mask[mid_band] = mid_atten

    r_hs = max_radius * high_start
    high_band = dist >= r_hs
    mask[high_band] = high_atten

    trans = 0.04 * max_radius
    for edge_r, atten_val in [(r_ml, mid_atten), (r_mh, mid_atten), (r_hs, high_atten)]:
        inner = (dist >= edge_r - trans) & (dist < edge_r)
        outer = (dist > edge_r) & (dist <= edge_r + trans)
        if trans > 0:
            mask[inner] = np.clip(atten_val + (1.0 - atten_val) * (edge_r - dist[inner]) / trans, 0, 1)
            mask[outer] = np.clip(atten_val + (1.0 - atten_val) * (dist[outer] - edge_r) / trans, 0, 1)

    result = np.empty_like(img)
    channels = img.shape[2] if img.ndim == 3 else 1
    for c in range(channels):
        ch = img[:, :, c] if img.ndim == 3 else img
        f = np.fft.fftshift(np.fft.fft2(ch.astype(np.float32)))
        f *= mask
        recon = np.fft.ifft2(np.fft.ifftshift(f)).real
        recon = np.clip(recon, 0, 255).astype(np.uint8)
        if img.ndim == 3:
            result[:, :, c] = recon
        else:
            result = recon
    return result
