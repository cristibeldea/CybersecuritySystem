"""Orchestrator pentru pipeline-ul de distorsiune in 11 etape."""
import numpy as np
from PIL import Image

from .helpers import LESS_DISTORTED_FACTOR
from .preprocess import _prepare_square
from .quality import _quality_strength, _scale_range
from .stage_01_elastic    import per_channel_elastic_warp
from .stage_02_fourier    import fourier_band_erosion
from .stage_03_patch_jitter import patch_jitter
from .stage_04_swirl      import swirl_distortion
from .stage_05_halftone   import halftone_overlay
from .stage_06_chromatic  import chromatic_aberration
from .stage_07_color_rotate import color_space_rotation
from .stage_08_color_jitter import color_jitter
from .stage_09_watermark  import watermark_overlay
from .stage_10_jpeg       import jpeg_artifact
from .stage_11_fgsm       import fgsm_perturbation

def distort_image(img: Image.Image, less_distorted: bool = False) -> Image.Image:
    """Crop, redimensionare, evaluare calitate si aplicarea celor 11 etape."""

    img = _prepare_square(img)
    arr = np.asarray(img).copy()

    if less_distorted:
        s = 0.85
    else:
        s = _quality_strength(arr)

    def _r(base: tuple, neutral: float = 0.0) -> tuple:
        """Scaleaza un interval; daca less_distorted, colapseaza catre limita inferioara."""
        scaled = _scale_range(base, s)
        if less_distorted:
            low = scaled[0]
            v = neutral + LESS_DISTORTED_FACTOR * (low - neutral)
            return (v, v)
        return scaled

    arr = per_channel_elastic_warp(
        arr,
        alpha_range=_r((10.0, 14.8)),
        sigma_range=_r((4.0, 5.2)),
    )

    mid_att = 0.30 + 0.21 * s
    high_att = 0.30 + 0.315 * s
    if less_distorted:
        mid_att = 1.0 - LESS_DISTORTED_FACTOR * (1.0 - mid_att)
        high_att = 1.0 - LESS_DISTORTED_FACTOR * (1.0 - high_att)
    arr = fourier_band_erosion(arr, mid_atten=mid_att, high_atten=high_att)

    pj_offset = max(1, int(round(2 * s)))
    if less_distorted:
        pj_offset = max(1, int(round(pj_offset * LESS_DISTORTED_FACTOR)))
    arr = patch_jitter(arr, block_size=20, max_offset=pj_offset)

    arr = swirl_distortion(
        arr, num_swirls=2,
        strength_range=_r((0.4, 0.6)),
        radius_frac=_r((0.12, 0.18)),
    )

    ht_blend = min(0.25, 0.12 * s)
    if less_distorted:
        ht_blend *= LESS_DISTORTED_FACTOR
    arr = halftone_overlay(arr, dot_spacing=6, blend=ht_blend)

    ca_shift = max(2, int(round(3 * s)))
    if less_distorted:
        ca_shift = max(1, int(round(ca_shift * LESS_DISTORTED_FACTOR)))
    arr = chromatic_aberration(arr, max_shift=ca_shift)

    cs_angle = 60.0 * s
    if less_distorted:
        cs_angle *= LESS_DISTORTED_FACTOR
    arr = color_space_rotation(arr, max_angle_deg=cs_angle)

    arr = color_jitter(
        arr,
        brightness_range=_r((-45, 45)),
        contrast_range=_r((0.65, 1.35), neutral=1.0),
        saturation_range=_r((0.45, 1.55), neutral=1.0),
    )

    wm_opacity = min(0.20, 0.13 * s)
    wm_line_opacity = min(0.16, 0.10 * s)
    if less_distorted:
        wm_opacity *= LESS_DISTORTED_FACTOR
        wm_line_opacity *= LESS_DISTORTED_FACTOR
    arr = watermark_overlay(arr, opacity=wm_opacity, line_opacity=wm_line_opacity)

    q_low = max(20, int(33 - (s - 1.0) * 15))
    q_high = max(q_low + 3, int(42 - (s - 1.0) * 10))
    if less_distorted:
        q_less = min(95, int(round(q_high + (1.0 - LESS_DISTORTED_FACTOR) * (100 - q_high))))
        arr = jpeg_artifact(arr, quality_range=(q_less, q_less))
    else:
        arr = jpeg_artifact(arr, quality_range=(q_low, q_high))

    fgsm_eps = 30.0 * s
    if less_distorted:
        fgsm_eps *= LESS_DISTORTED_FACTOR
    arr = fgsm_perturbation(arr, epsilon=fgsm_eps)

    return Image.fromarray(arr)

def apply_pipeline(img: Image.Image, less_distorted: bool = False) -> Image.Image:
    return distort_image(img, less_distorted=less_distorted)
