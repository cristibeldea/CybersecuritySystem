"""
Orchestrator for the 11-stage distortion pipeline.

  Step 0: center-crop to square, resize to TILE_SIZE
  Step 0b: measure Laplacian variance to derive an overall strength factor
           (sharp images → stronger distortion; blurry → gentler)
  Then apply stages 1..11 in fixed order, with each stage receiving
  parameters scaled around the global strength factor.

If ``less_distorted`` is True, each stage uses fixed parameters at the
minimum of its usual range, further reduced 50% toward the neutral
(no-distortion) point.  This is used for "less distorted" decoy images
in the grid.
"""
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
    """Center-crop to square, resize to TILE_SIZE, assess quality,
    then apply the 11-stage distortion pipeline.
    All distortion runs at a uniform TILE_SIZE x TILE_SIZE resolution.

    If less_distorted=True, all layers use fixed parameters at the minimum
    of their usual distortion range (deterministic, not random interval).
    """

    # Step 0: crop to square + resize — before any distortion
    img = _prepare_square(img)
    arr = np.asarray(img).copy()

    if less_distorted:
        s = 0.85  # minimum quality strength
    else:
        s = _quality_strength(arr)

    def _r(base: tuple, neutral: float = 0.0) -> tuple:
        """Scale range; if less_distorted, collapse to lower bound then
        reduce 50% toward the neutral (no-distortion) point."""
        scaled = _scale_range(base, s)
        if less_distorted:
            low = scaled[0]
            v = neutral + LESS_DISTORTED_FACTOR * (low - neutral)
            return (v, v)
        return scaled

    # [1] Per-channel elastic warp
    arr = per_channel_elastic_warp(
        arr,
        alpha_range=_r((10.0, 14.8)),
        sigma_range=_r((4.0, 5.2)),
    )

    # [2] Fourier band erosion (mid + high)
    mid_att = max(0.10, 0.30 * s)
    high_att = max(0.15, 0.45 * s)
    if less_distorted:
        mid_att = 1.0 - LESS_DISTORTED_FACTOR * (1.0 - mid_att)
        high_att = 1.0 - LESS_DISTORTED_FACTOR * (1.0 - high_att)
    arr = fourier_band_erosion(arr, mid_atten=mid_att, high_atten=high_att)

    # [3] Patch jitter
    pj_offset = max(1, int(round(2 * s)))
    if less_distorted:
        pj_offset = max(1, int(round(pj_offset * LESS_DISTORTED_FACTOR)))
    arr = patch_jitter(arr, block_size=20, max_offset=pj_offset)

    # [4] Swirl distortion
    arr = swirl_distortion(
        arr, num_swirls=2,
        strength_range=_r((0.4, 0.6)),
        radius_frac=_r((0.12, 0.18)),
    )

    # [5] Halftone overlay
    ht_blend = min(0.25, 0.12 * s)
    if less_distorted:
        ht_blend *= LESS_DISTORTED_FACTOR
    arr = halftone_overlay(arr, dot_spacing=6, blend=ht_blend)

    # [6] Chromatic aberration
    ca_shift = max(2, int(round(3 * s)))
    if less_distorted:
        ca_shift = max(1, int(round(ca_shift * LESS_DISTORTED_FACTOR)))
    arr = chromatic_aberration(arr, max_shift=ca_shift)

    # [7] Color space rotation
    cs_angle = 22.0 * s
    if less_distorted:
        cs_angle *= LESS_DISTORTED_FACTOR
    arr = color_space_rotation(arr, max_angle_deg=cs_angle)

    # [8] Color jitter
    arr = color_jitter(
        arr,
        brightness_range=_r((-15, 15)),
        contrast_range=_r((0.88, 1.12), neutral=1.0),
        saturation_range=_r((0.82, 1.18), neutral=1.0),
    )

    # [9] Watermark overlay
    wm_opacity = min(0.20, 0.13 * s)
    wm_line_opacity = min(0.16, 0.10 * s)
    if less_distorted:
        wm_opacity *= LESS_DISTORTED_FACTOR
        wm_line_opacity *= LESS_DISTORTED_FACTOR
    arr = watermark_overlay(arr, opacity=wm_opacity, line_opacity=wm_line_opacity)

    # [10] JPEG artifact simulation
    q_low = max(20, int(33 - (s - 1.0) * 15))
    q_high = max(q_low + 3, int(42 - (s - 1.0) * 10))
    if less_distorted:
        q_less = min(95, int(round(q_high + (1.0 - LESS_DISTORTED_FACTOR) * (100 - q_high))))
        arr = jpeg_artifact(arr, quality_range=(q_less, q_less))
    else:
        arr = jpeg_artifact(arr, quality_range=(q_low, q_high))

    # [11] FGSM perturbation (LAST)
    fgsm_eps = 7.0 * s
    if less_distorted:
        fgsm_eps *= LESS_DISTORTED_FACTOR
    arr = fgsm_perturbation(arr, epsilon=fgsm_eps)

    return Image.fromarray(arr)


# Public alias for the orchestrator, matching the conceptual name used
# in the thesis ("apply_pipeline").  ``distort_image`` is retained for
# backward compatibility with the original module.
def apply_pipeline(img: Image.Image, less_distorted: bool = False) -> Image.Image:
    return distort_image(img, less_distorted=less_distorted)
