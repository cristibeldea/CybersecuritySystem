"""
``captcha.distort`` — 11-stage adversarial distortion pipeline for CAPTCHA images.

This package is the result of refactoring the original monolithic
``captcha/distort.py`` (≈800 lines) into one file per pipeline stage,
plus shared helpers, quality-assessment utilities and a command-line
driver.  Each stage in the conceptual description of Chapter 3
corresponds one-to-one with a Python module:

    [1]  per_channel_elastic_warp   ← stage_01_elastic.py
    [2]  fourier_band_erosion       ← stage_02_fourier.py
    [3]  patch_jitter               ← stage_03_patch_jitter.py
    [4]  swirl_distortion           ← stage_04_swirl.py
    [5]  halftone_overlay           ← stage_05_halftone.py
    [6]  chromatic_aberration       ← stage_06_chromatic.py
    [7]  color_space_rotation       ← stage_07_color_rotate.py
    [8]  color_jitter               ← stage_08_color_jitter.py
    [9]  watermark_overlay          ← stage_09_watermark.py
    [10] jpeg_artifact              ← stage_10_jpeg.py
    [11] fgsm_perturbation          ← stage_11_fgsm.py

The orchestrator (``distort_image`` / ``apply_pipeline``) lives in
``pipeline.py``.  All public names exported here are kept identical to
those previously exposed by ``captcha/distort.py``, so any
``from captcha.distort import X`` import continues to work unchanged.
"""

# --- Public API: helpers and constants ---
from .helpers import (
    BASE_DIR,
    GRID_DIR,
    IMAGE_EXTENSIONS,
    LESS_DISTORTED_FACTOR,
    ORIGINALS_DIR,
    _bilinear_remap,
    _smooth_field,
)
from .quality import (
    TILE_SIZE,
    _laplacian_variance,
    _quality_strength,
    _scale_range,
)
from .preprocess import _prepare_square

# --- Public API: the 11 distortion stages ---
from .stage_01_elastic      import per_channel_elastic_warp
from .stage_02_fourier      import fourier_band_erosion
from .stage_03_patch_jitter import patch_jitter
from .stage_04_swirl        import swirl_distortion
from .stage_05_halftone     import halftone_overlay
from .stage_06_chromatic    import chromatic_aberration
from .stage_07_color_rotate import color_space_rotation
from .stage_08_color_jitter import color_jitter
from .stage_09_watermark    import watermark_overlay
from .stage_10_jpeg         import jpeg_artifact
from .stage_11_fgsm         import fgsm_perturbation

# --- Public API: orchestrator + CLI helpers ---
from .pipeline import apply_pipeline, distort_image
from .cli import _distort_directory, process_all


__all__ = [
    # constants
    "BASE_DIR", "ORIGINALS_DIR", "GRID_DIR", "IMAGE_EXTENSIONS",
    "LESS_DISTORTED_FACTOR", "TILE_SIZE",
    # helpers
    "_smooth_field", "_bilinear_remap",
    "_laplacian_variance", "_quality_strength", "_scale_range",
    "_prepare_square",
    # 11 distortion stages
    "per_channel_elastic_warp",
    "fourier_band_erosion",
    "patch_jitter",
    "swirl_distortion",
    "halftone_overlay",
    "chromatic_aberration",
    "color_space_rotation",
    "color_jitter",
    "watermark_overlay",
    "jpeg_artifact",
    "fgsm_perturbation",
    # orchestrator + CLI
    "apply_pipeline",
    "distort_image",
    "_distort_directory",
    "process_all",
]
