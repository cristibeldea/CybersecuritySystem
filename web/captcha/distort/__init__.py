"""Pipeline de distorsiune adversariala in 11 etape pentru imaginile CAPTCHA."""

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

from .pipeline import apply_pipeline, distort_image
from .cli import _distort_directory, process_all

__all__ = [
    "BASE_DIR", "ORIGINALS_DIR", "GRID_DIR", "IMAGE_EXTENSIONS",
    "LESS_DISTORTED_FACTOR", "TILE_SIZE",
    "_smooth_field", "_bilinear_remap",
    "_laplacian_variance", "_quality_strength", "_scale_range",
    "_prepare_square",
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
    "apply_pipeline",
    "distort_image",
    "_distort_directory",
    "process_all",
]
