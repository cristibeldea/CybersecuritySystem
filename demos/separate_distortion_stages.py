"""Aplica izolat fiecare dintre cele 11 etape ale pipeline-ului de distorsiune pe o imagine de test."""
import os
import sys

import numpy as np
from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.normpath(os.path.join(HERE, "..", "web"))
if WEB_DIR not in sys.path:
    sys.path.insert(0, WEB_DIR)

from captcha.distort.preprocess import _prepare_square  # noqa: E402
from captcha.distort.quality import _quality_strength, _scale_range  # noqa: E402
from captcha.distort.stage_01_elastic     import per_channel_elastic_warp  # noqa: E402
from captcha.distort.stage_02_fourier     import fourier_band_erosion  # noqa: E402
from captcha.distort.stage_03_patch_jitter import patch_jitter  # noqa: E402
from captcha.distort.stage_04_swirl       import swirl_distortion  # noqa: E402
from captcha.distort.stage_05_halftone    import halftone_overlay  # noqa: E402
from captcha.distort.stage_06_chromatic   import chromatic_aberration  # noqa: E402
from captcha.distort.stage_07_color_rotate import color_space_rotation  # noqa: E402
from captcha.distort.stage_08_color_jitter import color_jitter  # noqa: E402
from captcha.distort.stage_09_watermark   import watermark_overlay  # noqa: E402
from captcha.distort.stage_10_jpeg        import jpeg_artifact  # noqa: E402
from captcha.distort.stage_11_fgsm        import fgsm_perturbation  # noqa: E402

INPUT_DIR  = os.path.join(HERE, "resources_separate_distortion")
OUTPUT_DIR = os.path.join(HERE, "separate_distortions_demo")

VALID_EXTS = {".png", ".jpg", ".jpeg", ".bmp", ".webp", ".tiff", ".tif"}

def _build_stage_runners(arr_clean: np.ndarray):
    """Returneaza lista de (nume, callable) pentru cele 11 etape de distorsiune."""
    s = _quality_strength(arr_clean)

    def _r(base, neutral=0.0):
        return _scale_range(base, s)

    DEMO_BOOST = 1.20

    mid_att   = 1.0 - DEMO_BOOST * (1.0 - (0.30 + 0.21 * s))
    high_att  = 1.0 - DEMO_BOOST * (1.0 - (0.30 + 0.315 * s))
    pj_offset = max(1, int(round(2 * s * DEMO_BOOST)))
    ht_blend  = min(0.30, 0.12 * s * DEMO_BOOST)
    ca_shift  = max(2, int(round(3 * s * DEMO_BOOST)))
    cs_angle  = 60.0 * s * DEMO_BOOST
    wm_op     = min(0.24, 0.13 * s * DEMO_BOOST)
    wm_line   = min(0.20, 0.10 * s * DEMO_BOOST)
    q_low_base  = max(20, int(33 - (s - 1.0) * 15))
    q_high_base = max(q_low_base + 3, int(42 - (s - 1.0) * 10))
    q_low  = max(10, int(round(q_low_base / DEMO_BOOST)))
    q_high = max(q_low + 3, int(round(q_high_base / DEMO_BOOST)))
    fgsm_eps  = 30.0 * s * DEMO_BOOST

    elastic_alpha = (10.0 * DEMO_BOOST, 14.8 * DEMO_BOOST)
    elastic_sigma = ( 4.0 * DEMO_BOOST,  5.2 * DEMO_BOOST)
    swirl_strength = (0.4 * DEMO_BOOST, 0.6 * DEMO_BOOST)
    swirl_radius   = (0.12 * DEMO_BOOST, 0.18 * DEMO_BOOST)
    jitter_brightness = (-45.0 * DEMO_BOOST, 45.0 * DEMO_BOOST)
    jitter_contrast   = (1.0 - DEMO_BOOST * (1.0 - 0.65),
                         1.0 + DEMO_BOOST * (1.35 - 1.0))
    jitter_saturation = (1.0 - DEMO_BOOST * (1.0 - 0.45),
                         1.0 + DEMO_BOOST * (1.55 - 1.0))

    stages = [
        ("01_elastic", lambda a: per_channel_elastic_warp(
            a, alpha_range=_r(elastic_alpha), sigma_range=_r(elastic_sigma))),
        ("02_fourier", lambda a: fourier_band_erosion(
            a, mid_atten=mid_att, high_atten=high_att)),
        ("03_patch_jitter", lambda a: patch_jitter(
            a, block_size=20, max_offset=pj_offset)),
        ("04_swirl", lambda a: swirl_distortion(
            a, num_swirls=2,
            strength_range=_r(swirl_strength),
            radius_frac=_r(swirl_radius))),
        ("05_halftone", lambda a: halftone_overlay(
            a, dot_spacing=6, blend=ht_blend)),
        ("06_chromatic", lambda a: chromatic_aberration(
            a, max_shift=ca_shift)),
        ("07_color_rotate", lambda a: color_space_rotation(
            a, max_angle_deg=cs_angle)),
        ("08_color_jitter", lambda a: color_jitter(
            a,
            brightness_range=_r(jitter_brightness),
            contrast_range=_r(jitter_contrast, neutral=1.0),
            saturation_range=_r(jitter_saturation, neutral=1.0))),
        ("09_watermark", lambda a: watermark_overlay(
            a, opacity=wm_op, line_opacity=wm_line)),
        ("10_jpeg", lambda a: jpeg_artifact(
            a, quality_range=(q_low, q_high))),
        ("11_fgsm", lambda a: fgsm_perturbation(
            a, epsilon=fgsm_eps)),
    ]
    return s, stages

def _find_single_input() -> str:
    if not os.path.isdir(INPUT_DIR):
        raise SystemExit(f"Folderul de intrare nu există: {INPUT_DIR}")
    candidates = [
        f for f in os.listdir(INPUT_DIR)
        if os.path.splitext(f)[1].lower() in VALID_EXTS
        and os.path.isfile(os.path.join(INPUT_DIR, f))
    ]
    if not candidates:
        raise SystemExit(f"Nicio imagine in {INPUT_DIR}.")
    if len(candidates) > 1:
        print(f"[avertisment] gasite {len(candidates)} imagini; o folosesc pe prima: {candidates[0]}")
    return os.path.join(INPUT_DIR, candidates[0])

def main() -> None:
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    src_path = _find_single_input()
    print(f"[1/3] citesc:        {src_path}")

    img = Image.open(src_path).convert("RGB")
    img_square = _prepare_square(img)
    arr_clean = np.asarray(img_square).copy()

    out_orig = os.path.join(OUTPUT_DIR, "00_original_cropped.png")
    img_square.save(out_orig)
    print(f"[2/3] salvat baza:   {out_orig}  ({img_square.size[0]}x{img_square.size[1]})")

    s, stages = _build_stage_runners(arr_clean)
    print(f"[3/3] quality strength s = {s:.3f}; aplic cele 11 etape separat")

    for name, run in stages:
        arr = arr_clean.copy()
        arr = run(arr)
        out_path = os.path.join(OUTPUT_DIR, f"{name}.png")
        Image.fromarray(arr).save(out_path)
        print(f"      {name}  ->  {out_path}")

    print(f"\nGata. 12 fisiere in {OUTPUT_DIR}")

if __name__ == "__main__":
    main()
