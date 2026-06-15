"""Construieste provocarile vizuale ale grilei CAPTCHA."""
import hmac
import json
import mimetypes
import os
import random
from typing import Any, Dict, List, Optional, Tuple

from .constants import GRID_DIR
from .helpers import _b64url_decode, _b64url_encode, _sign, ensure_dirs

def _is_image_file(name: str) -> bool:
    ext = os.path.splitext(name)[1].lower()
    return ext in {".jpg", ".jpeg", ".png", ".webp", ".bmp", ".gif"}

def list_grid_categories() -> List[str]:
    ensure_dirs()
    out: List[str] = []
    for name in os.listdir(GRID_DIR):
        if name == "fake":
            continue
        full = os.path.join(GRID_DIR, name)
        if os.path.isdir(full):
            imgs = [x for x in os.listdir(full) if _is_image_file(x)]
            if imgs:
                out.append(name)
    out.sort()
    return out

def list_images_in_category(category: str) -> List[str]:
    """Returneaza path-urile imaginilor reale dintr-o categorie."""
    folder = os.path.join(GRID_DIR, category)
    if not os.path.isdir(folder):
        return []
    return [
        os.path.join(folder, name)
        for name in os.listdir(folder)
        if _is_image_file(name)
    ]

def list_fake_images_in_category(category: str) -> List[str]:
    """Returneaza path-urile imaginilor false dintr-o categorie."""
    folder = os.path.join(GRID_DIR, category, "fake")
    if not os.path.isdir(folder):
        return []
    return [
        os.path.join(folder, name)
        for name in os.listdir(folder)
        if _is_image_file(name)
    ]

def guess_mimetype(path: str) -> str:
    mt, _ = mimetypes.guess_type(path)
    return mt or "application/octet-stream"

CATEGORY_DISPLAY: Dict[str, str] = {
    "abstract": "abstract art",
    "airplanes": "airplanes",
    "benches": "benches",
    "bicycles": "bicycles",
    "birds": "birds",
    "boats": "boats",
    "bridges": "bridges",
    "buses": "buses",
    "cars": "cars",
    "cats": "cats",
    "chairs": "chairs",
    "chimneys": "chimneys",
    "clocks": "clocks",
    "crosswalks": "crosswalks",
    "dogs": "dogs",
    "doors": "doors",
    "fences": "fences",
    "fire_hydrants": "fire hydrants",
    "flowers": "flowers",
    "horses": "horses",
    "lakes": "lakes",
    "motorcycles": "motorcycles",
    "mountains": "mountains",
    "semaphores": "semaphores",
    "situational": "situational scenes",
    "stairs": "stairs",
    "stop_signs": "stop signs",
    "traffic_lights": "traffic lights",
    "trees": "trees",
    "trucks": "trucks",
    "umbrellas": "umbrellas",
    "windows": "windows",
}

def _make_asset_token(secret: str, nonce: str, payload: Dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = _sign(secret, nonce.encode("utf-8") + b"." + raw)
    return f"{_b64url_encode(raw)}.{sig}"

def _verify_asset_token(secret: str, nonce: str, token: str) -> Optional[Dict[str, Any]]:
    try:
        if "." not in token:
            return None
        b64, sig = token.split(".", 1)
        raw = _b64url_decode(b64)
        expected = _sign(secret, nonce.encode("utf-8") + b"." + raw)
        if not hmac.compare_digest(sig, expected):
            return None
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return None

def _build_tiles(secret: str, nonce: str,
                 items: List[Tuple[str, str, bool]]) -> Tuple[List[Dict], List[str]]:
    """Construieste dict-urile de tile si lista de raspunsuri."""
    random.shuffle(items)
    tiles: List[Dict[str, Any]] = []
    answers: List[str] = []

    for idx, (path, cat, is_answer) in enumerate(items):
        cx = random.uniform(0.45, 0.55)
        cy = random.uniform(0.45, 0.55)
        token = _make_asset_token(secret, nonce, {
            "kind": "grid", "path": path, "idx": idx,
            "cx": round(cx, 4), "cy": round(cy, 4),
        })
        tile_id = str(idx)
        tiles.append({"id": tile_id, "url": f"/captcha/asset/{nonce}/{token}"})
        if is_answer:
            answers.append(tile_id)

    return tiles, sorted(answers)

def _build_select_not_containing(secret: str, nonce: str,
                                 used_categories: List[str]) -> Dict[str, Any]:
    """Grila cu imagini reale plus false dintr-o singura categorie."""
    all_cats = list_grid_categories()
    eligible = [c for c in all_cats
                if c not in used_categories
                and len(list_images_in_category(c)) >= 6
                and len(list_fake_images_in_category(c)) >= 2]
    if not eligible:
        eligible = [c for c in all_cats
                    if len(list_images_in_category(c)) >= 6
                    and len(list_fake_images_in_category(c)) >= 2]
    if not eligible:
        raise RuntimeError("No categories with enough real + fake images")

    cat = random.choice(eligible)
    fakes = list_fake_images_in_category(cat)
    num_fakes = min(len(fakes), random.randint(2, 3))
    chosen_fakes = random.sample(fakes, num_fakes)
    num_real = 9 - num_fakes
    real_imgs = list_images_in_category(cat)
    chosen_real = random.sample(real_imgs, min(num_real, len(real_imgs)))

    items = [(p, cat, False) for p in chosen_real] + \
            [(p, cat, True) for p in chosen_fakes]

    tiles, answers = _build_tiles(secret, nonce, items)

    display_name = CATEGORY_DISPLAY.get(cat, cat.replace("_", " "))

    return {
        "kind": "grid",
        "task_type": "select_not_containing",
        "prompt": f"Select only the pictures that don't contain {display_name}.",
        "expect_count": num_fakes,
        "tiles": tiles,
        "correct_ids": answers,
        "_category": cat,
    }

def build_grid_challenge(secret: str, nonce: str,
                         used_categories: List[str],
                         attempt_index: int = 1) -> Dict[str, Any]:
    """Construieste o provocare de tip 'selecteaza ce nu contine'."""
    ch = _build_select_not_containing(secret, nonce, used_categories)
    ch["attempt_index"] = attempt_index
    return ch
