"""
Command-line driver: walk the originals directory tree, distort every
image with the 11-stage pipeline and write the output to the grid tree
preserving the same hierarchy.

  Usage:
      python -m captcha.distort                 # process all
      python -m captcha.distort --category cats # process one category
"""
import argparse
import os
import sys

from PIL import Image

from .helpers import GRID_DIR, IMAGE_EXTENSIONS, ORIGINALS_DIR
from .pipeline import distort_image


def _distort_directory(src_dir: str, dst_dir: str) -> int:
    """Distort all images in src_dir, saving to dst_dir. Returns count."""
    os.makedirs(dst_dir, exist_ok=True)
    files = sorted(
        f for f in os.listdir(src_dir)
        if os.path.splitext(f)[1].lower() in IMAGE_EXTENSIONS
    )
    count = 0
    for fname in files:
        src_path = os.path.join(src_dir, fname)
        dst_path = os.path.join(dst_dir, fname)
        less = "lessdistorted" in fname.lower()
        try:
            img = Image.open(src_path).convert("RGB")
            distorted = distort_image(img, less_distorted=less)
            distorted.save(dst_path, quality=92)
            count += 1
        except Exception as e:
            print(f"    SKIP {fname}: {e}")
    return count


def process_all(category_filter: str = None):
    if not os.path.isdir(ORIGINALS_DIR):
        print(f"ERROR: originals directory not found: {ORIGINALS_DIR}")
        sys.exit(1)

    os.makedirs(GRID_DIR, exist_ok=True)

    total = 0

    # Process top-level categories (e.g. cats, cars, abstract)
    categories = sorted(
        d for d in os.listdir(ORIGINALS_DIR)
        if os.path.isdir(os.path.join(ORIGINALS_DIR, d)) and d != "questions"
    )

    if category_filter:
        categories = [c for c in categories if c == category_filter]
        if not categories:
            print(f"ERROR: category '{category_filter}' not found in {ORIGINALS_DIR}")
            sys.exit(1)

    for cat in categories:
        src_dir = os.path.join(ORIGINALS_DIR, cat)
        dst_dir = os.path.join(GRID_DIR, cat)
        files = [f for f in os.listdir(src_dir)
                 if os.path.splitext(f)[1].lower() in IMAGE_EXTENSIONS]
        if not files:
            continue
        print(f"  [{cat}] {len(files)} images ...")
        total += _distort_directory(src_dir, dst_dir)

        # Process fake subfolder if it exists
        fake_src = os.path.join(src_dir, "fake")
        fake_dst = os.path.join(dst_dir, "fake")
        if os.path.isdir(fake_src):
            fake_files = [f for f in os.listdir(fake_src)
                          if os.path.splitext(f)[1].lower() in IMAGE_EXTENSIONS]
            if fake_files:
                print(f"  [{cat}/fake] {len(fake_files)} images ...")
                total += _distort_directory(fake_src, fake_dst)

    print(f"\nDone. {total} images distorted into {GRID_DIR}")


def main():
    parser = argparse.ArgumentParser(description="Distort CAPTCHA images")
    parser.add_argument("--category", type=str, default=None,
                        help="Process only this category folder")
    args = parser.parse_args()
    process_all(category_filter=args.category)


if __name__ == "__main__":
    main()
