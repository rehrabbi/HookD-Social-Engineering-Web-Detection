"""
Batch OCR + scan over a folder of images.

Usage:
    python ocr_batch.py path/to/folder

For every image it runs OCR and the phishing scanner, then writes ocr_batch_results.csv
and prints a summary (how many were flagged phishing/suspicious/safe).

This gives a QUALITATIVE quality check (extracted text + verdict per image).
To get OCR *accuracy* (CER/WER), add a 'truth_text' column with the real text and
compare — or fill ground_truth.csv and use test_agent.py.
"""
import os
import sys
import csv
import random

from utils.ocr import run_ocr
from ml_engine.backend_scanner import scan_logic

IMG_EXTS = {".jpg", ".jpeg", ".png", ".bmp", ".tif", ".tiff", ".webp"}


def main():
    if len(sys.argv) < 2:
        sys.exit("Usage: python ocr_batch.py <folder> [N_random_sample]")
    folder = sys.argv[1]
    if not os.path.isdir(folder):
        sys.exit(f"Not a folder: {folder}")

    images = sorted(f for f in os.listdir(folder) if os.path.splitext(f)[1].lower() in IMG_EXTS)
    if not images:
        sys.exit(f"No images found in {folder}")

    # Optional: randomly sample N images (reproducible)
    if len(sys.argv) > 2:
        n = int(sys.argv[2])
        random.seed(42)
        images = sorted(random.sample(images, min(n, len(images))))
        print(f"Randomly sampled {len(images)} of the images (seed=42).")

    rows = []
    counts = {"Phishing": 0, "Suspicious": 0, "Safe": 0}
    print(f"Processing {len(images)} images from {folder}...\n")

    for name in images:
        path = os.path.join(folder, name)
        try:
            text = run_ocr(path) or ""
            result = scan_logic(body=text, sender="Image_OCR")
            label = result.get("label", "Safe")
            conf = result.get("confidence", 0)
            counts[label] = counts.get(label, 0) + 1
            rows.append({
                "filename": name,
                "chars_extracted": len(text.strip()),
                "verdict": label,
                "confidence": conf,
                "extracted_text": text.strip().replace("\n", " "),
            })
            print(f"  {name:<40} -> {label:<11} {conf}%  ({len(text.strip())} chars)")
        except Exception as e:
            print(f"  {name:<40} -> ERROR: {e}")
            rows.append({"filename": name, "chars_extracted": 0, "verdict": "ERROR",
                         "confidence": 0, "extracted_text": str(e)})

    with open("ocr_batch_results.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["filename", "chars_extracted", "verdict", "confidence", "extracted_text"])
        w.writeheader()
        w.writerows(rows)

    print("\n" + "=" * 50)
    print(f"Total images        : {len(images)}")
    print(f"Flagged Phishing    : {counts.get('Phishing', 0)}")
    print(f"Flagged Suspicious  : {counts.get('Suspicious', 0)}")
    print(f"Flagged Safe        : {counts.get('Safe', 0)}")
    print("=" * 50)
    print("Saved ocr_batch_results.csv")
    print("\nNote: if these are ALL phishing screenshots, the catch-rate (recall) =")
    print("(Phishing + Suspicious) / Total. For OCR character accuracy, add the real text.")


if __name__ == "__main__":
    main()
