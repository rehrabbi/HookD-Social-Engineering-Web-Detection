import os
import shutil
import pytesseract
# FIX: Relative import
from .preprocess import preprocess_image


def _locate_tesseract():
    """
    Find the Tesseract engine without relying on a single hardcoded path.
    Order: explicit TESSERACT_CMD env var, then PATH, then the usual Windows
    install locations. Returns the full path to tesseract.exe, or None.
    """
    env_cmd = os.environ.get("TESSERACT_CMD")
    if env_cmd and os.path.exists(env_cmd):
        return env_cmd

    on_path = shutil.which("tesseract")
    if on_path:
        return on_path

    candidates = [
        r"C:\Program Files\Tesseract-OCR\tesseract.exe",
        r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Programs\Tesseract-OCR\tesseract.exe"),
        os.path.expandvars(r"%LOCALAPPDATA%\Tesseract-OCR\tesseract.exe"),
        "/usr/bin/tesseract",            # Linux/Mac fallbacks
        "/usr/local/bin/tesseract",
        "/opt/homebrew/bin/tesseract",
    ]
    for path in candidates:
        if path and os.path.exists(path):
            return path
    return None


# Detect once at import; point pytesseract at it if found.
TESSERACT_PATH = _locate_tesseract()
if TESSERACT_PATH:
    pytesseract.pytesseract.tesseract_cmd = TESSERACT_PATH


def tesseract_available():
    """True if the Tesseract engine was found on this machine."""
    return TESSERACT_PATH is not None


def extract_text(image):
    return pytesseract.image_to_string(image, config="--psm 6")


def run_ocr(image_path):
    if not TESSERACT_PATH:
        raise RuntimeError(
            "The Tesseract OCR engine is not installed on this machine, so "
            "image scanning is unavailable. Install it and restart the app "
            "(e.g. run in an elevated terminal: "
            "winget install -e --id UB-Mannheim.TesseractOCR --source winget)."
        )
    processed_image = preprocess_image(image_path)
    return extract_text(processed_image)
