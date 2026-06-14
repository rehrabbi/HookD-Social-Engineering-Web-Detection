import pytesseract
# FIX: Relative import
from .preprocess import preprocess_image 

pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

def extract_text(image):
    return pytesseract.image_to_string(image, config="--psm 6")

def run_ocr(image_path):
    processed_image = preprocess_image(image_path)
    return extract_text(processed_image)