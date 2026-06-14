import csv
import os
import Levenshtein
import textstat
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

# Import core phishing scanner and OCR logic
from ml_engine.backend_scanner import scan_logic
from utils.ocr import run_ocr

def calculate_ocr_accuracy(ground_truth_text, live_extracted_text):
    """Compares the live OCR engine text against your clean ground truth text."""
    distance = Levenshtein.distance(ground_truth_text.lower().strip(), live_extracted_text.lower().strip())
    max_len = max(len(ground_truth_text), len(live_extracted_text))
    if max_len == 0: return 1.0
    return max(0.0, 1 - (distance / max_len))

def run_evaluation(csv_filepath):
    print(f"📊 Starting Performance Test via Unified Text Stream ({csv_filepath})...\n")
    
    # Lists for ML agent metrics
    y_true = []
    y_pred = []
    
    # Lists for specialized metrics
    ocr_accuracies = []
    clarity_scores = []
    
    with open(csv_filepath, mode='r', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        
        for row in reader:
            ground_truth_text = row['content'].strip()
            actual_is_malicious = int(row['actual_label'])
            image_path = row.get('original_image_path', '').strip()
            
            if image_path and os.path.exists(image_path):
                try:
                    live_ocr_text = run_ocr(image_path)
                    ocr_acc = calculate_ocr_accuracy(ground_truth_text, live_ocr_text)
                    ocr_accuracies.append(ocr_acc)
                except Exception as ocr_err:
                    print(f"OCR failed for image {image_path}: {ocr_err}")

            # ML Agent Evaluation
            try:
                scan_result = scan_logic(body=ground_truth_text, sender="Evaluation_Pipeline")
                
                predicted_label = scan_result.get('label', 'Safe')
                pred_is_malicious = 1 if predicted_label in ["Phishing", "High Risk"] else 0
                
                y_true.append(actual_is_malicious)
                y_pred.append(pred_is_malicious)
                
                # Verdict Clarity Evaluation 
                explanation = scan_result.get('reason', f"Score: {scan_result.get('confidence', 0)}%")
                clarity_rating = textstat.flesch_reading_ease(explanation)
                clarity_scores.append(max(0, min(100, clarity_rating)))
                
            except Exception as e:
                print(f"❌ Error processing dataset ID {row.get('id')}: {e}")

    # Compute Final Mathematical Metrics
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    
    # Confusion matrix extraction for False Negative Rate
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    
    avg_ocr = (sum(ocr_accuracies) / len(ocr_accuracies)) * 100 if ocr_accuracies else None
    avg_clarity = sum(clarity_scores) / len(clarity_scores) if clarity_scores else 0.0

    # Print Performance
    print("=" * 55)
    print("AGENT COMPREHENSIVE PERFORMANCE REPORT")
    print("=" * 55)
    print(f"Total Text Streams Processed : {len(y_true)}")
    print("-" * 55)
    print(f"Precision                    : {precision * 100:.2f}%")
    print(f"Recall                       : {recall * 100:.2f}%")
    print(f"F1 Score                     : {f1 * 100:.2f}%")
    print(f"False Negative Rate (FNR)    : {fnr * 100:.2f}%  (Critical Threat Bypass)")
    print("-" * 55)
    if avg_ocr is not None:
        print(f"Average OCR Accuracy         : {avg_ocr:.2f}%")
    else:
        print("Average OCR Accuracy         : N/A (No image tracks tested)")
    print(f"Verdict Clarity Score        : {avg_clarity:.1f}/100")
    print("=" * 55)

if __name__ == "__main__":
    run_evaluation("ground_truth.csv")