import csv
import textstat
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

# Import core ML phishing scanner logic
from ml_engine.backend_scanner import scan_logic

def run_text_evaluation(csv_filepath):
    print(f"📊 Starting Text-Only Performance Test using {csv_filepath}...\n")
    
    y_true = []
    y_pred = []
    clarity_scores = []
    
    with open(csv_filepath, mode='r', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        
        for row in reader:
            content = row['content'].strip()
            actual_is_malicious = int(row['actual_label'])
            
            try:
                # Run the text straight through your ML scanner
                scan_result = scan_logic(body=content, sender="Text_Evaluation_Pipeline")
                
                # Normalize the label to binary classification
                predicted_label = scan_result.get('label', 'Safe')
                pred_is_malicious = 1 if predicted_label in ["Phishing", "High Risk"] else 0
                
                y_true.append(actual_is_malicious)
                y_pred.append(pred_is_malicious)
                
                # Evaluate the readability of the explanation
                explanation = scan_result.get('reason', f"Score: {scan_result.get('confidence', 0)}%")
                clarity_rating = textstat.flesch_reading_ease(explanation)
                clarity_scores.append(max(0, min(100, clarity_rating)))
                
            except Exception as e:
                print(f"Error processing dataset ID {row.get('id')}: {e}")

    # --- Compute Final Mathematical Metrics ---
    # zero_division=0 prevents crashes if the model guesses "Safe" for everything
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    
    # Calculate the False Negative Rate
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    
    avg_clarity = sum(clarity_scores) / len(clarity_scores) if clarity_scores else 0.0

    # Performance Report
    print("=" * 55)
    print("ML ENGINE: TEXT & URL PERFORMANCE REPORT")
    print(f"Total Text Streams Processed : {len(y_true)}")
    print(f"Precision                    : {precision * 100:.2f}%")
    print(f"Recall                       : {recall * 100:.2f}%")
    print(f"F1 Score                     : {f1 * 100:.2f}%")
    print(f"False Negative Rate (FNR)    : {fnr * 100:.2f}%  (Threats that bypassed)")
    print(f"Verdict Clarity Score        : {avg_clarity:.1f}/100")
    print("=" * 55)

if __name__ == "__main__":
    run_text_evaluation("text_ground_truth.csv")