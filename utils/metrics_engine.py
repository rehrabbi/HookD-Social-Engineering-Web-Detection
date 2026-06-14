from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
import Levenshtein
import textstat

def calculate_ml_metrics(y_true, y_pred):
    """
    Calculates classification metrics.
    y_true: List of actual labels (e.g., [1, 0, 1, 1] where 1 is malicious)
    y_pred: List of predicted labels (e.g., [1, 0, 0, 1])
    """
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    
    # Calculate False Negative Rate (FNR = FN / (FN + TP))
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    
    return {
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "false_negative_rate": fnr
    }

def calculate_ocr_accuracy(ground_truth_text, extracted_text):
    """
    Calculates Character Error Rate (CER) and accuracy using Levenshtein distance.
    """
    distance = Levenshtein.distance(ground_truth_text.lower(), extracted_text.lower())
    max_len = max(len(ground_truth_text), len(extracted_text))
    
    if max_len == 0:
        return 1.0 # Both empty means 100% accurate
        
    accuracy = 1 - (distance / max_len)
    return max(0.0, accuracy) # Ensure it doesn't drop below 0

def calculate_verdict_clarity(explanation_text):
    """
    Estimates clarity using the Flesch Reading Ease score.
    Higher score = easier to read and clearer.
    """
    score = textstat.flesch_reading_ease(explanation_text)
    
    # Normalize to a 0-100% clarity percentage (roughly)
    clarity_percentage = max(0, min(100, score))
    return clarity_percentage