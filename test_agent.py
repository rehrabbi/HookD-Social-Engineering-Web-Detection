import csv
import os
import sys
import re
import json
from datetime import datetime
from collections import Counter

import Levenshtein
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score, confusion_matrix

# Evaluate the engine the app actually uses (OLD BACKEND), not ml_engine.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "OLD BACKEND"))
from phish_scanner import scan_logic
from utils.ocr import run_ocr

# --- Generic detail strings the engine adds when it has nothing specific to say ---
GENERIC_DETAILS = {
    "No immediate threats detected.",
    "AI Model detected potential risk patterns.",
}

# --- Map a raw detail string to a signal category (for "which signals matter" analysis) ---
SIGNAL_PATTERNS = [
    ("Link/Sender Mismatch", "mismatch"),
    ("Suspicious TLD", "suspicious tld"),
    ("Suspicious Domain (DGA)", "dga"),
    ("Homoglyph Spoof", "homoglyph"),
    ("Brand Impersonation", "brand"),
    ("Intent / Context", "harvesting intent"),
    ("Advance-Fee (419)", "419"),
    ("BEC / CEO Fraud", "bec"),
    ("Fee Scam", "fee scam"),
    ("Malware Extension", "malware"),
    ("Obfuscation", "obfuscation"),
    ("Marketing / Hype", "hype"),
    ("Credential Request", "credential request"),
    ("Algorithmic Domain", "algorithmic"),
]


def categorize_signals(details):
    found = set()
    for d in details:
        low = d.lower()
        for label, pat in SIGNAL_PATTERNS:
            if pat in low:
                found.add(label)
    return found


def calculate_ocr_accuracy(ground_truth_text, live_extracted_text):
    """Normalized Levenshtein similarity between clean text and OCR output."""
    distance = Levenshtein.distance(ground_truth_text.lower().strip(), live_extracted_text.lower().strip())
    max_len = max(len(ground_truth_text), len(live_extracted_text))
    if max_len == 0:
        return 1.0
    return max(0.0, 1 - (distance / max_len))


# ---------------- Baselines (to answer: is the pipeline better than simple filters?) ----------------

BASELINE_KEYWORDS = [
    "verify", "suspended", "otp", "prize", "winner", "click", "urgent", "account",
    "password", "wire transfer", "customs fee", "claim", "refund", "locked", "confirm",
]
SUSPICIOUS_TLDS = (".xyz", ".top", ".info", ".online", ".club", ".tk", ".ru", ".ml")
URL_RE = re.compile(r'(?:https?://|www\.)\S+|[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b')


def keyword_baseline(text):
    low = text.lower()
    return 1 if any(k in low for k in BASELINE_KEYWORDS) else 0


def domain_baseline(text):
    """Flag if a link looks suspicious (bad TLD or URL shortener)."""
    for link in URL_RE.findall(text):
        low = link.lower()
        if any(low.endswith(t) or t + "/" in low for t in SUSPICIOUS_TLDS):
            return 1
        if "bit.ly" in low or "tinyurl" in low:
            return 1
    return 0


def metrics_block(y_true, y_pred):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "precision": precision_score(y_true, y_pred, zero_division=0) * 100,
        "recall": recall_score(y_true, y_pred, zero_division=0) * 100,
        "f1": f1_score(y_true, y_pred, zero_division=0) * 100,
        "accuracy": accuracy_score(y_true, y_pred) * 100,
        "fnr": (fn / (fn + tp) * 100) if (fn + tp) else 0.0,
        "fpr": (fp / (fp + tn) * 100) if (fp + tn) else 0.0,
        "specificity": (tn / (tn + fp) * 100) if (tn + fp) else 0.0,
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
    }


def run_evaluation(csv_filepath):
    print(f"Starting Performance Test ({csv_filepath})...\n")

    y_true, y_pred = [], []
    base_kw, base_dom = [], []
    ocr_accuracies = []
    clarity_hits = 0          # verdicts with >=1 specific reason
    total_verdicts = 0
    # signal -> [appearances, appearances_on_correct_prediction]
    signal_stats = Counter()
    signal_correct = Counter()

    with open(csv_filepath, mode="r", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        for row in reader:
            ground_truth_text = row["content"].strip()
            actual_is_malicious = int(row["actual_label"])
            image_path = row.get("original_image_path", "").strip()

            # OCR track (only when an image is provided)
            if image_path and os.path.exists(image_path):
                try:
                    live_ocr_text = run_ocr(image_path)
                    ocr_accuracies.append(calculate_ocr_accuracy(ground_truth_text, live_ocr_text))
                except Exception as ocr_err:
                    print(f"OCR failed for image {image_path}: {ocr_err}")

            # Classification track. The dataset is plain text with no sender,
            # so we scan in text-only mode (sender left blank) to measure the
            # engine fairly on message content.
            try:
                scan_result = scan_logic(body=ground_truth_text, sender="")
                predicted_label = scan_result.get("label", "Safe")
                pred_is_malicious = 1 if predicted_label in ["Phishing", "High Risk"] else 0

                y_true.append(actual_is_malicious)
                y_pred.append(pred_is_malicious)
                base_kw.append(keyword_baseline(ground_truth_text))
                base_dom.append(domain_baseline(ground_truth_text))

                # Verdict clarity: does it give a real, specific reason? (Q4)
                details = scan_result.get("details", []) or []
                specific = [d for d in details if d.strip() not in GENERIC_DETAILS]
                total_verdicts += 1
                if specific:
                    clarity_hits += 1

                # Signal contribution (Q3) — only meaningful on positive predictions
                correct = (pred_is_malicious == actual_is_malicious)
                for sig in categorize_signals(details):
                    signal_stats[sig] += 1
                    if correct:
                        signal_correct[sig] += 1

            except Exception as e:
                print(f"Error processing dataset ID {row.get('id')}: {e}")

    # ---------------- Report ----------------
    sysm = metrics_block(y_true, y_pred)
    avg_ocr = (sum(ocr_accuracies) / len(ocr_accuracies)) * 100 if ocr_accuracies else None
    clarity_pct = (clarity_hits / total_verdicts * 100) if total_verdicts else 0.0

    print("=" * 60)
    print("AGENT COMPREHENSIVE PERFORMANCE REPORT")
    print("=" * 60)
    print(f"Total Text Streams Processed : {len(y_true)}")
    print("-" * 60)
    print(f"Accuracy                     : {sysm['accuracy']:.2f}%")
    print(f"Precision                    : {sysm['precision']:.2f}%")
    print(f"Recall                       : {sysm['recall']:.2f}%")
    print(f"F1 Score                     : {sysm['f1']:.2f}%")
    print(f"False Negative Rate (FNR)    : {sysm['fnr']:.2f}%   (missed threats)")
    print(f"False Positive Rate (FPR)    : {sysm['fpr']:.2f}%   (false alarms on legit)")
    print(f"Specificity (TNR)            : {sysm['specificity']:.2f}%")
    print("-" * 60)
    print("Confusion Matrix")
    print(f"                 Predicted Legit   Predicted Phish")
    print(f"  Actual Legit        {sysm['tn']:>5}             {sysm['fp']:>5}")
    print(f"  Actual Phish        {sysm['fn']:>5}             {sysm['tp']:>5}")
    print("-" * 60)
    if avg_ocr is not None:
        print(f"Average OCR Accuracy         : {avg_ocr:.2f}%   ({len(ocr_accuracies)} images)")
    else:
        print("Average OCR Accuracy         : N/A (no image rows in this CSV)")
    print(f"Verdict Clarity Score        : {clarity_pct:.1f}%  (verdicts with a specific reason)")
    print("=" * 60)

    # Baseline comparison (Q1: pipeline vs keyword/domain filtering)
    kwm = metrics_block(y_true, base_kw)
    domm = metrics_block(y_true, base_dom)
    print("\nBASELINE COMPARISON (answers: better than simple filters?)")
    print("-" * 60)
    print(f"{'Approach':<22}{'Prec':>8}{'Recall':>8}{'F1':>8}{'Acc':>8}")
    print(f"{'HookD pipeline':<22}{sysm['precision']:>7.1f}{sysm['recall']:>8.1f}{sysm['f1']:>8.1f}{sysm['accuracy']:>8.1f}")
    print(f"{'Keyword filter':<22}{kwm['precision']:>7.1f}{kwm['recall']:>8.1f}{kwm['f1']:>8.1f}{kwm['accuracy']:>8.1f}")
    print(f"{'Domain/URL filter':<22}{domm['precision']:>7.1f}{domm['recall']:>8.1f}{domm['f1']:>8.1f}{domm['accuracy']:>8.1f}")
    print("-" * 60)

    # Signal contribution (Q3)
    print("\nSIGNAL CONTRIBUTION (which signals drive correct verdicts?)")
    print("-" * 60)
    if signal_stats:
        print(f"{'Signal':<26}{'Fired':>7}{'Correct':>9}{'Acc%':>8}")
        for sig, cnt in signal_stats.most_common():
            corr = signal_correct[sig]
            print(f"{sig:<26}{cnt:>7}{corr:>9}{(corr/cnt*100):>7.0f}%")
    else:
        print("No specific signals fired.")
    print("=" * 60)

    # --- Export results.json for the in-app Metrics page ---
    results = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "dataset": os.path.basename(csv_filepath),
        "total": len(y_true),
        "system": {k: (round(v, 2) if isinstance(v, float) else v) for k, v in sysm.items()},
        "ocr_accuracy": round(avg_ocr, 2) if avg_ocr is not None else None,
        "ocr_count": len(ocr_accuracies),
        "clarity": round(clarity_pct, 1),
        "baselines": {
            "HookD pipeline": {k: round(sysm[k], 1) for k in ("precision", "recall", "f1", "accuracy")},
            "Keyword filter": {k: round(kwm[k], 1) for k in ("precision", "recall", "f1", "accuracy")},
            "Domain/URL filter": {k: round(domm[k], 1) for k in ("precision", "recall", "f1", "accuracy")},
        },
        "signals": [
            {"name": sig, "fired": cnt, "correct": signal_correct[sig],
             "acc": round(signal_correct[sig] / cnt * 100)}
            for sig, cnt in signal_stats.most_common()
        ],
    }
    with open("results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print("Saved results.json (used by the in-app Metrics page).")

    print("\nNOTE: synthetic data validates the pipeline; for the paper, also test on")
    print("real collected screenshots/messages.")


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "ground_truth.csv"
    run_evaluation(path)
