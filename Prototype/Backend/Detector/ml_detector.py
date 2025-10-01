import pandas as pd
import os
import joblib
from scipy.sparse import hstack
from collections import Counter
import math

# --- Feature Engineering Functions ---
def count_special_chars(url):
    url = str(url)
    special_chars = ['/', '?', '.', '=', '-', '&', '%', '#']
    return sum(url.count(char) for char in special_chars)

def calculate_entropy(text):
    text = str(text)
    if not text: return 0
    entropy = 0; char_counts = Counter(text); text_len = len(text)
    for count in char_counts.values():
        p_x = count / text_len
        entropy += - p_x * math.log2(p_x)
    return entropy

# --- ML Phase Implementation ---
def run_ml_phase(df: pd.DataFrame) -> pd.DataFrame:
    """
    PHASE 2: Uses the trained ML model to classify URLs not caught by regex.
    """
    print("\n[*] Starting ML Detection Phase...")
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(script_dir, "..", "Models", "rf_model.joblib")
    vectorizer_path = os.path.join(script_dir, "..", "Models", "tfidf_vectorizer.joblib")

    try:
        model = joblib.load(model_path)
        vectorizer = joblib.load(vectorizer_path)
    except FileNotFoundError:
        print("[!] Error: Model or vectorizer file not found. Make sure they are in the 'Models' folder.")
        return df

    unlabeled_df = df[df['attack_type'].isna()].copy()

    if unlabeled_df.empty:
        print("[+] No new data for ML phase to analyze.")
        return df

    print(f"[+] Analyzing {len(unlabeled_df)} samples with the ML model...")
    urls_to_analyze = unlabeled_df['url']

    lexical_features = pd.DataFrame(index=urls_to_analyze.index)
    lexical_features['url_length'] = urls_to_analyze.str.len()
    lexical_features['special_char_count'] = urls_to_analyze.apply(count_special_chars)
    lexical_features['entropy'] = urls_to_analyze.apply(calculate_entropy)

    tfidf_features = vectorizer.transform(urls_to_analyze.astype(str))
    X_new = hstack([lexical_features.astype(float), tfidf_features])
    
    predictions = model.predict(X_new)
    
    ml_detected_indices = unlabeled_df.index[predictions == 1]
    unlabeled_df.loc[ml_detected_indices, 'attack_type'] = "ML Detected Malicious"
    
    df.update(unlabeled_df)
    
    detected_count = len(ml_detected_indices)
    print(f"[+] ML Phase complete. Found {detected_count} new potential attacks.")
    return df