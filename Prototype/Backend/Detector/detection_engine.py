
import pandas as pd
import os
from regex_detector import run_regex_phase

def get_bucket_file_path(filename="parsed_data.csv"): 
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(BASE_DIR, "..", "Bucket", filename)
    return os.path.normpath(file_path)

def run_ml_phase(df: pd.DataFrame) -> pd.DataFrame:
    print("\n[*] Starting ML Detection Phase...")
    print("[+] ML Phase (not yet implemented). Passing data through.")
    return df

def run_hybrid_detection(df: pd.DataFrame) -> pd.DataFrame:
    print("--- Starting Hybrid Detection Engine ---")
    df_after_regex = run_regex_phase(df)
    final_results_df = run_ml_phase(df_after_regex)
    print("\n--- Hybrid Detection Complete ---")
    return final_results_df

def save_results_to_bucket(df: pd.DataFrame, filename: str):
    """Saves the DataFrame with detected attacks to a new CSV file."""
    if df.empty:
        return

    bucket_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "Bucket")
    output_filepath = os.path.join(bucket_path, filename)
    
    df.to_csv(output_filepath, index=False)
    print(f"\n[💾] Success! Full results with detections saved to: {output_filepath}")


if __name__ == "__main__":
    bucket_file = get_bucket_file_path()
    
    try:
        input_df = pd.read_csv(bucket_file)
        if 'attack_type' in input_df.columns:
            input_df['attack_type'] = input_df['attack_type'].astype(object)

        results_df = run_hybrid_detection(input_df)
        

        save_results_to_bucket(results_df, "detection_results.csv")
        
        detected_attacks = results_df[results_df['attack_type'].notna()]
        
        if not detected_attacks.empty:
            print("\n--- Final Detected Attacks (Console Output) ---")
            pd.set_option('display.max_colwidth', None)
            print(detected_attacks[['url', 'attack_type', 'status_code']])
        else:
            print("\n--- No attacks detected. ---")

    except FileNotFoundError:
        print(f"[!] Error: Input file not found at {bucket_file}")