import pandas as pd
import os
from regex_detector import run_regex_phase
from ml_detector import run_ml_phase

def run_hybrid_detection(df: pd.DataFrame) -> pd.DataFrame:
    """Manages the full, multi-phase detection workflow."""
    print("--- Starting Hybrid Detection Engine ---")
    
    df_after_regex = run_regex_phase(df)
    
    final_results_df = run_ml_phase(df_after_regex)
    
    print("\n--- Hybrid Detection Complete ---")
    return final_results_df

if __name__ == "__main__":

    bucket_file = os.path.join("..", "Bucket", "parsed_data.csv")
    
    try:
        input_df = pd.read_csv(bucket_file)
       
        if 'attack_type' in input_df.columns:
            input_df['attack_type'] = input_df['attack_type'].astype(object)
 
        results_df = run_hybrid_detection(input_df)
        
        results_df.to_csv(os.path.join("..", "Bucket", "detection_results.csv"), index=False)
        print(f"\n[💾] Full results saved to: ../Bucket/detection_results.csv")
        
    except FileNotFoundError:
        print(f"[!] Error: Input file not found at {bucket_file}")
