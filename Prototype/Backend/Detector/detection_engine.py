import pandas as pd
import os

# Use relative imports to find the sibling detector files
from .regex_detector import run_regex_phase
from .ml_detector import run_ml_phase

# --- Main Orchestrator ---
def run_hybrid_detection(df: pd.DataFrame) -> pd.DataFrame:
    """Manages the full, multi-phase detection workflow."""
    print("--- Starting Hybrid Detection Engine ---")
    
    # Phase 1: Use regex for known patterns
    df_after_regex = run_regex_phase(df)
    
    # Phase 2: Use ML for everything the regex didn't catch
    final_results_df = run_ml_phase(df_after_regex)
    
    print("\n--- Hybrid Detection Complete ---")
    return final_results_df