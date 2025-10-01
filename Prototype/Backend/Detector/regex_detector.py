import pandas as pd
import re
from urllib.parse import unquote

def run_regex_phase(df: pd.DataFrame) -> pd.DataFrame:
    """
    PHASE 1: Decodes URLs and applies regex to label known attacks.
    """
    print("[*] Starting Regex Detection Phase...")
    
    attack_patterns = {
        "XSS": re.compile(
            r"(?:<script.*>)|(?:</script>)|(?:onerror\s*=)|(?:onload\s*=)|(?:javascript:)|(?:%3Cscript)|(?:script%3E)",
            re.IGNORECASE
        ),
        "SQL Injection": re.compile(
            r"(?:\%27)|(?:\')|(?:\-\-)|(?:\%23)|(?:#)|(?:union\s*select)|(?:insert\s*into)|(?:select\s*from)",
            re.IGNORECASE
        ),
        "Command Injection": re.compile(
            r"(?:\|\|)|(?:\%7C\%7C)|(?:\;)|(?:whoami)|(?:net\s*user)|(?:ls\s*-l)|(?:uname\s*-a)",
            re.IGNORECASE
        ),
        "File Inclusion": re.compile(
            r"(?:\.\./)|(?:\.\.\\)|(?:etc/passwd)|(?:php://input)",
            re.IGNORECASE
        )
    }

    df_copy = df.copy()
    df_copy['decoded_url'] = df_copy['url'].fillna('').apply(unquote).apply(unquote)

    for attack_name, pattern in attack_patterns.items():
        matches = df_copy['decoded_url'].str.contains(pattern, regex=True, na=False)
        df_copy.loc[matches & df_copy['attack_type'].isna(), 'attack_type'] = attack_name
        
    df_copy = df_copy.drop(columns=['decoded_url'])
    
    detected_count = df_copy['attack_type'].notna().sum()
    print(f"[+] Regex Phase complete. Found {detected_count} potential attacks.")
    return df_copy