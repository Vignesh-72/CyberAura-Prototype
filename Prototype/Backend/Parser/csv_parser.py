import os
import pandas as pd

def get_csv_path():
    """Constructs the full path to a sample CSV file for testing."""
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    csv_path = os.path.join(BASE_DIR, "..", "..", "..", "Dataset", "IPDR Dataset", "stored_xss.csv")
    return os.path.normpath(csv_path)

def pair_transactions_from_csv(file_path: str) -> pd.DataFrame:
    """
    Loads a raw log CSV, pairs HTTP requests with their responses, and
    returns a clean DataFrame of complete transactions.
    """
    print(f"[*] Loading and pairing transactions from {file_path}...")
    try:
        df = pd.read_csv(file_path)
    except FileNotFoundError:
        print(f"[!] Error: File not found at {file_path}")
        return pd.DataFrame()

    paired_records = []
    open_requests = {}

    # Iterate over each row in the DataFrame to find pairs
    for index, row in df.iterrows():
        # Use pd.notna to handle potential empty cells (NaN)
        is_request = pd.notna(row.get('url'))
        is_response = pd.notna(row.get('status_code'))

        try:
            # Create a key for the TCP stream
            stream_key = (row['src_ip'], row['src_port'], row['dst_ip'], row['dst_port'])

            if is_request:
                # Store the essential request info
                open_requests[stream_key] = {
                    'timestamp': row.get('timestamp'),
                    'src_ip': row.get('src_ip'),
                    'src_port': row.get('src_port'),
                    'dst_ip': row.get('dst_ip'),
                    'dst_port': row.get('dst_port'),
                    'highest_protocol': row.get('highest_protocol'),
                    'length': row.get('length'),
                    'url': row.get('url'),
                }
            elif is_response:
                # The response key is the reverse of the request key
                response_key = (row['dst_ip'], row['dst_port'], row['src_ip'], row['src_port'])
                
                if response_key in open_requests:
                    # Match found! Combine request data with response data
                    record = open_requests[response_key]
                    record['status_code'] = row['status_code']
                    record['attack_type'] = None  # Initialize attack_type
                    
                    paired_records.append(record)
                    
                    # Clean up the dictionary
                    del open_requests[response_key]
        except KeyError:
            # This can happen if a row is missing IP/port info
            print(f"[*] Warning: Skipping malformed row {index}.")
            continue
            
    result_df = pd.DataFrame(paired_records)
    print(f"[+] Done. Paired {len(result_df)} complete HTTP transactions.")
    return result_df

def save_df_to_bucket(df: pd.DataFrame, original_filename: str):
    """Saves the DataFrame to a CSV file inside the Bucket folder."""
    if df.empty:
        print("[!] No data to save.")
        return

    base_name = os.path.basename(original_filename)
    file_name, _ = os.path.splitext(base_name)
    output_filename = f"parsed_{file_name}.csv"
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    bucket_path = os.path.join(script_dir, "..", "Bucket")
    
    os.makedirs(bucket_path, exist_ok=True)
    
    output_filepath = os.path.join(bucket_path, output_filename)
    
    df.to_csv(output_filepath, index=False)
    
    print(f"\n[💾] Success! Output saved to: {output_filepath}")

# --- Main execution block ---
if __name__ == "__main__":
    csv_file = get_csv_path()
    
    # The new function pairs the transactions
    paired_df = pair_transactions_from_csv(csv_file)
    
    # Save the result
    save_df_to_bucket(paired_df, csv_file)