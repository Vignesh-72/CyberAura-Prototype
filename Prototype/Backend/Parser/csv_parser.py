import os
import pandas as pd

def get_csv_path():
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    csv_path = os.path.join(BASE_DIR, "..", "..", "..", "Dataset", "IPDR Dataset", "command_injection.csv")
    return os.path.normpath(csv_path)

def pair_transactions_from_csv(file_path: str) -> pd.DataFrame:
    print(f"[*] Loading and pairing transactions from {file_path}...")
    try:
        df = pd.read_csv(file_path)
    except FileNotFoundError:
        print(f"[!] Error: File not found at {file_path}")
        return pd.DataFrame()
    paired_records = []
    open_requests = {}
    for index, row in df.iterrows():
        is_request = pd.notna(row.get('url'))
        is_response = pd.notna(row.get('status_code'))
        try:
            stream_key = (row['src_ip'], row['src_port'], row['dst_ip'], row['dst_port'])
            if is_request:
                open_requests[stream_key] = {'timestamp': row.get('timestamp'), 'src_ip': row.get('src_ip'), 'src_port': row.get('src_port'), 'dst_ip': row.get('dst_ip'), 'dst_port': row.get('dst_port'), 'highest_protocol': row.get('highest_protocol'), 'length': row.get('length'), 'url': row.get('url')}
            elif is_response:
                response_key = (row['dst_ip'], row['dst_port'], row['src_ip'], row['src_port'])
                if response_key in open_requests:
                    record = open_requests[response_key]
                    record['status_code'] = row['status_code']
                    record['attack_type'] = None
                    paired_records.append(record)
                    del open_requests[response_key]
        except KeyError:
            print(f"[*] Warning: Skipping malformed row {index}.")
            continue
    result_df = pd.DataFrame(paired_records)
    print(f"[+] Done. Paired {len(result_df)} complete HTTP transactions.")
    return result_df

def save_df_to_bucket(df: pd.DataFrame):
    """Saves the DataFrame to a static CSV file named parsed_data.csv."""
    output_filename = "parsed_data.csv" 
    script_dir = os.path.dirname(os.path.abspath(__file__))
    bucket_path = os.path.join(script_dir, "..", "Bucket")
    os.makedirs(bucket_path, exist_ok=True)
    output_filepath = os.path.join(bucket_path, output_filename)
    df.to_csv(output_filepath, index=False)
    print(f"\n[💾] Success! Output saved to: {output_filepath}")

if __name__ == "__main__":
    csv_file = get_csv_path()
    paired_df = pair_transactions_from_csv(csv_file)

    save_df_to_bucket(paired_df)