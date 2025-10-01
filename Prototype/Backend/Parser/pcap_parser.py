import pyshark
import os
import pandas as pd

def get_pcap_path():
    """Constructs the full path to the sample pcap file."""
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    pcap_path = os.path.join(BASE_DIR, "..", "..", "..", "Dataset", "Attack Pcaps", "Sql Injection", "sql_injection.pcap")
    return os.path.normpath(pcap_path)

def parse_pcap_to_df(file_path: str) -> pd.DataFrame:
    """
    Reads a PCAP, pairs HTTP requests with their responses, and extracts
    fields into a Pandas DataFrame.
    """
    print(f"[*] Parsing {file_path}...")
    capture = pyshark.FileCapture(file_path, display_filter="http")

    records = []
    open_requests = {}

    for packet in capture:
        try:
            ip_layer = packet.ip
            tcp_layer = packet.tcp
            http_layer = packet.http

            stream_key = (ip_layer.src, tcp_layer.srcport, ip_layer.dst, tcp_layer.dstport)
            
            if hasattr(http_layer, 'request_full_uri'):
                request_data = {
                    'timestamp': packet.sniff_timestamp,
                    'src_ip': ip_layer.src,
                    'src_port': tcp_layer.srcport,
                    'dst_ip': ip_layer.dst,
                    'dst_port': tcp_layer.dstport,
                    'highest_protocol': packet.highest_layer,
                    'length': packet.length,
                    'url': http_layer.request_full_uri,
                }
                open_requests[stream_key] = request_data

            elif hasattr(http_layer, 'response_code'):
                response_key = (ip_layer.dst, tcp_layer.dstport, ip_layer.src, tcp_layer.srcport)
                
                if response_key in open_requests:
                    record = open_requests[response_key]
                    record['status_code'] = http_layer.response_code
                    record['attack_type'] = None
                    records.append(record)
                    del open_requests[response_key]

        except (AttributeError, KeyError):
            continue

    capture.close()
    
    df = pd.DataFrame(records)
    print(f"[+] Done. Extracted {len(df)} complete HTTP transactions.")
    return df
def save_df_to_bucket(df: pd.DataFrame):
    output_filename = "parsed_data.csv" 

    script_dir = os.path.dirname(os.path.abspath(__file__))
    bucket_path = os.path.join(script_dir, "..", "Bucket")

    os.makedirs(bucket_path, exist_ok=True)
    output_filepath = os.path.join(bucket_path, output_filename)
    df.to_csv(output_filepath, index=False)
    print(f"\n[💾] Success! Output saved to: {output_filepath}")

if __name__ == "__main__":
    pcap_file = get_pcap_path()
    http_transactions_df = parse_pcap_to_df(pcap_file)

    save_df_to_bucket(http_transactions_df)