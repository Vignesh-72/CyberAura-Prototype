import streamlit as st
import pandas as pd
import pyshark
import tempfile
import os

def process_pcap_to_dataframe(uploaded_file):
    """
    Reads all packets from an uploaded PCAP file, correctly captures packet details,
    and converts them to a pandas DataFrame.
    """
    all_packets_data = []
    temp_pcap_path = None
    try:
        # Save uploaded file to a temporary location for pyshark to read
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp_file:
            tmp_file.write(uploaded_file.getvalue())
            temp_pcap_path = tmp_file.name

        capture = pyshark.FileCapture(temp_pcap_path)
        
        for packet in capture:
            # Initialize dictionary with default None values for each packet
            packet_info = {
                'timestamp': packet.sniff_time.isoformat(),
                'length': packet.length,
                'highest_protocol': packet.highest_layer,
                'src_ip': None, 'dst_ip': None, 'src_port': None, 'dst_port': None,
                'url': None, 'status_code': None
            }
            
            # Safely extract IP, TCP, and UDP layer information
            if 'IP' in packet:
                packet_info['src_ip'] = packet.ip.src
                packet_info['dst_ip'] = packet.ip.dst
            if 'TCP' in packet:
                packet_info['src_port'] = packet.tcp.srcport
                packet_info['dst_port'] = packet.tcp.dstport
            if 'UDP' in packet:
                packet_info['src_port'] = packet.udp.srcport
                packet_info['dst_port'] = packet.udp.dstport

            # Precisely add HTTP data only to the packets where it exists
            if 'HTTP' in packet:
                if hasattr(packet.http, 'request_full_uri'):
                    packet_info['url'] = packet.http.request_full_uri
                if hasattr(packet.http, 'response_code'):
                    packet_info['status_code'] = packet.http.response_code

            all_packets_data.append(packet_info)
            
        capture.close()

    except Exception as e:
        st.error(f"An error occurred during PCAP processing: {e}")
        return None
    finally:
        # Clean up the temporary file
        if temp_pcap_path and os.path.exists(temp_pcap_path):
            os.remove(temp_pcap_path)

    if not all_packets_data:
        return None

    # Create the DataFrame from the collected data
    df = pd.DataFrame(all_packets_data)
    
    # Add the empty column for manual labeling
    df['attack_type'] = ""
    
    # Reorder columns for better readability
    ordered_cols = ['timestamp', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'highest_protocol', 'length', 'url', 'status_code', 'attack_type']
    final_cols = [col for col in ordered_cols if col in df.columns]
    df = df[final_cols]
    
    return df

# --- Streamlit App UI ---

st.set_page_config(layout="wide")
st.title("Universal PCAP to IPDR Converter 📄➡️🧾")
st.write("Upload any PCAP file to convert it into a comprehensive CSV format. An empty 'attack_type' column will be added for your manual labeling.")

# Initialize session state to store the dataframe between button clicks
if 'df' not in st.session_state:
    st.session_state.df = None

# Create the file uploader widget
uploaded_file = st.file_uploader("Choose a PCAP file from your system", type=['pcap', 'pcapng'])

if uploaded_file is not None:
    # Button to trigger the conversion process
    if st.button(f"Convert '{uploaded_file.name}' to CSV"):
        with st.spinner("Processing all packets... This may take a while for large files."):
            st.session_state.df = process_pcap_to_dataframe(uploaded_file)

        if st.session_state.df is not None and not st.session_state.df.empty:
            st.success(f"Successfully converted {len(st.session_state.df)} packets!")
        else:
            st.error("Could not find any processable packets in the uploaded file.")

# Display the data preview and download button only after a successful conversion
if st.session_state.df is not None:
    st.subheader("Converted Data Preview")
    st.dataframe(st.session_state.df.head(10))

    # Prepare data for the download button
    csv_data = st.session_state.df.to_csv(index=False).encode('utf-8')
    
    # Get the base name of the uploaded file (e.g., "sqli_attack")
    base_name = os.path.splitext(uploaded_file.name)[0]
    # Create the desired output filename (e.g., "sqli_attack.csv")
    output_filename = f"{base_name}.csv"

    st.download_button(
       label="📥 Download IPDR as CSV",
       data=csv_data,
       file_name=output_filename,
       mime='text/csv',
    )
