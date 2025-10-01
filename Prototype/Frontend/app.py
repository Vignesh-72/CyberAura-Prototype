import streamlit as st
import pandas as pd
import os
import sys
from io import StringIO
import plotly.express as px
import time

# --- Add Backend to Python Path ---
# Corrected base_dir to point to the project root (up two levels from app.py)
base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if base_dir not in sys.path:
    sys.path.insert(0, base_dir)

try:
    # Corrected imports to be absolute from the project root
    from Prototype.Backend.Parser.pcap_parser import parse_pcap_to_df
    from Prototype.Backend.Detector.regex_detector import run_regex_phase
    from Prototype.Backend.Detector.ml_detector import run_ml_phase
except ImportError as e:
    st.error(f"Fatal Error: Could not import backend modules: {e}. Please ensure the folder structure is correct.")
    st.stop()

# --- HELPER FUNCTIONS ---

def find_test_files():
    """Finds all pcap and csv files in the Dataset directory and structures them for the UI."""
    test_files = {}
    dataset_path = os.path.join(base_dir, 'Dataset')
    ipdr_path = os.path.join(dataset_path, 'IPDR Dataset')

    # 1. Define and add the main comprehensive sample files first
    recommended_files = {
        "Recommended Demo: All Attacks (CSV)": os.path.join(ipdr_path, "sample1_dataset.csv"),
        "Demo: SQL & Command Injection (PCAP)": os.path.join(ipdr_path, "sample2_dataset(sql & command injection).pcap"),
        "Demo: XSS & File Inclusion (PCAP)": os.path.join(ipdr_path, "sample3_dataset(xss,fileInclusion).pcap"),
        "Demo: Benign Traffic (No Attacks) (PCAP)": os.path.join(ipdr_path, "sample4_dataset(no_attack).pcap")
    }

    for display_name, full_path in recommended_files.items():
        if os.path.exists(full_path):
            test_files[display_name] = full_path

    # 2. Add individual attack files for more specific testing
    pcap_path = os.path.join(dataset_path, 'Attack Pcaps')
    if os.path.isdir(pcap_path):
        for root, _, files in os.walk(pcap_path):
            for file in files:
                if file.endswith('.pcap'):
                    full_path = os.path.join(root, file)
                    attack_type = os.path.basename(root).replace("_", " ").title()
                    display_name = f"Specific Attack: {attack_type} (PCAP)"
                    if display_name not in test_files:
                         test_files[display_name] = full_path
                
    return test_files

def pair_transactions_from_csv(df: pd.DataFrame) -> pd.DataFrame:
    """Pairs requests and responses from a raw log CSV."""
    paired_records, open_requests = [], {}
    for _, row in df.iterrows():
        try:
            is_request = pd.notna(row.get('url')) and pd.isna(row.get('status_code'))
            is_response = pd.notna(row.get('status_code'))
            if is_request:
                stream_key = (row['src_ip'], row['src_port'], row['dst_ip'], row['dst_port'])
                open_requests[stream_key] = row.to_dict()
            elif is_response:
                response_key = (row['dst_ip'], row['dst_port'], row['src_ip'], row['src_port'])
                if response_key in open_requests:
                    record = open_requests.pop(response_key)
                    record['status_code'] = row['status_code']
                    paired_records.append(record)
        except (KeyError, IndexError, TypeError):
            continue
    return pd.DataFrame(paired_records)

def get_threat_level(ratio):
    """Returns a color and descriptive text based on the attack percentage."""
    if ratio > 80: return "#d32f2f", "CRITICAL ACTIVITY"
    if ratio > 50: return "#ff4b4b", "HIGH ACTIVITY"
    if ratio > 20: return "#ffc107", "ELEVATED ACTIVITY"
    return "green", "LOW ACTIVITY"

def display_prototype_info():
    """Displays information about the prototype's capabilities in a styled container."""
    with st.container(border=True):
        st.markdown("### 📖 About This Prototype")
        st.markdown("""
        This **CyberAura** prototype demonstrates a hybrid detection engine for identifying URL-based attacks. It uses a two-phase approach to prove the effectiveness of our methodology for the SIH Grand Finale.
        """)
        
        st.markdown("#### Detection Capabilities:")
        st.markdown("""
        The engine is currently configured to detect the following attack types:
        - **SQL Injection (SQLi)**
        - **Cross-Site Scripting (XSS)** - *Stored, Reflected, and DOM-based*
        - **Command Injection**
        - **File Inclusion**
        """)

        col1, col2 = st.columns(2)
        with col1:
            st.info("**🔍 Phase 1: Regex Engine**\nA high-speed scanner using patterns to find *known* attacks in URLs.", icon="🔍")
        with col2:
            st.success("**🤖 Phase 2: ML Model**\nA classifier trained to find *complex or hidden* attacks by analyzing URL features.", icon="🤖")

def display_team_info():
    """Displays information about the team members and their roles."""
    with st.container(border=True):
        st.markdown("### 👥 Meet the Team: CyberAura")
        st.markdown("This prototype was proudly developed for the Smart India Hackathon Grand Finale by:")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.markdown("**Vignesh S**<br>*Project Lead & System Architect*", unsafe_allow_html=True)
            st.markdown("**Thasmiya Kulsum K**<br>*Backend Development (Parsers & Engine)*", unsafe_allow_html=True)
        with col2:
            st.markdown("**UMAR FAROOQ .V .H**<br>*Machine Learning & Model Training*", unsafe_allow_html=True)
            st.markdown("**Sheema Kaunain S.H**<br>*Frontend Development (Streamlit UI/UX)*", unsafe_allow_html=True)
        with col3:
            st.markdown("**Froz Naasim N**<br>*Dataset Management & Regex Engine*", unsafe_allow_html=True)
            st.markdown("**Shahana Muskaan G I**<br>*Testing, Validation & Documentation*", unsafe_allow_html=True)

def run_analysis_pipeline(file_input, is_uploaded_file=True):
    """Handles the entire backend analysis process with UI updates."""
    with st.status("Executing Hybrid Detection Pipeline...", expanded=True) as status:
        time.sleep(1)
        status.update(label="Phase 1: Parsing Input File...")
        st.write("➡️ **Step 1: Parsing Input File...**")

        file_name = file_input.name if is_uploaded_file else os.path.basename(file_input)
        file_extension = os.path.splitext(file_name)[1]
        parsed_df = None
        try:
            if file_extension == '.pcap':
                if is_uploaded_file:
                    temp_dir = "temp_uploads"
                    os.makedirs(temp_dir, exist_ok=True)
                    pcap_path = os.path.join(temp_dir, file_name)
                    with open(pcap_path, "wb") as f: f.write(file_input.getbuffer())
                    parsed_df = parse_pcap_to_df(pcap_path)
                else:
                    parsed_df = parse_pcap_to_df(file_input)
            else: # .csv
                if is_uploaded_file:
                    stringio = StringIO(file_input.getvalue().decode("utf-8"))
                    temp_df = pd.read_csv(stringio)
                else:
                    temp_df = pd.read_csv(file_input)

                if all(col in temp_df.columns for col in ['url', 'status_code']):
                    parsed_df = temp_df
                else:
                    parsed_df = pair_transactions_from_csv(temp_df)
        except Exception as e:
            status.update(label="Parsing Failed!", state="error", expanded=True)
            st.error(f"Could not parse the input file. Error: {e}")
            return None

        if parsed_df is None or parsed_df.empty or 'url' not in parsed_df.columns:
            status.update(label="Parsing Failed!", state="error", expanded=True)
            st.error("The parsed file is empty or missing the required 'url' column. Please check the file format.")
            return None
        
        if 'attack_type' not in parsed_df.columns: parsed_df['attack_type'] = None
        parsed_df['attack_type'] = parsed_df['attack_type'].astype(object)

        st.write(f"✅ **Parsing Complete:** Found {len(parsed_df)} total transactions.")
        time.sleep(1.5)
        status.update(label="Phase 2: Regex Detection...")
        st.write("➡️ **Step 2: Running Regex Detector...**")
        df_after_regex = run_regex_phase(parsed_df.copy())
        regex_hits = df_after_regex['attack_type'].notna().sum()
        st.write(f"✅ **Regex Analysis Complete:** Identified {regex_hits} known attack patterns.")
        time.sleep(1.5)
        status.update(label="Phase 3: ML Detection...")
        st.write("➡️ **Step 3: Running Machine Learning Model...**")
        final_results_df = run_ml_phase(df_after_regex)
        ml_hits = final_results_df['attack_type'].str.contains("ML", na=False).sum()
        st.write(f"✅ **ML Analysis Complete:** Found {ml_hits} new, complex threats.")
        time.sleep(1)
        
        status.update(label="Hybrid Analysis Complete!", state="complete", expanded=False)
        return final_results_df

def display_results_dashboard(results_df):
    """Renders the entire results dashboard."""
    
    with st.container():
        st.markdown("### 📊 Executive Summary")
        with st.container(border=True):
            total_requests = len(results_df)
            attacks_detected = results_df['attack_type'].notna().sum()
            attack_ratio = (attacks_detected / total_requests * 100) if total_requests > 0 else 0
            threat_color, threat_desc = get_threat_level(attack_ratio)
            
            col1, col2, col3 = st.columns(3)
            col1.metric("Total HTTP Transactions", total_requests)

            with col2:
                attack_color = "#ff4b4b" if attacks_detected > 0 else "inherit"
                st.markdown(f"""
                <div style="border: 1px solid rgba(255, 255, 255, 0.2); border-radius: 10px; padding: 15px; text-align: center;">
                    <label style="color: #8e8e8e; font-size: 1.2rem;">Total Attacks Found</label>
                    <div style="font-size: 2.2rem; color: {attack_color};">{attacks_detected}</div>
                </div>
                """, unsafe_allow_html=True)
            
            with col3:
                st.markdown(f"""
                <div style="border: 1px solid rgba(255, 255, 255, 0.2); border-radius: 10px; padding: 15px; text-align: center;">
                    <label style="color: #8e8e8e; font-size: 1.2rem;">Threat Level</label>
                    <div style="font-size: 2.2rem;">{attack_ratio:.1f}%</div>
                    <div style="color: {threat_color}; font-weight: bold;">{threat_desc}</div>
                </div>
                """, unsafe_allow_html=True)

    with st.container():
        st.markdown("### 🧠 Threat Intelligence Breakdown")
        col_a, col_b = st.columns([0.4, 0.6])
        with col_a:
            with st.container(border=True):
                st.subheader("Detections by Engine")
                st.caption("This proves our hybrid methodology...")
                regex_df = results_df[results_df['attack_type'].notna() & ~results_df['attack_type'].str.contains("ML", na=False)]
                ml_df = results_df[results_df['attack_type'].str.contains("ML", na=False)]
                detection_data = pd.DataFrame({'Method': ['🔍 Regex', '🤖 ML'], 'Count': [len(regex_df), len(ml_df)]})
                fig_donut = px.pie(detection_data, names='Method', values='Count', hole=0.6, color_discrete_map={'🔍 Regex':'#d32f2f', '🤖 ML':'#1976d2'})
                fig_donut.update_layout(showlegend=True, paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', legend=dict(yanchor="top", y=0.85, xanchor="left", x=0.25))
                st.plotly_chart(fig_donut, use_container_width=True)
        with col_b:
            with st.container(border=True):
                st.subheader("Top Attack Types")
                st.caption("This shows the most frequent types...")
                if attacks_detected > 0:
                    attack_counts = results_df['attack_type'].value_counts()
                    fig_bar = px.bar(attack_counts, x=attack_counts.index, y=attack_counts.values, labels={'x':'Attack Type', 'y':'Count'}, color=attack_counts.index, color_discrete_map={'XSS':'#ff6f00', 'SQL Injection':'#c62828', 'File Inclusion':'#ad1457', 'ML Detected Malicious':'#1565c0'})
                    fig_bar.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', showlegend=False)
                    st.plotly_chart(fig_bar, use_container_width=True)
                else:
                    st.info("No attacks detected to visualize.")

    with st.container():
        st.markdown("### 📜 Full Transaction Log Explorer")
        st.info("Rows highlighted in RED were found by the Regex engine. Rows in BLUE were found by the Machine Learning model.", icon="ℹ️")
        
        def highlight_attacks(row):
            style = [''] * len(row)
            if pd.notna(row.attack_type):
                color = '#2a1a1a' if "ML" not in str(row.attack_type) else '#1a222a'
                border = '2px solid #d32f2f' if "ML" not in str(row.attack_type) else '2px solid #1976d2'
                style = [f'background-color: {color}; border-left: {border};' for _ in row]
            return style
        st.dataframe(results_df.style.apply(highlight_attacks, axis=1), use_container_width=True)
    
    display_prototype_info()
    st.markdown("---")
    display_team_info()

# --- MAIN APPLICATION FLOW ---
def main():
    st.set_page_config(page_title="CyberAura", page_icon="🛡️", layout="wide")

    with st.sidebar:
        # st.image("https://i.imgur.com/8Nn5xAC.png", width=280)
        st.title("CyberAura Control Panel")
        
        st.markdown("#### Upload a Custom File")
        uploaded_file = st.file_uploader("Upload a PCAP or CSV log file", type=['pcap', 'csv'], label_visibility="collapsed")
        
        st.markdown("---")
        
        st.markdown("#### Or select a sample test file")
        test_files = find_test_files()
        test_file_options = list(test_files.keys())
        
        default_index = 0
        for i, option in enumerate(test_file_options):
            if "Recommended" in option:
                default_index = i
                break
        
        selected_test_file_display = st.selectbox(
            "Choose a sample", 
            test_file_options, 
            index=default_index, 
            label_visibility="collapsed"
        )
        
        st.markdown("---")
        analyze_button = st.button("▶  Analyze Traffic", type="primary", use_container_width=True)
        st.markdown("---")
        
    st.title("🛡️ Cyber Threat Analysis Dashboard")

    if analyze_button:
        file_to_process = None
        is_upload = False

        if uploaded_file is not None:
            file_to_process = uploaded_file
            is_upload = True
            st.sidebar.info(f"Analyzing uploaded file: `{uploaded_file.name}`")
        elif selected_test_file_display:
            file_to_process = test_files[selected_test_file_display]
            is_upload = False
            st.sidebar.info(f"Analyzing sample file: `{os.path.basename(file_to_process)}`")
        
        if file_to_process:
            results = run_analysis_pipeline(file_to_process, is_uploaded_file=is_upload)
            if results is not None:
                st.session_state['results'] = results
        else:
            st.sidebar.warning("Please upload a file or select a sample to analyze.")

    if 'results' in st.session_state:
        display_results_dashboard(st.session_state['results'])
    else:
        st.info("Upload a file or select a sample from the sidebar and click 'Analyze Traffic' to begin.", icon="👈")
        display_prototype_info()
        st.markdown("---")
        display_team_info()

if __name__ == "__main__":
    main()

