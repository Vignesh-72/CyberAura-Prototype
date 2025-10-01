# 🛡️ CyberAura: Hybrid URL Attack Detection Engine

[![Live App](https://img.shields.io/badge/🚀%20Launch%20App-Streamlit-green?style=for-the-badge)](https://cyberaura.streamlit.app/)
[![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=fff)](#)

CyberAura is a web-based security tool designed to identify URL-based attacks from network traffic data (PCAP files) or log files (CSV). It leverages a powerful hybrid detection engine that combines high-speed pattern matching with intelligent machine learning to provide comprehensive threat analysis.

## 🚀 Live Demo

You can access and test the live prototype here:  
**https://cyberaura.streamlit.app/**

## ✨ Core Features & Methodology

The prototype implements the core features outlined in our initial proposal.

### Hybrid Detection Engine
Utilizes a two-phase approach for maximum accuracy:
- **Phase 1: Regex Engine**: A high-speed scanner using specific, curated patterns to find known attacks that are visible directly in the URL (e.g., `' OR 1=1`).
- **Phase 2: Machine Learning Model**: A trained Random Forest classifier that identifies complex or hidden attacks by analyzing various URL features (length, entropy, character patterns), even when the malicious payload isn't obvious.

### Multi-Format Support
Ingests and analyzes both raw network traffic (`.pcap`) and pre-parsed log files (`.csv`).

### Comprehensive Attack Coverage
The prototype is trained to detect the most common URL-based threats:
- SQL Injection (SQLi)
- Cross-Site Scripting (XSS) - Stored, Reflected, and DOM-based
- Command Injection
- File Inclusion

### Interactive Dashboard
A user-friendly web interface built with Streamlit that provides a clear and immediate summary of the analysis, including metrics, charts, and a detailed, color-coded transaction log.

## 🛠️ Technology Stack

### Backend
- **Python**
- **Data Processing**: Pandas
- **Network Analysis**: Pyshark
- **Machine Learning**: Scikit-learn (Random Forest, TfidfVectorizer), Joblib

### Frontend
- **Streamlit**
- **Plotting**: Plotly Express
