# AirSentinel-Wireless-Security-Audit-Analysis-Tool

AirSentinel is a cross-platform Python-based GUI tool for wireless network scanning, PCAP analysis, and security auditing.
It helps users identify potential security risks in Wi-Fi networks using live system scans or captured packet data.
Reports can be exported in JSON, Markdown, or PDF formats for documentation and further analysis.

## 🚀 Features
- Live Wireless Network Scan
   - Supports Windows (netsh) and Linux (nmcli)
   - Displays SSID, BSSID, channel, signal strength, and security type
   - Risk assessment based on encryption & authentication
- PCAP File Analysis
  - Uses Scapy to parse beacon frames from .pcap or .pcapng files
  - Extracts SSID, BSSID, channel, and security protocols
  - Risk assessment per network
- Risk Scoring & Color-Coding
  - High Risk (e.g., WEP, Open networks) – 🔴
  - Medium Risk (e.g., WPA/WPA2 with TKIP) – 🟡
  - Low Risk (e.g., WPA3) – 🟢
- Report Generation
  - Export in JSON for raw data
  - Export in Markdown for clean, human-readable reports
  - Export in PDF (via reportlab)
- Cross-Platform GUI
  - Built with PyQt5
  - Tabbed interface for Live Scan, PCAP Analysis, and Reports
 
## 📦 Installation
1️⃣ Clone the repository
<pre>
  git clone https://github.com/YourUsername/AirSentinel.git
  cd AirSentinel
</pre>

2️⃣ Install dependencies
<pre>
  pip install PyQt5 scapy reportlab
</pre>
Note:
- scapy is required only for PCAP analysis
- reportlab is required only for PDF export
- Linux users may need to install nmcli
- Windows users must run with Administrator privileges for full scan results

## 🖥️ Usage
Run the application:
<pre>
  python main.py
</pre>

## Tabs Overview
1. Live Scan
   - Click Start System Scan to detect nearby Wi-Fi networks.
   - Optionally specify an interface (e.g., wlan0).
   - View risk levels directly in the table.
2. PCAP Analysis
   - Open a .pcap or .pcapng file.
   - Extracts Wi-Fi access points and their security configurations.
3. Reports
   - Preview scan results in structured JSON format.
   - Export to JSON, Markdown, or PDF.
  
  ## 📷 Screenshots
  <img width="996" height="732" alt="image" src="https://github.com/user-attachments/assets/02ffea82-8cbb-4b8d-8b37-208751233b54" />
  <img width="995" height="736" alt="image" src="https://github.com/user-attachments/assets/07640acc-dde8-4473-a6e3-d1a7d01bb1b0" />

## 📄 License
 - This project is licensed under the MIT License – you are free to use, modify, and distribute it.

## 🙌 Credits
- PyQt5 – GUI framework
- Scapy – Packet parsing
- ReportLab – PDF export
- Built by Akanksha Mane
