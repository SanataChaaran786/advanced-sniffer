🛡️ Advanced Network Sniffer
A Python-based network packet sniffer designed to detect and analyze real-time traffic.
This tool performs live packet capture, logs data to .txt and .csv, detects suspicious activity (like SYN floods and port scans), and looks up IP geolocation using ipinfo.io.

🚀 Features
✅ Live packet capture (TCP/UDP/IP)
✅ Real-time alerts for:

Port Scans
SYN Floods
✅ IP Geolocation (Organization + Country)
✅ Logs packets to .txt and .csv
✅ Command-line flags for interface and packet limit
✅ Automatic traffic summary after capture

📂 Project Structure
advanced-sniffer/ ├── advanced_sniffer.py # Main sniffer script ├── requirements.txt # Python dependencies ├── README.md # Project documentation ├── screenshots/ # Output screenshots │ ├── live_capture.png │ ├── traffic_summary.png │ ├── alert_example.png │ └── csv_output.png

📸 Screenshots
📡 Live Capture
Live Capture

📊 Traffic Summary
Traffic Summary

🚨 Alert Example (Port Scan)
Alert

📄 CSV Output
CSV Output

🧪 How to Run
1. Clone this repository
bash: git clone https://github.com/your-username/advanced-sniffer.git cd advanced-sniffer pip install -r requirements.txt python advanced_sniffer.py -c 50 python advanced_sniffer.py -i "Wi-Fi" -c 100

💡 Future Improvements GUI version with Tkinter or PyQt

PDF traffic reports

Interactive IP filtering / blocking

Live graphs using matplotlib

Author: Rayyan Khalil Cybersecurity Intern | Python Enthusiast | Network Sniffing Tools Developer

Connect on LinkedIn https://www.linkedin.com/in/rayyan-chaaran-a3078b288/