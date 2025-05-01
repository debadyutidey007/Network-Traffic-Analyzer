# Network Traffic Analyzer

## Overview
The Network Traffic Analyzer is a Flask-based web application designed to monitor, analyze, and visualize network traffic. It provides real-time insights into network activities, detects anomalies using machine learning, and generates detailed reports. The application supports user authentication, incident management, blocklist management, and integration with external threat intelligence services like VirusTotal. It operates in demo mode by default due to the absence of packet capture libraries, simulating network traffic for testing and demonstration purposes.

Features
1. Real-Time Monitoring: Tracks network packets, IP addresses, protocols, and ports.
2. Anomaly Detection: Uses an IsolationForest model to identify unusual traffic patterns.
3. Incident Management: Logs and categorizes security incidents with details like source/destination IPs, protocols, and severity.
4. Blocklist Management: Allows admins to block/unblock IPs and domains.
5. Reporting: Generates PDF reports with visualizations (e.g., protocol distribution charts) using ReportLab and Matplotlib.
6. User Authentication: Supports user login, registration, and admin privileges via Flask-Login.
7. Web Interface: Provides a dashboard, incident details, configuration management, and report downloads.
8. API Endpoints: Offers JSON/CSV exports and statistics for integration with other tools.
9. Threat Intelligence: Queries VirusTotal for domain reputation (requires API key).
10. Encrypted Logging: Encrypts sensitive incident details using Fernet cryptography.
11. Socket.IO Integration: Real-time updates for incidents and analyzer status.

# Requirements
1. Python 3.8+
2. Dependencies (install via pip install -r requirements.txt):
   (i) Flask; (ii) Flask-SocketIO; (iii) Flask-Login; (iv) Flask-SQLAlchemy; (v) scikit-learn; (vi) numpy; (vii) pandas; (viii) matplotlib; (ix) reportlab; (x) cryptography; (xi) requests; (xii) configparser
3. A web browser for accessing the UI
4. (Optional) VirusTotal API key for threat intelligence

# Installation
1. Clone the Repository:
   git clone <repository-url>
   cd network-traffic-analyzer
2. Set Up a Virtual Environment:
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
3. Install Dependencies:
   pip install -r requirements.txt
4. Configure the Application:
   (a) Copy analyzer_config.ini.example to analyzer_config.ini and update settings (e.g., VirusTotal API key).
   (b) Set environment variables if needed (e.g., VT_API_KEY).
5. Initialize the Database:
   python network_traffic_analyzer.py

   This creates the SQLite database and default configurations. An admin user (admin/admin) is created automatically.
6. Run the Application:
   python network_traffic_analyzer.py

   The app runs on http://0.0.0.0:5000 with debug mode enabled.

# Usage
1. Access the Web Interface:
   (a) Open http://localhost:5000 in a browser.
   (b) Log in with admin/admin (change the password after first login).
   (c) Use the dashboard to view recent incidents, severity counts, and analyzer status.
2. Manage Incidents:
   (a) View and filter incidents by severity, protocol, or IP.
   (b) Update incident notes, mark as resolved, or block source IPs (admin only).
3. Configure Settings:
   (a) Admins can update configurations, manage blocklists, and add new users via /config.
4. Generate Reports:
   (a) Navigate to /reports to generate and download PDF reports (general, incidents, traffic, or anomaly).
5. API Access:
   (a) Use endpoints like /api/stats/protocols or /api/recent_incidents for programmatic access (requires login).

# Demo Mode
(a) The application runs in demo mode by default, simulating network traffic with randomized IPs, protocols, and domains.
(b) Packet capture is disabled (PACKET_CAPTURE_AVAILABLE = False) due to missing libraries (e.g., WinPcap/Npcap on Windows).
(c) TLS parsing is also disabled (TLS_AVAILABLE = False).

# Database Schema
1. The application uses SQLAlchemy with SQLite (configurable). Key models:
2. User: Stores user credentials and admin status.
3. Incident: Logs security incidents with encrypted details.
4. PacketStatistics: Tracks packet counts, byte sizes, and anomalies.
5. BlockedIP/BlockedDomain: Manages blocklists.
6. AnalyzerConfig: Stores configuration settings.
7. Report: Records generated report metadata.

# Security Notes
1. Change the default admin password immediately.
2. Store the encryption key (ENCRYPTION_KEY) securely, as it’s required to decrypt incident logs.
3. Use a secure VirusTotal API key and avoid hardcoding it.
4. Deploy with a WSGI server (e.g., Gunicorn) and HTTPS in production.

# Limitations

1. Demo mode only; real packet capture requires additional libraries (e.g., pcapy, pyshark).
2. No support for live packet capture on Windows without WinPcap/Npcap.
3. TLS parsing is disabled, limiting protocol analysis.
4. Reports are limited to recent data (e.g., 100 incidents) for performance.

# Contact
For issues or questions, open an issue on the repository or contact the maintainer at debadyutidey7@gmail.com.
