# Network Traffic Analyzer

<div align="center">

[![Version](https://img.shields.io/badge/Version-1.0.0-blue.svg)](https://github.com/debadyutidey007/Network-Traffic-Analyzer)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/)
[![GitHub stars](https://img.shields.io/github/stars/debadyutidey007/Network-Traffic-Analyzer.svg?style=social)](https://github.com/debadyutidey007/Network-Traffic-Analyzer/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/debadyutidey007/Network-Traffic-Analyzer.svg?style=social)](https://github.com/debadyutidey007/Network-Traffic-Analyzer/network/members)
[![Repo Size](https://img.shields.io/github/repo-size/debadyutidey007/Network-Traffic-Analyzer)](https://github.com/debadyutidey007/Network-Traffic-Analyzer)

A Python-based utility for comprehensive network packet capture, in-depth analysis, and insightful visualization. Designed for network professionals, cybersecurity analysts, and researchers.

</div>

---

## 📜 Overview

The **Network Traffic Analyzer** is a sophisticated, open-source Python-based utility meticulously engineered for the comprehensive capture, in-depth analysis, and insightful visualization of network packets. This robust tool is designed to serve a diverse audience, including network administrators, cybersecurity analysts, software developers, and academic researchers, by offering an unparalleled lens into the intricate dynamics of network communications.

By leveraging the capabilities of this analyzer, users can:

* **Proactively Monitor Network Activity:** Gain granular, real-time visibility into the flow of data across designated network interfaces, enabling continuous oversight of network health and performance.
* **Fortify Security Posture:** Facilitate the identification of anomalous traffic patterns, suspicious connection attempts, and potential indicators of compromise (IoCs), thereby enhancing an organization's defensive capabilities against cyber threats.
* **Expedite Network Troubleshooting:** Precisely pinpoint the root causes of network bottlenecks, misconfigurations, and connectivity failures through meticulous examination of packet-level details and protocol interactions.
* **Deepen Protocol Comprehension:** Acquire practical, hands-on understanding of the operational mechanics of various network protocols within a live environment, augmenting theoretical knowledge with empirical data.

Built upon the extensible framework of **Scapy**, this analyzer provides a highly flexible and powerful platform for dissecting, manipulating, and interpreting the complex tapestry of network traffic.

---

## ✨ Core Capabilities

This Network Traffic Analyzer is equipped with a suite of advanced features, each designed to provide granular control and extract actionable intelligence from network data:

* **Real-time Packet Interception and Display:**
    * **Mechanism:** Employs raw socket programming via Scapy to intercept live network packets directly from specified network interfaces (e.g., Ethernet, Wi-Fi, Loopback).
    * **Output:** Provides immediate, streaming display of essential packet header information (e.g., Source/Destination MAC/IP, Protocol Type, Port Numbers) and, where applicable, a summary of the payload, allowing for instantaneous observation of network events.
    * **Persistence:** Supports continuous packet capture, providing an enduring monitoring capability until explicitly terminated by the user, facilitating the observation of transient network phenomena.

* **Advanced Protocol Dissection and Analysis:**
    * **Deep Packet Inspection (DPI):** Performs multi-layer protocol dissection, meticulously parsing and interpreting fields from the Data Link Layer (Layer 2) up to the Application Layer (Layer 7), depending on the captured protocol stack.
    * **Extensive Protocol Support:** Offers detailed breakdowns for a wide array of common network protocols, including but not limited to IPv4/IPv6, TCP, UDP, ICMP, ARP, DNS, HTTP, and others supported by Scapy.
    * **Human-Readable Interpretation:** Translates complex binary and hexadecimal protocol data into easily digestible, human-readable formats, significantly reducing the cognitive load associated with raw packet analysis.

* **Flexible Berkeley Packet Filter (BPF) Application:**
    * **Precision Filtering:** Integrates native support for BPF syntax, enabling users to construct highly specific filters to narrow down the captured traffic stream. This allows for focused analysis on criteria such as:
        * **Host-based:** `host 192.168.1.100`
        * **Network-based:** `net 10.0.0.0/8`
        * **Protocol-based:** `tcp`, `udp`, `icmp`
        * **Port-based:** `port 80`, `port 443`, `portrange 1024-65535`
        * **Combinations:** `tcp and port 80 and host example.com`
    * **Efficiency:** By pre-filtering packets at the capture stage, the tool minimizes processing overhead and storage requirements, making analysis more efficient and targeted.

* **Comprehensive Statistical Aggregation:**
    * **Real-time Metrics:** Generates dynamic statistics on captured packets, including total packet count, aggregate bytes transferred, and calculated data rates (e.g., packets/second, bytes/second).
    * **Traffic Distribution:** Provides insightful breakdowns of network traffic by various dimensions, such as protocol type, top source/destination IP addresses, and communication pairs.
    * **Operational Insights:** These statistics are invaluable for identifying "top talkers," prevalent protocols, potential network anomalies, and assessing overall network utilization patterns, aiding in capacity planning and performance optimization.

* **Intuitive Command-Line Interface (CLI):**
    * **User-Centric Design:** Features a streamlined, interactive command-line interface that guides users through the entire workflow, from interface selection to filter application and result presentation.
    * **Ease of Use:** Designed for accessibility, allowing both seasoned network professionals and newcomers to quickly initiate captures and interpret results without a steep learning curve.
    * **Efficiency:** The CLI prioritizes rapid interaction and clear output, making it ideal for quick diagnostics and automated scripting.

* **Standardized Data Export Capabilities:**
    * **Offline Analysis:** Facilitates the saving of captured packet data into industry-standard formats, primarily **PCAP (Packet Capture)**, which can be subsequently opened and analyzed by other powerful network analysis tools such as Wireshark.
    * **Forensic & Collaborative Use:** This functionality is critical for long-term data archival, post-incident forensic analysis, and collaborative investigation among security teams.

---

## 🛠 Technologies Utilized

The robust architecture and functional capabilities of this project are underpinned by the following foundational technologies:

* **Python 3.x:** As the primary programming language, Python was selected for its extensive ecosystem of libraries, inherent readability, and strong community support in networking, data processing, and automation. Its versatility allows for rapid prototyping and development of complex network tools.

* **Scapy:** This indispensable Python library forms the core of the analyzer's packet manipulation capabilities. Scapy's unique strength lies in its ability to:
    * Forge or decode packets for a vast number of network protocols.
    * Send packets over the wire and capture incoming traffic.
    * Match requests and replies, enabling stateful protocol analysis.
    * Perform network scanning, discovery, and attack simulations.
    Its powerful features make it the backbone for all packet-level interactions within this analyzer.

* **Pandas (Optional/Future Integration):** While not yet fully integrated, the Pandas library is envisioned for future enhancements. Its robust data structures (DataFrames) and data analysis tools would be leveraged for:
    * Structuring and managing large datasets of captured packet metadata.
    * Performing complex statistical aggregations and time-series analysis.
    * Generating advanced reports and summaries from extensive capture sessions.

* **Matplotlib / Seaborn (Optional/Future Integration):** These powerful Python visualization libraries are earmarked for future development to provide graphical representations of network traffic patterns. Potential visualizations include:
    * Protocol distribution pie charts.
    * Bandwidth utilization graphs over time.
    * Top talker bar charts.
    These visual aids would offer a more intuitive and immediate understanding of network behavior and trends.

---

## 🚀 Installation Guide

To successfully set up and operate the Network Traffic Analyzer on your local machine, please adhere to these detailed installation instructions.

### Prerequisites

Before proceeding with the installation, ensure the following components are present on your system:

* **Python 3.6 or higher:** Download the appropriate installer for your operating system from the official Python website: [https://www.python.org/downloads/](https://www.python.org/downloads/).
* **pip:** Python's standard package installer. It is typically included with Python 3 installations. Verify its presence by running `pip --version` in your terminal.

### Step-by-Step Installation Procedure

1.  **Clone the Repository:**
    Initiate the installation process by cloning the project's Git repository to your preferred local directory:

    ```bash
    git clone [https://github.com/debadyutidey007/Network-Traffic-Analyzer.git](https://github.com/debadyutidey007/Network-Traffic-Analyzer.git)
    cd Network-Traffic-Analyzer
    ```

2.  **Establish a Virtual Environment (Highly Recommended):**
    Creating a dedicated virtual environment is a best practice for Python projects. It isolates project dependencies, preventing conflicts with other Python installations or projects on your system.

    ```bash
    python -m venv venv
    ```

    * **Activate the virtual environment:**
        * **On Linux/macOS:**
            ```bash
            source venv/bin/activate
            ```
        * **On Windows (Command Prompt):**
            ```cmd
            venv\Scripts\activate.bat
            ```
        * **On Windows (PowerShell):**
            ```powershell
            .\venv\Scripts\Activate.ps1
            ```

3.  **Install Project Dependencies:**
    With your virtual environment activated, install all necessary Python packages specified in the `requirements.txt` file. This file lists `scapy` and any other libraries required for the analyzer's operation.

    ```bash
    pip install -r requirements.txt
    ```
    * **Note:** Verify the existence of a `requirements.txt` file in the root of the repository. If it is missing or incomplete, you may need to manually install `scapy` using `pip install scapy`.

4.  **Configure Network Interface Permissions (Crucial):**
    Packet capturing inherently requires elevated privileges to access raw network sockets.

    * **For Linux/macOS Users:** You have two primary methods to grant these permissions:

        * **Option A: Execute with `sudo` (Recommended for Initial Testing/Simplicity):**
            The simplest approach is to run the Python script with superuser privileges each time:
            ```bash
            sudo python main.py
            ```
            While straightforward, this method necessitates entering your password for every execution.

        * **Option B: Grant `cap_net_raw` Capability (More Permanent & Secure for Non-Root):**
            This method allows a non-root user to perform packet capture without requiring `sudo` for every run. It grants the Python executable the `CAP_NET_RAW` and `CAP_NET_ADMIN` capabilities.
            ```bash
            sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/python3.x
            ```
            * **Important:** Replace `/usr/bin/python3.x` with the absolute path to your specific Python 3 executable. You can typically locate this path using `which python` (if your virtual environment is active) or `which python3` from your shell.
            * This command modifies the executable's permissions to allow raw socket operations without full root access.

    * **For Windows Users:**
        On Windows operating systems, running Python scripts that utilize Scapy for packet capture generally requires **Administrator privileges**. Right-click your Command Prompt or PowerShell icon and select "Run as administrator" before executing the script. Furthermore, Scapy on Windows relies on a packet capture driver; thus, you **must install Npcap** (or the older WinPcap) from its official website ([https://nmap.org/npcap/](https://nmap.org/npcap/)) to enable packet capture functionality.

---

## 💡 Usage Guide

Once the Network Traffic Analyzer has been successfully installed and configured, you can initiate its operation from your activated virtual environment.

1.  **Launch the Analyzer:**
    Navigate to the root directory of the cloned project in your terminal and execute the main script:

    ```bash
    python main.py
    ```
    *(Please ensure that `main.py` accurately reflects the name of your primary script file; adjust if necessary, e.g., `python network_analyzer.py`.)*

2.  **Interactive Operational Prompts:**
    Upon execution, the analyzer will present a series of interactive prompts, guiding you through the packet capture and analysis process:

    * **Interface Selection:** You will be prompted to specify the network interface from which to capture traffic (e.g., `eth0`, `wlan0`, `en0`, `Wi-Fi`). Accurate selection is critical for capturing relevant data.
    * **BPF Filter Definition:** You will have the opportunity to input a BPF filter string. This powerful filtering mechanism allows you to precisely define which packets are captured, enabling focused analysis. Examples include:
        * `tcp`: Capture all TCP traffic.
        * `udp port 53`: Capture all UDP traffic on port 53 (DNS queries).
        * `host 192.168.1.100 and port 80`: Capture HTTP traffic to/from a specific IP address.
        * Leave the field empty to capture all traffic on the selected interface.
    * **Capture Control:** Commands will be available to initiate (start) and terminate (stop) the packet capture process, providing full control over the monitoring duration.
    * **Statistical Review:** Access summarized data on captured packets, including aggregate counts, byte totals, and protocol distribution, providing a high-level overview of network activity.
    * **Data Export:** Option to save the captured session to a standard PCAP file, facilitating subsequent offline analysis with advanced tools like Wireshark.

### Illustrative Usage Scenarios

To demonstrate the analyzer's versatility, consider the following practical applications:

* **Comprehensive Network Monitoring:**
    To observe all network traffic flowing through your primary wired interface:
    ```bash
    $ python main.py
    Enter network interface (e.g., eth0, wlan0): eth0
    Enter BPF filter (leave empty for all traffic):
    Starting packet capture on eth0... (Press Ctrl+C to stop)
    ```

* **Targeted Web Traffic Analysis:**
    To capture HTTP (port 80) and HTTPS (port 443) traffic specifically to or from a particular web server (`example.com`) on your wireless interface:
    ```bash
    $ python main.py
    Enter network interface (e.g., eth0, wlan0): wlan0
    Enter BPF filter (e.g., tcp, host 192.168.1.1): (tcp port 80 or tcp port 443) and host example.com
    Starting packet capture on wlan0 with filter '(tcp port 80 or tcp port 443) and host example.com'...
    ```

* **Diagnosing DNS Resolution Issues:**
    To monitor all DNS (UDP port 53) queries and responses on your network interface, which can be crucial for diagnosing name resolution problems:
    ```bash
    $ python main.py
    Enter network interface (e.g., eth0, wlan0): eth0
    Enter BPF filter (leave empty for all traffic): udp port 53
    Starting packet capture on eth0 with filter 'udp port 53'...
    ```

---

## 🤝 Contributing to the Project

We enthusiastically welcome and deeply appreciate contributions from the global open-source community to continually enhance the Network Traffic Analyzer. Your valuable input, whether in the form of bug fixes, new feature implementations, or documentation improvements, is instrumental in evolving this project.

### Guidelines for Contribution

To ensure a smooth and effective contribution process, please adhere to the following guidelines:

1.  **Fork the Repository:** Begin by forking the project's repository to your personal GitHub account. This creates a copy where you can freely make changes.

2.  **Create a Dedicated Feature Branch:** For every new feature or bug fix, establish a new, descriptively named branch from the `main` branch. This isolates your changes and facilitates clear review.

    ```bash
    git checkout -b feature/descriptive-feature-name
    # Example: git checkout -b feature/add-packet-export-option
    ```
    or for bug fixes:
    ```bash
    git checkout -b bugfix/brief-issue-description
    # Example: git checkout -b bugfix/fix-udp-checksum-error
    ```

3.  **Implement and Document Your Changes:** Write your code, ensuring it aligns with the project's existing coding style and best practices. Crucially, include comprehensive comments within your code to explain complex logic, algorithms, and function purposes. Update any relevant documentation (e.g., `README.md`, inline comments) to reflect your changes.

4.  **Thorough Testing:** Before submitting, rigorously test your additions or modifications. Ensure they function as expected, cover edge cases, and do not introduce any regressions or new issues. If applicable, add new unit or integration tests.

5.  **Craft Meaningful Commit Messages:** Write clear, concise, and descriptive commit messages that explain what changes were made and why. Follow [conventional commit guidelines](https://www.conventionalcommits.org/en/v1.0.0/) where possible (e.g., `feat:`, `fix:`, `docs:`).

    ```bash
    git commit -m 'feat: Implement real-time statistical summary for captured protocols'
    # or
    git commit -m 'fix: Correct buffer overflow vulnerability in packet parsing module'
    ```

6.  **Push Changes to Your Branch:** Upload your local changes to your forked repository on GitHub:

    ```bash
    git push origin feature/your-branch-name
    ```

7.  **Submit a Pull Request (PR):**
    * Navigate to the original Network-Traffic-Analyzer repository on GitHub.
    * You should see a prompt to create a new pull request from your recently pushed branch.
    * Provide a detailed and comprehensive description of your pull request. Explain the problem it solves, the solution implemented, any design decisions made, and how it was tested.
    * Reference any related GitHub issues (e.g., `Closes #123`, `Fixes #456`).

### Reporting Issues

If you discover a bug, encounter unexpected behavior, or have a suggestion for a new feature, please open an [issue](https://github.com/debadyutidey007/Network-Traffic-Analyzer/issues) on the GitHub repository's Issues page. When reporting a bug, provide as much detail as possible, including:

* Steps to reproduce the issue.
* Expected behavior versus actual behavior.
* Your operating system, Python version, and any relevant environment details.
* Relevant error messages or tracebacks.

---

## 📄 License

This project is released under the terms of the **MIT License**. This permissive open-source license grants users the freedom to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the software, subject to the inclusion of the original copyright no