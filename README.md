# 🛡️ Network Security Scanner

A Python-based network security scanning tool with a Flask web interface. It scans an authorized IPv4 target for commonly used open TCP ports, identifies associated services, and highlights potential security concerns.

## Features

- **IP Address Validation** – Checks whether the target is a valid IP address.
- **TCP Port Scanning** – Scans 11 commonly used ports.
- **Service Identification** – Identifies services associated with open ports.
- **Security Warnings** – Highlights potential concerns involving FTP, Telnet, and SMB.
- **Risk Classification** – Assigns a basic LOW, MEDIUM, or HIGH risk level based on detected open ports.
- **Web Interface** – Provides a simple interface using Flask, HTML, and CSS.
- **Scan Results** – Displays detected open ports, services, and relevant warnings.

## Technologies Used

- Python
- Flask
- HTML5
- CSS3
- Socket Programming
- IP Address Validation (`ipaddress` module)

## Ports Scanned

| Port | Service |
|---|---|
| 21 | FTP |
| 22 | SSH |
| 23 | Telnet |
| 25 | SMTP |
| 53 | DNS |
| 80 | HTTP |
| 110 | POP3 |
| 143 | IMAP |
| 443 | HTTPS |
| 445 | SMB |
| 3389 | RDP |

## Risk Classification

The application uses a basic rule-based classification:

| Risk Level | Description |
|---|---|
| LOW | No open ports detected |
| MEDIUM | Open ports detected without the ports specifically flagged by this tool |
| HIGH | FTP (21), Telnet (23), or SMB (445) detected as open |

*Note: This is a basic indicator based on selected ports, not a comprehensive vulnerability assessment.*

## Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/kennethteh61/network-security-scanner.git
cd network-security-scanner
```

### 2. Install Flask

```bash
pip install flask
```

### 3. Run the application

```bash
python app.py
```

### 4. Open the web interface

Navigate to:

```text
http://127.0.0.1:5000
```

Enter an authorized target IP address to begin scanning.

## Project Structure

```text
network-security-scanner/
├── app.py
├── scanner.py
├── templates/
│   ├── index.html
│   └── results.html
├── static/
│   └── style.css
├── .gitignore
└── README.md
```

## Example Output

```text
Network Security Scanner

Scan Results

Open Ports Found: 1
Risk Level: HIGH

Port 445
Service: SMB
Status: OPEN

Warning:
SMB may expose file-sharing services.
```

## Security Disclaimer

This project is intended for educational purposes and authorized security testing only.

Only scan devices and networks that you own or have explicit permission to assess. The scanner performs basic TCP connection checks and does not identify all vulnerabilities or security misconfigurations.

## Future Improvements

- Support for custom port ranges.
- Scan history and result logging.
- Export scan reports.
- Improved risk assessment.
- Additional service detection.
- Enhanced input validation and error handling.

## Author

**Teh Wei Yao**

GitHub: [@kennethteh61](https://github.com/kennethteh61)