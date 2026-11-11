import ipaddress
import socket


def scan_target(target):
    try:
        ipaddress.ip_address(target)

        print("Valid IP address entered.")
        print("Starting scan on target:", target)

        ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            3389: "RDP"
        }

        open_ports = 0
        scan_results = []

        for port, service in ports.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)

            result = sock.connect_ex((target, port))

            if result == 0:
                print("[OPEN] Port", port, "-", service)
                open_ports += 1

                warning = ""

                if port == 21:
                    warning = "FTP may transmit data without encryption."
                    print("[WARNING] FTP may transmit data without encryption.")

                if port == 23:
                    warning = "Telnet transmits data without encryption."
                    print("[WARNING] Telnet transmits data without encryption.")

                if port == 445:
                    warning = "SMB may expose file-sharing services."
                    print("[WARNING] SMB may expose file-sharing services.")

                scan_results.append({
                    "port": port,
                    "service": service,
                    "warning": warning
                })

            sock.close()

        print("Scan completed. Open ports found:", open_ports)

        risk_level = "LOW"

        for result in scan_results:
            if result["port"] in [21, 23, 445]:
                risk_level = "HIGH"
                break

        if risk_level != "HIGH" and open_ports > 0:
            risk_level = "MEDIUM"

        return {
            "open_ports": open_ports,
            "results": scan_results,
            "risk_level": risk_level
        }

    except ValueError:
        print("Invalid IP address entered.")
        return {
            "open_ports": 0,
            "results": [],
            "risk_level": "INVALID"
    }