import ipaddress
import socket
import ssl



def detect_service_version(sock, port, target):
    """
    Attempt to identify the service software through its TCP banner.
    """

    try:
        sock.settimeout(2)

        # HTTP and HTTPS service detection
        if port in [80, 443]:

            if port == 443:
                context = ssl.create_default_context()
                connection = context.wrap_socket(
                    sock, server_hostname=target
                )
            else:
                connection = sock

            request = (
                "HEAD / HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                "Connection: close\r\n\r\n"
            )

            connection.sendall(request.encode())

            response = connection.recv(2048).decode(
                "utf-8", errors="replace"
            )

            for line in response.splitlines():
                if line.lower().startswith("server:"):
                    return line.split(":", 1)[1].strip()

            return "Version not disclosed"

        # Other services: attempt to read their initial banner
        banner = sock.recv(1024).decode(
            "utf-8", errors="replace"
        ).strip()

        if banner:
            return banner.splitlines()[0].strip()

        return "Unknown"

    except (OSError, ssl.SSLError, socket.timeout):
        return "Unknown"


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
            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )
            sock.settimeout(1)

            try:
                result = sock.connect_ex((target, port))

                if result == 0:
                    print("[OPEN] Port", port, "-", service)
                    open_ports += 1

                    version = detect_service_version(
                        sock, port, target
                    )

                    print("[VERSION]", version)

                    warning = ""

                    if port == 21:
                        warning = "FTP may transmit data without encryption."

                    elif port == 23:
                        warning = "Telnet transmits data without encryption."

                    elif port == 445:
                        warning = "SMB may expose file-sharing services."

                    if warning:
                        print("[WARNING]", warning)

                    scan_results.append({
                        "port": port,
                        "service": service,
                        "version": version,
                        "warning": warning
                    })

            finally:
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
