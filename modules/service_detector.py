
import socket

COMMON_SERVICES = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
}


def identify_service(port):
    """Identify a service using its conventional port mapping."""
    return COMMON_SERVICES.get(port, "Unknown")


def probe_http(target, port, timeout=2):
    """Send a basic HTTP request and inspect the response."""
    try:
        with socket.create_connection(
            (target, port), timeout=timeout
        ) as connection:

            connection.settimeout(timeout)

            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                f"User-Agent: RedOps/1.0\r\n"
                f"Connection: close\r\n\r\n"
            )

            connection.sendall(request.encode("ascii"))
            response = connection.recv(4096)

            decoded = response.decode(
                "utf-8", errors="replace"
            )

            if not decoded.startswith("HTTP/"):
                return None

            headers = decoded.split("\r\n")

            server_header = next(
                (
                    line for line in headers
                    if line.lower().startswith("server:")
                ),
                "Server: Not disclosed"
            )

            return {
                "status": headers[0],
                "server": server_header
            }

    except (OSError, socket.timeout):
        return None


def grab_banner(target, port, timeout=2):
    """Attempt to retrieve a basic TCP service banner."""
    try:
        with socket.create_connection(
            (target, port), timeout=timeout
        ) as connection:

            connection.settimeout(timeout)
            banner = connection.recv(1024)

            return banner.decode(
                "utf-8", errors="replace"
            ).strip()

    except (OSError, socket.timeout):
        return None


def detect_services(target, open_ports):
    """Identify services and attempt HTTP or banner detection."""
    results = []

    for port in open_ports:

        http_info = probe_http(target, port)

        if http_info:
            service = "HTTP"
            banner = (
                f"{http_info['status']} | "
                f"{http_info['server']}"
            )
        else:
            service = identify_service(port)
            banner = grab_banner(target, port)

        results.append({
            "port": port,
            "service": service,
            "banner": banner
        })

    return results
