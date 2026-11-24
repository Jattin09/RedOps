
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import ip_address


def validate_target(target):
    """Validate that the target is a valid IP address."""
    try:
        ip_address(target)
        return True
    except ValueError:
        return False


def scan_port(target, port, timeout=1.0):
    """Check whether a TCP port is open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))

            if result == 0:
                return port

    except (OSError, socket.error):
        pass

    return None


def scan_ports(target, ports, max_workers=50):
    """Scan a list of TCP ports on one authorised IP."""
    if not validate_target(target):
        raise ValueError("Invalid IPv4 address")

    if max_workers < 1 or max_workers > 100:
        raise ValueError("Workers must be between 1 and 100")

    open_ports = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(scan_port, target, port): port
            for port in ports
        }

        for future in as_completed(futures):
            result = future.result()

            if result is not None:
                open_ports.append(result)

    return sorted(open_ports)
