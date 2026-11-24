
import socket
import ipaddress

from concurrent.futures import ThreadPoolExecutor, as_completed


MAX_HOSTS = 256


def validate_network(network):
    """Validate an IPv4 network in CIDR notation."""
    try:
        parsed = ipaddress.ip_network(network, strict=False)

        if parsed.version != 4:
            raise ValueError("Only IPv4 networks are supported.")

        if parsed.num_addresses > MAX_HOSTS:
            raise ValueError(
                f"Network too large. Maximum allowed: {MAX_HOSTS} addresses."
            )

        return parsed

    except ValueError as error:
        raise ValueError(f"Invalid network: {error}")


def enumerate_hosts(network):
    """Return usable host addresses from an IPv4 network."""
    parsed = validate_network(network)

    return [str(host) for host in parsed.hosts()]


def is_host_alive(host, timeout=1.0):
    """
    Check whether a host responds to a TCP connection
    on common service ports.
    """
    common_ports = [22, 80, 443, 445, 3389]

    for port in common_ports:
        try:
            with socket.create_connection(
                (host, port), timeout=timeout
            ):
                return True

        except (OSError, socket.timeout):
            continue

    return False


def discover_hosts(network, max_workers=20):
    """Discover hosts responding on common TCP service ports."""

    hosts = enumerate_hosts(network)

    if not 1 <= max_workers <= 50:
        raise ValueError("Workers must be between 1 and 50")

    alive_hosts = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:

        futures = {
            executor.submit(is_host_alive, host): host
            for host in hosts
        }

        for future in as_completed(futures):
            host = futures[future]

            try:
                if future.result():
                    alive_hosts.append(host)

            except OSError:
                continue

    return sorted(
        alive_hosts,
        key=lambda host: tuple(int(part) for part in host.split("."))
    )
