
import socket
import ssl
from urllib.parse import urlparse

import requests


SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


def validate_url(url):
    """Validate an HTTP or HTTPS URL."""
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not parsed.hostname:
        raise ValueError("A valid hostname or IP is required.")

    return parsed


def inspect_web_service(url, timeout=5):
    """Collect HTTP response and security header information."""
    validate_url(url)

    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=False,
            verify=True,
            headers={"User-Agent": "RedOps/1.0"}
        )

        headers = response.headers

        security_headers = {
            name: headers.get(name)
            for name in SECURITY_HEADERS
        }

        return {
            "url": url,
            "status_code": response.status_code,
            "server": headers.get("Server", "Not disclosed"),
            "powered_by": headers.get(
                "X-Powered-By", "Not disclosed"
            ),
            "security_headers": security_headers,
            "missing_security_headers": [
                name for name, value in security_headers.items()
                if not value
            ],
            "redirect_location": headers.get("Location"),
        }

    except requests.RequestException as error:
        raise RuntimeError(f"Web inspection failed: {error}")


def inspect_tls_certificate(hostname, port=443, timeout=5):
    """Inspect a publicly presented HTTPS certificate."""
    context = ssl.create_default_context()

    try:
        with socket.create_connection(
            (hostname, port), timeout=timeout
        ) as connection:

            with context.wrap_socket(
                connection, server_hostname=hostname
            ) as secure_connection:

                certificate = secure_connection.getpeercert()

                return {
                    "subject": certificate.get("subject"),
                    "issuer": certificate.get("issuer"),
                    "expires": certificate.get("notAfter"),
                    "tls_version": secure_connection.version(),
                }

    except (OSError, ssl.SSLError, ValueError) as error:
        return {"error": str(error)}
