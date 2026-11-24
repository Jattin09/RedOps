
import argparse
from datetime import datetime, timezone

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from modules.port_scanner import scan_ports
from modules.service_detector import detect_services
from modules.network_scanner import discover_hosts, validate_network
from modules.web_recon import inspect_web_service
from modules.report_generator import generate_report

console = Console()

VERSION = "1.0.0"


def display_banner():
    banner = r"""
 ____          _  ___
|  _ \ ___  __| |/ _ \ _ __  ___
| |_) / _ \/ _` | | | | '_ \/ __|
|  _ <  __/ (_| | |_| | |_) \__ \
|_| \_\___|\__,_|\___/| .__/|___/
                       |_|
    Automated Reconnaissance Toolkit
    """
    console.print(Panel(banner, style="bold cyan"))
    console.print(f"[green]Version: {VERSION}[/green]\n")


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="RedOps - Automated Reconnaissance Toolkit"
    )

    target_group = parser.add_mutually_exclusive_group(required=True)

    target_group.add_argument(
        "-t", "--target",
        help="Single authorised IPv4 address"
    )

    target_group.add_argument(
        "-n", "--network",
        help="Authorised network in CIDR notation"
    )

    parser.add_argument(
        "-p", "--ports",
        default="1-1000",
        help="TCP port range (default: 1-1000)"
    )

    parser.add_argument(
        "--profile",
        choices=["quick", "standard", "comprehensive"],
        default="standard",
        help="Scan profile"
    )

    parser.add_argument(
        "--report",
        choices=["html", "json"],
        default="html",
        help="Report format"
    )

    parser.add_argument(
        "--web",
        action="store_true",
        help="Perform web reconnaissance"
    )

    return parser.parse_args()


def parse_port_range(port_range):
    try:
        parts = port_range.split("-")

        if len(parts) != 2:
            raise ValueError

        start, end = map(int, parts)

        if not (1 <= start <= end <= 65535):
            raise ValueError

        return list(range(start, end + 1))

    except ValueError:
        raise ValueError("Invalid port range. Example: 1-1000")


def display_results(target, services):
    table = Table(title=f"Scan Results: {target}")

    table.add_column("Port", style="cyan")
    table.add_column("Service", style="green")
    table.add_column("Banner", style="white")

    for service in services:
        table.add_row(
            str(service["port"]),
            service["service"],
            str(service.get("banner") or "Not available")[:100]
        )

    console.print(table)


def run_web_recon(target, services):
    """Inspect detected HTTP and HTTPS services."""

    web_results = []

    for service in services:
        service_name = service["service"]
        port = service["port"]

        if service_name not in (
            "HTTP", "HTTP-ALT", "HTTPS", "HTTPS-ALT"
        ):
            continue

        scheme = (
            "https"
            if service_name in ("HTTPS", "HTTPS-ALT")
            else "http"
        )

        url = f"{scheme}://{target}:{port}"

        console.print(
            f"\n[bold cyan]Web reconnaissance: {url}[/bold cyan]"
        )

        try:
            result = inspect_web_service(url)
            web_results.append(result)

            console.print(
                f"[green]HTTP Status:[/green] {result['status_code']}"
            )
            console.print(
                f"[green]Server:[/green] {result['server']}"
            )
            console.print(
                f"[green]Powered By:[/green] {result['powered_by']}"
            )

            table = Table(title="Security Header Assessment")
            table.add_column("Security Header", style="cyan")
            table.add_column("Status", style="green")

            for header, value in result["security_headers"].items():
                table.add_row(
                    header,
                    "Present" if value else "Missing"
                )

            console.print(table)

        except (RuntimeError, ValueError) as error:
            console.print(
                f"[red]Web inspection failed: {error}[/red]"
            )

    return web_results


def create_report(target, services, web_results, report_format):
    """Collect scan data and generate a report."""

    report_data = {
        "tool": "RedOps",
        "version": VERSION,
        "target": target,
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "open_ports": [item["port"] for item in services],
        "services": services,
        "web_results": web_results
    }

    report_path = generate_report(
        report_data,
        report_format,
        output_dir="reports"
    )

    console.print(
        f"\n[bold green]Report generated successfully![/bold green]"
    )
    console.print(f"[cyan]Saved to: {report_path}[/cyan]")

    return report_path


def scan_single_target(target, ports, web):
    console.print(
        f"\n[bold cyan]Scanning authorised target: {target}[/bold cyan]"
    )

    open_ports = scan_ports(target, ports)

    if not open_ports:
        console.print("[yellow]No open TCP ports found.[/yellow]")
        services = []
    else:
        services = detect_services(target, open_ports)
        display_results(target, services)

    web_results = []

    if web and services:
        web_results = run_web_recon(target, services)

    return services, web_results


def run_single_scan(target, ports, web, report_format):
    services, web_results = scan_single_target(target, ports, web)

    create_report(
        target,
        services,
        web_results,
        report_format
    )


def run_network_scan(network, ports, report_format):
    parsed_network = validate_network(network)

    console.print(
        f"\n[bold cyan]Discovering hosts in: {parsed_network}[/bold cyan]"
    )

    alive_hosts = discover_hosts(str(parsed_network))

    if not alive_hosts:
        console.print("[yellow]No responsive hosts found.[/yellow]")

    all_services = []
    host_results = []

    for host in alive_hosts:
        console.print(
            f"\n[bold cyan]Scanning host: {host}[/bold cyan]"
        )

        open_ports = scan_ports(host, ports)

        if open_ports:
            services = detect_services(host, open_ports)
            display_results(host, services)
        else:
            services = []
            console.print(
                "[yellow]No open selected TCP ports.[/yellow]"
            )

        all_services.extend(services)

        host_results.append({
            "target": host,
            "open_ports": [item["port"] for item in services],
            "services": services,
            "web_results": []
        })

    report_data = {
        "tool": "RedOps",
        "version": VERSION,
        "target": str(parsed_network),
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "open_ports": [
            item["port"] for item in all_services
        ],
        "services": all_services,
        "web_results": [],
        "hosts": host_results
    }

    report_path = generate_report(
        report_data,
        report_format,
        output_dir="reports"
    )

    console.print(
        f"\n[bold green]Network report generated![/bold green]"
    )
    console.print(f"[cyan]Saved to: {report_path}[/cyan]")


def main():
    display_banner()
    args = parse_arguments()

    try:
        ports = parse_port_range(args.ports)

        if args.target:
            run_single_scan(
                args.target,
                ports,
                args.web,
                args.report
            )

        elif args.network:
            if args.web:
                raise ValueError(
                    "--web currently supports single-IP scans only."
                )

            run_network_scan(
                args.network,
                ports,
                args.report
            )

    except (ValueError, RuntimeError, OSError) as error:
        console.print(
            f"[bold red]Error: {error}[/bold red]"
        )


if __name__ == "__main__":
    main()
