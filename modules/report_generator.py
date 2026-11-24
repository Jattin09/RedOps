
import json
import html
from pathlib import Path
from datetime import datetime


REPORT_DIRECTORY = Path("reports")


def generate_report_filename(report_format):
    """Generate a timestamped report filename."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"redops_report_{timestamp}.{report_format}"


def generate_json_report(report_data, output_path):
    """Save scan results as JSON."""

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(
            report_data,
            file,
            indent=4,
            ensure_ascii=False
        )

    return output_path


def generate_html_report(report_data, output_path):
    """Generate a professional HTML reconnaissance report."""

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    target = html.escape(str(report_data.get("target", "Unknown")))
    scan_time = html.escape(
        str(report_data.get("scan_time", "Not available"))
    )

    ports = report_data.get("open_ports", [])
    services = report_data.get("services", [])
    web_results = report_data.get("web_results", [])

    # Build service discovery table
    port_rows = ""

    for service in services:
        port = html.escape(str(service.get("port", "")))
        name = html.escape(str(service.get("service", "Unknown")))

        banner = str(service.get("banner") or "Not available")
        safe_banner = html.escape(banner[:180])

        if len(banner) > 180:
            safe_banner += "..."

        port_rows += f"""
        <tr>
            <td class="port-column">{port}</td>
            <td class="service-column">{name}</td>
            <td class="banner-column">{safe_banner}</td>
        </tr>
        """

    if not port_rows:
        port_rows = """
        <tr>
            <td colspan="3">No open TCP ports found.</td>
        </tr>
        """

    # Build web reconnaissance sections
    web_sections = ""

    for result in web_results:
        url = html.escape(str(result.get("url", "")))
        status = html.escape(str(result.get("status_code", "")))
        server = html.escape(str(result.get("server", "")))
        powered_by = html.escape(
            str(result.get("powered_by", "Not disclosed"))
        )

        headers = result.get("security_headers", {})
        header_rows = ""

        for name, value in headers.items():
            safe_name = html.escape(str(name))
            header_status = "Present" if value else "Missing"

            header_rows += f"""
            <tr>
                <td>{safe_name}</td>
                <td>{header_status}</td>
            </tr>
            """

        web_sections += f"""
        <section class="web-section">
            <h3>{url}</h3>

            <p><strong>HTTP Status:</strong> {status}</p>
            <p><strong>Server:</strong> {server}</p>
            <p><strong>Powered By:</strong> {powered_by}</p>

            <h4>Security Headers</h4>

            <table class="security-table">
                <thead>
                    <tr>
                        <th>Security Header</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    {header_rows}
                </tbody>
            </table>
        </section>
        """

    if not web_sections:
        web_sections = "<p>No web reconnaissance results recorded.</p>"

    # Complete HTML document
    document = f"""<!DOCTYPE html>
<html lang="en">

<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<title>RedOps Security Assessment Report</title>

<style>

* {{
    box-sizing: border-box;
}}

body {{
    font-family: Arial, sans-serif;
    background: #f4f6f9;
    color: #202938;
    margin: 0;
    padding: 30px;
    line-height: 1.5;
}}

.container {{
    width: 100%;
    max-width: 1100px;
    margin: auto;
    background: white;
    padding: 30px;
    border-radius: 12px;
}}

h1 {{
    color: #087ea4;
    margin-top: 0;
}}

h2 {{
    color: #263445;
    border-bottom: 2px solid #087ea4;
    padding-bottom: 8px;
    margin-top: 30px;
}}

h3 {{
    color: #087ea4;
    overflow-wrap: anywhere;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    margin: 15px 0 25px;
    table-layout: fixed;
}}

th, td {{
    border: 1px solid #d9dee5;
    padding: 12px;
    text-align: left;
    vertical-align: top;
    overflow-wrap: anywhere;
    word-break: break-word;
}}

th {{
    background: #eaf3f8;
    color: #263445;
}}

.service-table th:first-child,
.service-table td:first-child {{
    width: 12%;
}}

.service-table th:nth-child(2),
.service-table td:nth-child(2) {{
    width: 18%;
}}

.service-table th:nth-child(3),
.service-table td:nth-child(3) {{
    width: 70%;
}}

.security-table th:first-child,
.security-table td:first-child {{
    width: 70%;
}}

.security-table th:last-child,
.security-table td:last-child {{
    width: 30%;
}}

.web-section {{
    margin-top: 25px;
    padding: 15px;
    background: #fafcfe;
    border: 1px solid #e1e7ed;
    border-radius: 8px;
}}

footer {{
    margin-top: 35px;
    padding-top: 15px;
    border-top: 1px solid #ddd;
    color: #687386;
    font-size: 13px;
}}

@media (max-width: 600px) {{
    body {{
        padding: 10px;
    }}

    .container {{
        padding: 15px;
    }}

    th, td {{
        padding: 8px;
        font-size: 13px;
    }}
}}

</style>
</head>

<body>

<div class="container">

<h1>RedOps Security Assessment Report</h1>

<p><strong>Target:</strong> {target}</p>

<p><strong>Scan time (UTC):</strong> {
    html.escape(str(report_data.get("scan_time", "Not available")))
}</p>

<h2>Scan Summary</h2>

<p><strong>Open TCP ports:</strong> {len(ports)}</p>

<h2>Service Discovery</h2>

<table class="service-table">

<thead>
<tr>
    <th>Port</th>
    <th>Service</th>
    <th>Banner</th>
</tr>
</thead>

<tbody>
{port_rows}
</tbody>

</table>

<h2>Web Reconnaissance</h2>

{web_sections}

<footer>
Generated by RedOps Automated Reconnaissance Toolkit.
Only use results from authorised security assessments.
</footer>

</div>

</body>
</html>
"""

    output_path.write_text(document, encoding="utf-8")

    return output_path


def generate_report(report_data, report_format, output_dir="reports"):
    """Generate a JSON or HTML report."""

    if report_format not in ("json", "html"):
        raise ValueError("Report format must be json or html.")

    output_directory = Path(output_dir)
    output_directory.mkdir(parents=True, exist_ok=True)

    filename = generate_report_filename(report_format)
    output_path = output_directory / filename

    if report_format == "json":
        return generate_json_report(report_data, output_path)

    return generate_html_report(report_data, output_path)
