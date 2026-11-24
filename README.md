# RedOps – Automated Reconnaissance Toolkit

**RedOps** is a Python-based network reconnaissance toolkit developed in Kali Linux. It helps security learners and authorized testers discover active hosts, identify open TCP ports, detect common services, inspect HTTP services and generate structured scan reports.

The project demonstrates practical knowledge of Python programming, networking, TCP scanning, service identification and basic web reconnaissance.

## Features

- **Single IP scanning:** Scan an individual IPv4 address.
- **Network scanning:** Discover responsive hosts within an authorized CIDR network.
- **TCP port scanning:** Identify open TCP ports within a specified range.
- **Service identification:** Detect common services such as SSH, HTTP and HTTPS.
- **Web reconnaissance:** Inspect HTTP response status, server information and security headers.
- **HTML reports:** Generate readable security assessment reports.
- **JSON reports:** Export structured scan results for further analysis.
- **Automated tests:** Validate core modules using Python's unitest framework.

## Technology Stack

| Technology | Purpose                             |
| ---------- | ----------------------------------- |
| Python     | Core programming language           |
| Kali Linux | Development and testing environment |
| Socket     | TCP network communication           |
| Requests   | HTTP reconnaissance                 |
| SSL        | HTTPS connection handling           |
| Rich       | Terminal output and formatting      |
| HTML/CSS   | Report presentation                 |
| JSON       | Structured report output            |
| Unittest   | Automated testing                   |

## Project Structure

```text
RedOps/
│
├── modules/
│   ├── __init__.py
│   ├── network_scanner.py
│   ├── port_scanner.py
│   ├── service_detector.py
│   ├── web_recon.py
│   ├── report_generator.py
│   └── test_*.py
│
├── reports/
├── screenshots/
├── utils/
│
├── redops.py
├── requirements.txt
├── README.md
├── LICENSE
└── .gitignore
```

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/Jattin09/RedOps.git
cd RedOps
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
```

### 3. Activate the environment

```bash
source .venv/bin/activate
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

## Usage

### Single IP scan

```bash
python redops.py -t 192.168.1.7 -p 1-1000
```

### Scan a specific port

```bash
python redops.py -t 192.168.1.7 -p 80-80
```

### Network scan

```bash
python redops.py -n 192.168.1.0/24 -p 1-1000
```

### Web reconnaissance

```bash
python redops.py -t 192.168.1.7 -p 8888-8888 --web
```

### Generate an HTML report

```bash
python redops.py -t 192.168.1.7 -p 8888-8888 --web --report html
```

### Generate a JSON report

```bash
python redops.py -t 192.168.1.7 -p 8888-8888 --web --report json
```

Generated reports are saved in the `reports/` directory.

## Testing

RedOps uses Python's built-in unittest framework.

Run the complete test suite:

```bash
python -m unittest discover -s modules -p "test_*.py" -v
```

**Current test results: 22 tests passed.**

## Current Capabilities and Limitations

RedOps is an educational reconnaissance project, not a replacement for professional vulnerability scanners.

Current limitations include:

- Host discovery relies on TCP-based checks and may miss unresponsive hosts.
- Service identification is based on basic service detection and available banners.
- Web reconnaissance currently supports single-IP scans.
- Missing security headers are observations, not confirmed vulnerabilities.
- HTTPS certificate inspection is implemented in the web reconnaissance module but is not yet fully integrated into the main CLI workflow.
- Scan profiles and advanced reporting features are not fully implemented.

## Future Improvements

- Improve service fingerprinting.
- Add more comprehensive network scan options.
- Improve report presentation and findings.
- Expand automated test coverage.

## Author

**Jattin Salotra**

Cybersecurity Learner | Aspiring Penetration Tester

GitHub: [@Jattin09](https://github.com/Jattin09)

## Disclaimer

RedOps is intended strictly for educational purposes and authorised security testing.

Only scan systems and networks for which you have explicit permission. The author is not responsible for misuse of this tool.
