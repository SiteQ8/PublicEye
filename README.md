<div align="center">

<img src="docs/screenshots/banner.svg" width="100%" alt="PublicEye"/>

<br>

[![Version](https://img.shields.io/badge/version-2.0-f0a500?style=flat-square)]()
[![License](https://img.shields.io/badge/license-MIT-f0a500?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.8+-f0a500?style=flat-square&logo=python&logoColor=white)]()
[![Modules](https://img.shields.io/badge/modules-8-f0a500?style=flat-square)]()
[![On-Prem](https://img.shields.io/badge/on--prem-deployable-f0a500?style=flat-square)]()

**Open Source Intelligence framework that rivals commercial alternatives. On-prem deployable. Zero cloud dependencies.**

[Quick Start](#quick-start) · [Modules](#modules) · [Usage](#usage) · [Reporting](#reporting) · [vs. Commercial](#publiceye-vs-commercial-alternatives)

</div>

---

## Overview

PublicEye is a Python-based OSINT framework with **8 intelligence modules** in a single 826-line script. It performs domain reconnaissance, SSL/TLS analysis, subdomain enumeration, IP intelligence, email infrastructure analysis, technology fingerprinting, port scanning, and social media discovery — all from your own infrastructure with zero cloud dependencies.

### Why PublicEye?

- **Single-file deployment** — 826 lines of Python. No complex installation.
- **Zero API keys required** — Core functionality works without any external accounts.
- **On-premises** — All data stays in your environment. Nothing leaves your network.
- **Multi-format reporting** — JSON, CSV, and HTML reports generated automatically.
- **Concurrent execution** — Threaded scanning for subdomain enumeration, port scanning, social discovery.
- **Passive by default** — Domain, SSL, email, and tech modules use passive techniques only.

---

## Quick Start

```bash
git clone https://github.com/SiteQ8/PublicEye.git
cd PublicEye
pip install -r requirements.txt

# Full scan
python3 publiceye.py -t example.com -m full

# Single module
python3 publiceye.py -t example.com -m ssl

# IP reconnaissance
python3 publiceye.py -t 8.8.8.8 -m ip

# Social media discovery
python3 publiceye.py -t johndoe -m social

# HTML report
python3 publiceye.py -t example.com -m full -o html
```

### Requirements

```
Python 3.8+
requests
dnspython
python-whois
```

---

## Modules

| Module | Command | Techniques | Description |
|--------|---------|-----------|-------------|
| **Domain Intelligence** | `-m domain` | DNS (8 record types), WHOIS, HTTP headers, security headers scoring, robots.txt, sitemap | Full domain reconnaissance with security posture assessment |
| **SSL/TLS Analysis** | `-m ssl` | Certificate parsing, protocol detection, cipher analysis, SAN enumeration, expiry check | TLS certificate and protocol security assessment |
| **Subdomain Enumeration** | `-m subdomains` | Certificate Transparency (crt.sh), DNS brute-force (80+ wordlist), concurrent resolution | Passive and active subdomain discovery |
| **IP Intelligence** | `-m ip` | Reverse DNS, geolocation, ISP/Org/ASN, IPv4/v6 classification, private/global detection | IP address reconnaissance and attribution |
| **Email Intelligence** | `-m email` | MX records, provider detection, SPF/DMARC/DKIM validation, DKIM selector discovery | Email infrastructure and authentication analysis |
| **Tech Fingerprinting** | `-m tech` | 24+ signature patterns for CMS, frameworks, CDN, analytics, CAPTCHA, server software | Web technology stack identification |
| **Port Scanner** | `-m ports` | TCP connect scan, 23 common ports, concurrent threads, service identification | Lightweight service discovery |
| **Social Discovery** | `-m social` | 15 platforms (GitHub, X, Instagram, LinkedIn, Reddit, TikTok, YouTube, etc.) | Username existence enumeration |

### Full Scan Mode

`-m full` automatically selects applicable modules based on target type:

| Target Type | Modules Executed |
|-------------|-----------------|
| Domain (`example.com`) | domain, ssl, subdomains, ip, email, tech, ports |
| IP Address (`8.8.8.8`) | ip, ports |
| Email (`user@example.com`) | email |
| Username (`johndoe`) | social |

---

## Usage

```
python3 publiceye.py -t TARGET -m MODULE [OPTIONS]

Required:
  -t, --target    Target (domain, IP, email, username)
  -m, --module    Module(s) to run (comma-separated, or 'full')

Options:
  -o, --output    Report format: json, csv, html (default: json)
  -v, --verbose   Verbose output
  --threads N     Max concurrent threads (default: 10)
  --timeout N     Request timeout in seconds (default: 10)
  --version       Show version
```

### Examples

```bash
# Domain reconnaissance
python3 publiceye.py -t example.com -m domain

# Multiple modules
python3 publiceye.py -t example.com -m domain,ssl,subdomains

# Full scan with HTML report
python3 publiceye.py -t example.com -m full -o html

# IP with custom threads
python3 publiceye.py -t 8.8.8.8 -m ip,ports --threads 20

# Email infrastructure
python3 publiceye.py -t user@company.com -m email

# Social media
python3 publiceye.py -t targetuser -m social
```

---

## Reporting

Every scan generates reports in `./publiceye_reports/`:

| Format | Contents | Use Case |
|--------|----------|----------|
| **JSON** | Structured data with full metadata | API integration, automation pipelines |
| **CSV** | Tabular module/key/value format | Spreadsheets, GRC platforms |
| **HTML** | Visual report with styling | Management review, audit evidence |

HTML reports are generated automatically alongside the primary output format.

---

## PublicEye vs. Commercial Alternatives

| Feature | PublicEye | Maltego ($1,999/yr) | SpiderFoot | Recon-ng |
|---------|-----------|---------------------|------------|----------|
| Price | **Free (MIT)** | $1,999/yr | Free / $800/yr | Free |
| On-premises | **Yes** | Partial | Yes | Yes |
| Zero API keys | **Yes (core)** | No | No | No |
| Single-file deployment | **Yes** | No | No | No |
| JSON/CSV/HTML reports | **All three** | Yes | Yes | CSV only |
| Subdomain enumeration | **CT + DNS brute** | Yes | Yes | Yes |
| Social media (15 platforms) | **Yes** | Yes | Yes | Limited |
| Tech fingerprinting (24+) | **Yes** | Yes | Yes | Limited |

---

## Security and Ethics

PublicEye is designed for **authorized security assessments only**. All core modules use passive techniques (DNS queries, HTTP requests, certificate parsing, public APIs). The port scanner module performs active TCP connections and should only be used against systems you own or have explicit authorization to test.

- No exploitation capabilities
- No credential harvesting
- No brute-force authentication attacks
- User-Agent clearly identifies PublicEye requests
- All data stays on your infrastructure

---

## Contributing

Contributions welcome:

- New intelligence modules (WHOIS history, dark web monitoring, breach detection)
- Additional social media platforms
- Technology fingerprint signatures
- Pipelining and workflow automation
- Docker containerization
- Web UI frontend

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

MIT License — see [LICENSE](LICENSE).

---

<div align="center">
  <sub>PublicEye — Open Source Intelligence Framework</sub><br>
  <sub><a href="https://github.com/SiteQ8">@SiteQ8</a> — Ali AlEnezi</sub><br>
  <sub>Enterprise OSINT. On-prem deployable. Zero cloud dependencies.</sub>
</div>
