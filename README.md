<div align="center">

<img src="docs/screenshots/banner.svg" width="100%" alt="PublicEye"/>

<br>

[![Version](https://img.shields.io/badge/version-3.0-f0a500?style=flat-square)]()
[![License](https://img.shields.io/badge/license-MIT-f0a500?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.8+-f0a500?style=flat-square&logo=python&logoColor=white)]()
[![Modules](https://img.shields.io/badge/modules-20-f0a500?style=flat-square)]()
[![OSINT](https://img.shields.io/badge/categories-13-f0a500?style=flat-square)]()
[![APIs](https://img.shields.io/badge/API_keys-zero-f0a500?style=flat-square)]()

**OSINT Intelligence Platform — 20 modules, 13 categories, live APIs, zero backend**

[Live Platform](https://siteq8.github.io/PublicEye) · [Features](#features) · [Modules](#modules) · [Quick Start](#quick-start)

</div>

---

## What is PublicEye

PublicEye is a complete OSINT intelligence platform that runs entirely in your browser. No server, no backend, no API keys required. Every search, every lookup, every scan happens live using real public APIs — results displayed inline, never leaving the platform.

Built for analysts, investigators, and security teams who need real-time intelligence without commercial tool budgets or cloud dependencies.

**Login:** `admin` / `Eye@2025`

---

## Features

### Live API Modules (real data, real-time)

| Module | API Source | What It Does |
|--------|-----------|--------------|
| DNS Records | dns.google | A, AAAA, MX, NS, TXT, SOA, CNAME, CAA with SPF/DMARC flagging |
| Subdomains | crt.sh | Certificate Transparency — all unique subdomains from every cert ever issued |
| IP & Geolocation | ipwho.is | Country, city, ISP, ASN, coordinates with flag emoji |
| Shodan InternetDB | internetdb.shodan.io | Open ports, hostnames, CPEs, CVEs — no API key needed |
| Email Security | dns.google | MX, SPF, DMARC, 10 DKIM selectors, STRONG/MODERATE/WEAK score |
| WHOIS / RDAP | rdap.org | Registration dates, status, nameservers, registrar entities |
| Crypto Tracker | blockchain.info | Bitcoin balance, TX count, recent transactions with links |
| Wayback Machine | archive.org | Check archived snapshots, link to full calendar |
| GitHub Code Search | api.github.com | Repository search with stars, language, description |
| CertStream | certstream.calidog.io | Real-time WebSocket certificate monitoring with brand filter |
| Username Probing | Direct HTTP | Probes 20 platforms live, shows LIKELY EXISTS / CHECK MANUALLY |

### Inline Search Modules (results inside PublicEye)

| Module | Method | What It Does |
|--------|--------|--------------|
| Telegram OSINT | iframe (TGStat, Lyzem) | Channel/group search with switchable source tabs — inline results |
| Dark Web Search | iframe (SearX.be) | Dark web references + leak searches displayed inside platform |
| Social Media Intel | iframe (SearX, Phonebook.cz) | Social media search with 3 source tabs — all inline |
| Google Dorks | Generator + iframe (SearX.be) | 14 auto-generated dorks with Run ▶ button — executes inline |
| Phone Lookup | iframe (SearX.be) | Phone number intelligence search displayed inside platform |
| Email Discovery | iframe (Phonebook.cz) | Email address discovery — inline results |
| Image OSINT | iframe (SearX.be) | Image intelligence search — inline results |

### Intelligence Features

| Feature | Description |
|---------|-------------|
| Dashboard | 5 metrics, OSINT capabilities table, threat level, quick actions |
| Investigations | Case management with INV IDs, priorities (CRITICAL/HIGH/MEDIUM), IOC counts |
| IOC Manager | 12 preloaded IOCs (domains, IPs, hashes) — add custom IOCs with type/value/notes |
| Threat Feeds | 6 intelligence sources: CISA ICS-CERT, AlienVault OTX, URLhaus, PhishTank, MalwareBazaar, FS-ISAC |
| Reports | 4 export formats: JSON, HTML, CSV, STIX/TAXII |
| API Keys | 5 optional key slots: Shodan, VirusTotal, Hunter.io, SecurityTrails, AbuseIPDB |
| Settings | Scan engine config, CertStream config, platform preferences |

---

## Quick Start

### Online (Zero Install)

**[https://siteq8.github.io/PublicEye](https://siteq8.github.io/PublicEye)**

Login: `admin` / `Eye@2025`

### Local

```bash
git clone https://github.com/SiteQ8/PublicEye.git
open PublicEye/docs/index.html
```

### CLI (Python)

```bash
git clone https://github.com/SiteQ8/PublicEye.git
cd PublicEye
pip install requests
python3 publiceye.py -t sans.org -m all -o html
```

---

## Modules

### 20 sidebar pages across 5 sections:

**Intelligence:** Dashboard, Investigations, IOC Manager

**Collection:** Domain Recon (8 scan modules), Shodan Intel, Email OSINT, Username Search

**Social & Dark Web:** Social Media, Telegram, Dark Web

**Advanced:** Crypto Tracker, Google Dorks, Wayback Machine, Code Search, Image OSINT, Phone Lookup

**Monitoring:** CertStream (live WebSocket), Threat Feeds

**Platform:** API Keys, Settings

---

## Design

Single HTML file (66KB). Dark OSINT theme: JetBrains Mono + Outfit fonts. Gold `#F0A500` accent on near-black `#07080A`. CRT scanline overlay. Login screen with demo credentials. Sidebar navigation with section grouping. All results inline — no external tabs.

---

## License

MIT — see [LICENSE](LICENSE).

---

<div align="center">
  <sub>PublicEye v3.0 — OSINT Intelligence Platform</sub><br>
  <sub><a href="https://github.com/SiteQ8">@SiteQ8</a> — Ali AlEnezi</sub>
</div>
