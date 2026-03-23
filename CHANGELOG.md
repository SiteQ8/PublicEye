# Changelog

## [3.0.0] - 2026-03-23

### Added
- Complete platform rebuild: 20 sidebar pages, 13 OSINT categories
- Intelligence section: Dashboard, Investigations (case management), IOC Manager
- Inline search results: Telegram, Dark Web, Social Media, Google Dorks, Phone, Email, Image
- iframe integration with TGStat, Lyzem, SearX.be, Phonebook.cz
- Google Dorks generator with inline Run ▶ button (14 dork categories)
- Username probing: live HTTP checks against 20 platforms
- Cryptocurrency tracker: real blockchain.info API for Bitcoin address intelligence
- Dark web search via SearX.be privacy engine (inline results)
- Telegram OSINT with switchable source tabs (TGStat, Lyzem)
- Social media search with 3 inline source tabs
- CertStream monitor: real-time WebSocket, brand keyword filter, phishing detection
- Threat feeds panel: CISA ICS-CERT, AlienVault OTX, URLhaus, PhishTank, MalwareBazaar
- Report export: JSON, HTML, CSV, STIX/TAXII formats
- API key management: Shodan, VirusTotal, Hunter.io, SecurityTrails, AbuseIPDB
- Settings: scan engine, CertStream, platform preferences

### Changed
- All search pages now display results inside PublicEye (no external tabs)
- Login screen redesign with radial gradient background
- Sidebar reorganized into 5 sections: Intelligence, Collection, Social & Dark Web, Advanced, Monitoring, Platform
- User profile with avatar in sidebar footer

## [2.0.0] - 2026-03-09

### Added
- Initial release: 8 OSINT modules (DNS, SSL, Subdomains, IP, Email, Tech, Ports, Social)
- Python CLI (publiceye.py, 826 lines)
- JSON, CSV, HTML report generation
- On-premises deployment, zero API keys

## Author

Ali AlEnezi (@SiteQ8)
