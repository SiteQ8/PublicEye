# Changelog

## [2.0.0] - 2026-03-09

### Added
- 8 OSINT modules in 826 lines of Python
- Domain Intelligence: DNS (8 types), WHOIS, HTTP headers, security scoring
- SSL/TLS Analysis: certificate, protocol, cipher, SAN, expiry
- Subdomain Enumeration: CT logs (crt.sh) + DNS brute-force (80+ wordlist)
- IP Intelligence: geolocation, reverse DNS, ASN, ISP
- Email Intelligence: MX, SPF, DMARC, DKIM, provider detection
- Technology Fingerprinting: 24+ signatures (CMS, frameworks, CDN)
- Port Scanner: 23 common TCP ports, concurrent scanning
- Social Media Discovery: 15 platforms, concurrent checking
- Multi-format reporting: JSON, CSV, HTML
- Full scan mode (-m full) with auto-detection
- Concurrent execution via ThreadPoolExecutor
- GUI documentation page
- Professional banner SVG
- Community files
