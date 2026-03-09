#!/usr/bin/env python3
"""
PublicEye — Open Source Intelligence Framework
Enterprise-grade OSINT platform for security professionals.

Author: Ali AlEnezi (@SiteQ8)
License: MIT
"""

import argparse
import json
import sys
import os
import re
import socket
import ssl
import hashlib
import csv
import datetime
import ipaddress
import concurrent.futures
from pathlib import Path
from urllib.parse import urlparse

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

VERSION = "2.0.0"
BANNER = r"""
    ____        __    ___      ______
   / __ \__  __/ /_  / (_)____/ ____/_  _____
  / /_/ / / / / __ \/ / / ___/ __/ / / / / _ \
 / ____/ /_/ / /_/ / / / /__/ /___/ /_/ /  __/
/_/    \__,_/_.___/_/_/\___/_____/\__, /\___/
                                 /____/
    Open Source Intelligence Framework  v{version}
    github.com/SiteQ8/PublicEye
""".format(version=VERSION)

# ─── Configuration ────────────────────────────────────────────────────
OUTPUT_DIR = Path("./publiceye_reports")
CONFIG = {
    "user_agent": "PublicEye-OSINT/2.0 (+https://github.com/SiteQ8/PublicEye)",
    "timeout": 10,
    "max_threads": 10,
    "output_format": "json",
    "verbose": False,
}


# ─── Utilities ────────────────────────────────────────────────────────
class Colors:
    R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[94m"
    C = "\033[96m"; W = "\033[97m"; D = "\033[90m"; N = "\033[0m"; BOLD = "\033[1m"


def log(msg, level="info"):
    colors = {"info": Colors.C, "pass": Colors.G, "fail": Colors.R, "warn": Colors.Y, "data": Colors.W}
    tag = {"info": "INFO", "pass": "PASS", "fail": "FAIL", "warn": "WARN", "data": "DATA"}
    c = colors.get(level, Colors.W)
    print(f"  {c}[{tag.get(level, 'INFO')}]{Colors.N} {msg}")


def safe_request(url, timeout=10):
    """Make HTTP request with error handling."""
    if not HAS_REQUESTS:
        return None
    try:
        headers = {"User-Agent": CONFIG["user_agent"]}
        resp = requests.get(url, headers=headers, timeout=timeout, verify=True)
        return resp
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════════
# MODULE 1: DOMAIN INTELLIGENCE
# ═══════════════════════════════════════════════════════════════════════
class DomainIntel:
    """Comprehensive domain reconnaissance."""

    @staticmethod
    def run(target):
        results = {"module": "domain_intel", "target": target, "findings": {}}
        log(f"Domain Intelligence: {target}", "info")

        # DNS Records
        if HAS_DNS:
            for rtype in ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV"]:
                try:
                    answers = dns.resolver.resolve(target, rtype)
                    records = [str(r) for r in answers]
                    results["findings"][f"dns_{rtype.lower()}"] = records
                    log(f"DNS {rtype}: {', '.join(records[:3])}", "data")
                except Exception:
                    pass

        # WHOIS
        if HAS_WHOIS:
            try:
                w = whois.whois(target)
                whois_data = {
                    "registrar": str(w.registrar or ""),
                    "creation_date": str(w.creation_date or ""),
                    "expiration_date": str(w.expiration_date or ""),
                    "name_servers": w.name_servers or [],
                    "status": w.status if isinstance(w.status, list) else [str(w.status or "")],
                    "org": str(w.org or ""),
                    "country": str(w.country or ""),
                }
                results["findings"]["whois"] = whois_data
                log(f"WHOIS Registrar: {whois_data['registrar']}", "data")
                log(f"WHOIS Org: {whois_data['org']}", "data")
            except Exception:
                log("WHOIS lookup failed", "warn")

        # HTTP Headers
        resp = safe_request(f"https://{target}")
        if resp:
            interesting = {}
            for h in ["Server", "X-Powered-By", "X-Frame-Options", "Content-Security-Policy",
                       "Strict-Transport-Security", "X-Content-Type-Options", "X-XSS-Protection",
                       "Access-Control-Allow-Origin", "X-AspNet-Version", "X-Generator"]:
                if h in resp.headers:
                    interesting[h] = resp.headers[h]
            results["findings"]["http_headers"] = interesting
            results["findings"]["http_status"] = resp.status_code
            results["findings"]["http_redirect_chain"] = [r.url for r in resp.history]
            for h, v in interesting.items():
                log(f"HTTP {h}: {v}", "data")

        # Security Headers Assessment
        if resp:
            security_headers = ["Strict-Transport-Security", "Content-Security-Policy",
                                "X-Frame-Options", "X-Content-Type-Options", "X-XSS-Protection",
                                "Referrer-Policy", "Permissions-Policy"]
            missing = [h for h in security_headers if h not in resp.headers]
            present = [h for h in security_headers if h in resp.headers]
            results["findings"]["security_headers"] = {"present": present, "missing": missing}
            score = len(present) / len(security_headers) * 100
            results["findings"]["security_score"] = round(score, 1)
            level = "pass" if score >= 70 else "warn" if score >= 40 else "fail"
            log(f"Security Headers Score: {score:.0f}% ({len(present)}/{len(security_headers)})", level)

        # Robots.txt
        resp_robots = safe_request(f"https://{target}/robots.txt")
        if resp_robots and resp_robots.status_code == 200:
            disallowed = re.findall(r"Disallow:\s*(.+)", resp_robots.text)
            results["findings"]["robots_disallowed"] = disallowed[:20]
            log(f"Robots.txt: {len(disallowed)} disallowed paths", "data")

        # Sitemap
        resp_sitemap = safe_request(f"https://{target}/sitemap.xml")
        if resp_sitemap and resp_sitemap.status_code == 200:
            urls = re.findall(r"<loc>(.*?)</loc>", resp_sitemap.text)
            results["findings"]["sitemap_urls"] = len(urls)
            log(f"Sitemap: {len(urls)} URLs indexed", "data")

        return results


# ═══════════════════════════════════════════════════════════════════════
# MODULE 2: SSL/TLS ANALYSIS
# ═══════════════════════════════════════════════════════════════════════
class SSLAnalysis:
    """TLS certificate and protocol analysis."""

    @staticmethod
    def run(target, port=443):
        results = {"module": "ssl_analysis", "target": target, "findings": {}}
        log(f"SSL/TLS Analysis: {target}:{port}", "info")

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((target, port), timeout=CONFIG["timeout"]) as sock:
                with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    protocol = ssock.version()

                    # Certificate info
                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    san = [e[1] for e in cert.get("subjectAltName", [])]

                    cert_data = {
                        "subject_cn": subject.get("commonName", ""),
                        "issuer_cn": issuer.get("commonName", ""),
                        "issuer_org": issuer.get("organizationName", ""),
                        "not_before": cert.get("notBefore", ""),
                        "not_after": cert.get("notAfter", ""),
                        "serial": cert.get("serialNumber", ""),
                        "san": san,
                        "protocol": protocol,
                        "cipher_suite": cipher[0] if cipher else "",
                        "cipher_bits": cipher[2] if cipher else 0,
                    }

                    results["findings"]["certificate"] = cert_data
                    log(f"Subject: {cert_data['subject_cn']}", "data")
                    log(f"Issuer: {cert_data['issuer_org']} ({cert_data['issuer_cn']})", "data")
                    log(f"Protocol: {protocol} | Cipher: {cipher[0] if cipher else 'N/A'}", "data")
                    log(f"SAN entries: {len(san)}", "data")
                    log(f"Valid until: {cert_data['not_after']}", "data")

                    # Expiry check
                    try:
                        expiry = datetime.datetime.strptime(cert_data["not_after"], "%b %d %H:%M:%S %Y %Z")
                        days_left = (expiry - datetime.datetime.utcnow()).days
                        results["findings"]["days_until_expiry"] = days_left
                        level = "pass" if days_left > 30 else "warn" if days_left > 7 else "fail"
                        log(f"Certificate expires in {days_left} days", level)
                    except Exception:
                        pass

        except Exception as e:
            log(f"SSL analysis failed: {e}", "fail")
            results["findings"]["error"] = str(e)

        return results


# ═══════════════════════════════════════════════════════════════════════
# MODULE 3: SUBDOMAIN ENUMERATION
# ═══════════════════════════════════════════════════════════════════════
class SubdomainEnum:
    """Passive and active subdomain discovery."""

    COMMON_SUBS = [
        "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "ns1", "ns2",
        "mx", "blog", "dev", "staging", "test", "api", "app", "admin", "portal",
        "vpn", "remote", "cdn", "static", "assets", "media", "images", "docs",
        "help", "support", "status", "monitor", "grafana", "jenkins", "gitlab",
        "jira", "confluence", "wiki", "owa", "autodiscover", "exchange", "cpanel",
        "whm", "plesk", "db", "mysql", "postgres", "redis", "elastic", "kibana",
        "prometheus", "sentry", "vault", "consul", "k8s", "docker", "registry",
        "ci", "cd", "build", "deploy", "stage", "uat", "qa", "prod", "backup",
        "internal", "intranet", "extranet", "partner", "client", "demo", "sandbox",
        "shop", "store", "pay", "billing", "invoice", "crm", "erp", "hr", "cloud",
    ]

    @staticmethod
    def run(target):
        results = {"module": "subdomain_enum", "target": target, "findings": {"subdomains": []}}
        log(f"Subdomain Enumeration: {target}", "info")

        found = []

        # Passive: crt.sh certificate transparency
        resp = safe_request(f"https://crt.sh/?q=%.{target}&output=json")
        if resp and resp.status_code == 200:
            try:
                crt_data = resp.json()
                ct_subs = set()
                for entry in crt_data:
                    names = entry.get("name_value", "").split("\n")
                    for name in names:
                        name = name.strip().lower()
                        if name.endswith(f".{target}") and "*" not in name:
                            ct_subs.add(name)
                found.extend(ct_subs)
                log(f"Certificate Transparency: {len(ct_subs)} subdomains", "data")
            except Exception:
                pass

        # Active: DNS brute force
        if HAS_DNS:
            log("DNS brute-force (common subdomains)...", "info")
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 3

            def check_sub(sub):
                fqdn = f"{sub}.{target}"
                try:
                    resolver.resolve(fqdn, "A")
                    return fqdn
                except Exception:
                    return None

            with concurrent.futures.ThreadPoolExecutor(max_workers=CONFIG["max_threads"]) as executor:
                futures = {executor.submit(check_sub, s): s for s in SubdomainEnum.COMMON_SUBS}
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result and result not in found:
                        found.append(result)

        found = sorted(set(found))
        results["findings"]["subdomains"] = found
        results["findings"]["count"] = len(found)
        log(f"Total subdomains discovered: {len(found)}", "pass" if found else "warn")
        for sub in found[:15]:
            log(f"  {sub}", "data")
        if len(found) > 15:
            log(f"  ... and {len(found) - 15} more", "data")

        return results


# ═══════════════════════════════════════════════════════════════════════
# MODULE 4: IP INTELLIGENCE
# ═══════════════════════════════════════════════════════════════════════
class IPIntel:
    """IP address reconnaissance and geolocation."""

    @staticmethod
    def run(target):
        results = {"module": "ip_intel", "target": target, "findings": {}}
        log(f"IP Intelligence: {target}", "info")

        # Resolve if hostname
        ip = target
        try:
            if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
                ip = socket.gethostbyname(target)
                results["findings"]["resolved_ip"] = ip
                log(f"Resolved to: {ip}", "data")
        except Exception:
            log("DNS resolution failed", "fail")
            return results

        # IP type
        try:
            addr = ipaddress.ip_address(ip)
            results["findings"]["ip_version"] = addr.version
            results["findings"]["is_private"] = addr.is_private
            results["findings"]["is_global"] = addr.is_global
            results["findings"]["is_multicast"] = addr.is_multicast
            results["findings"]["is_loopback"] = addr.is_loopback
            log(f"IPv{addr.version} | Private: {addr.is_private} | Global: {addr.is_global}", "data")
        except Exception:
            pass

        # Reverse DNS
        try:
            rdns = socket.gethostbyaddr(ip)
            results["findings"]["reverse_dns"] = rdns[0]
            log(f"Reverse DNS: {rdns[0]}", "data")
        except Exception:
            results["findings"]["reverse_dns"] = None

        # Geolocation via ip-api.com
        resp = safe_request(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,zip,lat,lon,isp,org,as,query")
        if resp and resp.status_code == 200:
            try:
                geo = resp.json()
                if geo.get("status") == "success":
                    results["findings"]["geolocation"] = geo
                    log(f"Location: {geo.get('city')}, {geo.get('regionName')}, {geo.get('country')}", "data")
                    log(f"ISP: {geo.get('isp')}", "data")
                    log(f"Org: {geo.get('org')}", "data")
                    log(f"ASN: {geo.get('as')}", "data")
                    log(f"Coordinates: {geo.get('lat')}, {geo.get('lon')}", "data")
            except Exception:
                pass

        return results


# ═══════════════════════════════════════════════════════════════════════
# MODULE 5: EMAIL INTELLIGENCE
# ═══════════════════════════════════════════════════════════════════════
class EmailIntel:
    """Email address and domain email infrastructure analysis."""

    @staticmethod
    def run(target):
        results = {"module": "email_intel", "target": target, "findings": {}}

        # Detect if target is email or domain
        if "@" in target:
            domain = target.split("@")[1]
            results["findings"]["email"] = target
            results["findings"]["domain"] = domain
            log(f"Email Intelligence: {target}", "info")

            # Email format validation
            email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            results["findings"]["valid_format"] = bool(re.match(email_regex, target))
        else:
            domain = target
            log(f"Email Domain Intelligence: {target}", "info")

        # MX Records
        if HAS_DNS:
            try:
                mx_records = dns.resolver.resolve(domain, "MX")
                mx_list = sorted([(r.preference, str(r.exchange).rstrip(".")) for r in mx_records])
                results["findings"]["mx_records"] = mx_list
                for pref, mx in mx_list:
                    log(f"MX [{pref}]: {mx}", "data")

                # Detect email provider
                mx_str = " ".join([m[1].lower() for m in mx_list])
                if "google" in mx_str or "gmail" in mx_str:
                    provider = "Google Workspace"
                elif "outlook" in mx_str or "microsoft" in mx_str:
                    provider = "Microsoft 365"
                elif "protonmail" in mx_str:
                    provider = "ProtonMail"
                elif "zoho" in mx_str:
                    provider = "Zoho Mail"
                elif "mimecast" in mx_str:
                    provider = "Mimecast"
                elif "barracuda" in mx_str:
                    provider = "Barracuda"
                else:
                    provider = "Custom / Self-hosted"
                results["findings"]["email_provider"] = provider
                log(f"Email Provider: {provider}", "data")
            except Exception:
                pass

        # SPF Record
        if HAS_DNS:
            try:
                txt_records = dns.resolver.resolve(domain, "TXT")
                for r in txt_records:
                    txt = str(r).strip('"')
                    if txt.startswith("v=spf1"):
                        results["findings"]["spf"] = txt
                        log(f"SPF: {txt[:80]}...", "data")
            except Exception:
                pass

        # DMARC Record
        if HAS_DNS:
            try:
                dmarc = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
                for r in dmarc:
                    txt = str(r).strip('"')
                    if "v=DMARC1" in txt:
                        results["findings"]["dmarc"] = txt
                        policy = re.search(r"p=(\w+)", txt)
                        if policy:
                            log(f"DMARC Policy: {policy.group(1)}", "data")
            except Exception:
                results["findings"]["dmarc"] = None
                log("DMARC: Not configured", "warn")

        # DKIM (common selectors)
        if HAS_DNS:
            selectors = ["default", "google", "selector1", "selector2", "k1", "k2", "dkim", "mail", "s1", "s2"]
            found_dkim = []
            for sel in selectors:
                try:
                    dkim = dns.resolver.resolve(f"{sel}._domainkey.{domain}", "TXT")
                    found_dkim.append(sel)
                except Exception:
                    pass
            results["findings"]["dkim_selectors"] = found_dkim
            if found_dkim:
                log(f"DKIM selectors found: {', '.join(found_dkim)}", "data")

        return results


# ═══════════════════════════════════════════════════════════════════════
# MODULE 6: TECHNOLOGY FINGERPRINTING
# ═══════════════════════════════════════════════════════════════════════
class TechFingerprint:
    """Web technology detection and fingerprinting."""

    SIGNATURES = {
        "WordPress": ["/wp-content/", "/wp-includes/", "wp-json"],
        "Drupal": ["Drupal", "/sites/default/", "drupal.js"],
        "Joomla": ["/media/jui/", "Joomla!", "/administrator/"],
        "Shopify": ["cdn.shopify.com", "shopify"],
        "Wix": ["wixstatic.com", "wix.com"],
        "Squarespace": ["squarespace.com", "sqsp.net"],
        "React": ["react", "_next/", "__NEXT_DATA__"],
        "Angular": ["ng-version", "angular", "ng-app"],
        "Vue.js": ["vue.js", "__vue__", "v-cloak"],
        "jQuery": ["jquery", "jQuery"],
        "Bootstrap": ["bootstrap"],
        "Cloudflare": ["cloudflare", "cf-ray"],
        "AWS": ["amazonaws.com", "aws", "x-amz-"],
        "Nginx": ["nginx"],
        "Apache": ["Apache"],
        "IIS": ["Microsoft-IIS"],
        "PHP": ["X-Powered-By: PHP", ".php"],
        "ASP.NET": ["ASP.NET", "aspnet", "__VIEWSTATE"],
        "Node.js": ["X-Powered-By: Express", "node"],
        "Google Analytics": ["google-analytics.com", "gtag", "UA-", "G-"],
        "Google Tag Manager": ["googletagmanager.com", "GTM-"],
        "Cloudflare CDN": ["cdnjs.cloudflare.com"],
        "reCAPTCHA": ["recaptcha", "g-recaptcha"],
        "hCaptcha": ["hcaptcha"],
    }

    @staticmethod
    def run(target):
        results = {"module": "tech_fingerprint", "target": target, "findings": {"technologies": []}}
        log(f"Technology Fingerprinting: {target}", "info")

        resp = safe_request(f"https://{target}")
        if not resp:
            resp = safe_request(f"http://{target}")
        if not resp:
            log("Could not fetch target", "fail")
            return results

        body = resp.text.lower()
        headers_str = str(resp.headers).lower()
        combined = body + " " + headers_str

        detected = []
        for tech, sigs in TechFingerprint.SIGNATURES.items():
            for sig in sigs:
                if sig.lower() in combined:
                    detected.append(tech)
                    break

        results["findings"]["technologies"] = sorted(set(detected))
        results["findings"]["count"] = len(set(detected))

        for tech in sorted(set(detected)):
            log(f"Detected: {tech}", "data")

        # Server header
        server = resp.headers.get("Server", "")
        if server:
            results["findings"]["server"] = server
            log(f"Server: {server}", "data")

        # Powered by
        powered = resp.headers.get("X-Powered-By", "")
        if powered:
            results["findings"]["powered_by"] = powered

        return results


# ═══════════════════════════════════════════════════════════════════════
# MODULE 7: PORT SCANNER (Lightweight)
# ═══════════════════════════════════════════════════════════════════════
class PortScanner:
    """Lightweight TCP port scanner for common service ports."""

    COMMON_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
        6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "Elasticsearch",
        27017: "MongoDB",
    }

    @staticmethod
    def run(target, ports=None):
        results = {"module": "port_scanner", "target": target, "findings": {"open_ports": []}}
        log(f"Port Scanner: {target}", "info")

        # Resolve hostname
        try:
            ip = socket.gethostbyname(target)
        except Exception:
            log("Could not resolve target", "fail")
            return results

        scan_ports = ports or PortScanner.COMMON_PORTS.keys()

        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    return port
            except Exception:
                pass
            return None

        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONFIG["max_threads"]) as executor:
            futures = {executor.submit(scan_port, p): p for p in scan_ports}
            for future in concurrent.futures.as_completed(futures):
                port = future.result()
                if port:
                    service = PortScanner.COMMON_PORTS.get(port, "Unknown")
                    open_ports.append({"port": port, "service": service, "state": "open"})
                    log(f"Port {port}/tcp OPEN — {service}", "data")

        open_ports.sort(key=lambda x: x["port"])
        results["findings"]["open_ports"] = open_ports
        results["findings"]["total_open"] = len(open_ports)
        results["findings"]["total_scanned"] = len(list(scan_ports))
        log(f"Open ports: {len(open_ports)} / {len(list(scan_ports))} scanned", "pass")

        return results


# ═══════════════════════════════════════════════════════════════════════
# MODULE 8: SOCIAL MEDIA DISCOVERY
# ═══════════════════════════════════════════════════════════════════════
class SocialDiscovery:
    """Check username existence across social platforms."""

    PLATFORMS = {
        "GitHub": "https://github.com/{user}",
        "Twitter/X": "https://x.com/{user}",
        "Instagram": "https://www.instagram.com/{user}/",
        "LinkedIn": "https://www.linkedin.com/in/{user}/",
        "Reddit": "https://www.reddit.com/user/{user}",
        "TikTok": "https://www.tiktok.com/@{user}",
        "YouTube": "https://www.youtube.com/@{user}",
        "Pinterest": "https://www.pinterest.com/{user}/",
        "Medium": "https://medium.com/@{user}",
        "Twitch": "https://www.twitch.tv/{user}",
        "Keybase": "https://keybase.io/{user}",
        "HackerOne": "https://hackerone.com/{user}",
        "Bugcrowd": "https://bugcrowd.com/{user}",
        "Dev.to": "https://dev.to/{user}",
        "Mastodon": "https://mastodon.social/@{user}",
    }

    @staticmethod
    def run(username):
        results = {"module": "social_discovery", "target": username, "findings": {"profiles": []}}
        log(f"Social Media Discovery: {username}", "info")

        if not HAS_REQUESTS:
            log("requests library required", "fail")
            return results

        def check_platform(name, url_template):
            url = url_template.format(user=username)
            try:
                resp = requests.get(url, headers={"User-Agent": CONFIG["user_agent"]},
                                    timeout=8, allow_redirects=True)
                if resp.status_code == 200:
                    return {"platform": name, "url": url, "status": "found"}
            except Exception:
                pass
            return None

        found = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = {executor.submit(check_platform, name, url): name
                       for name, url in SocialDiscovery.PLATFORMS.items()}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
                    log(f"Found: {result['platform']} — {result['url']}", "data")

        results["findings"]["profiles"] = found
        results["findings"]["platforms_checked"] = len(SocialDiscovery.PLATFORMS)
        results["findings"]["profiles_found"] = len(found)
        log(f"Profiles found: {len(found)} / {len(SocialDiscovery.PLATFORMS)} checked", "pass")

        return results


# ═══════════════════════════════════════════════════════════════════════
# REPORT GENERATION
# ═══════════════════════════════════════════════════════════════════════
class Reporter:
    """Multi-format report generation."""

    @staticmethod
    def save(data, target, fmt="json"):
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        safe_target = re.sub(r"[^\w\-.]", "_", target)

        if fmt == "json":
            path = OUTPUT_DIR / f"publiceye-{safe_target}-{timestamp}.json"
            with open(path, "w") as f:
                json.dump(data, f, indent=2, default=str)
        elif fmt == "csv":
            path = OUTPUT_DIR / f"publiceye-{safe_target}-{timestamp}.csv"
            with open(path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["module", "key", "value"])
                for module_data in data.get("modules", []):
                    mod = module_data.get("module", "")
                    for key, val in module_data.get("findings", {}).items():
                        writer.writerow([mod, key, json.dumps(val, default=str)])
        elif fmt == "html":
            path = OUTPUT_DIR / f"publiceye-{safe_target}-{timestamp}.html"
            Reporter._generate_html(data, path)

        log(f"Report saved: {path}", "pass")
        return str(path)

    @staticmethod
    def _generate_html(data, path):
        modules_html = ""
        for mod in data.get("modules", []):
            findings = ""
            for k, v in mod.get("findings", {}).items():
                findings += f"<tr><td style='font-weight:600;color:#f0a500'>{k}</td><td>{json.dumps(v, default=str, indent=1)[:500]}</td></tr>"
            modules_html += f"""
            <h2 style="color:#00d4ff;border-bottom:1px solid #1e2d3e;padding-bottom:6px">{mod.get('module','')}</h2>
            <p style="color:#7a8ea0">Target: {mod.get('target','')}</p>
            <table style="width:100%;border-collapse:collapse"><tbody>{findings}</tbody></table>"""

        html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>PublicEye Report</title>
<style>body{{font-family:monospace;background:#0a0e14;color:#c8d6e5;padding:24px;max-width:960px;margin:0 auto}}
h1{{color:#f0a500}}td{{padding:6px 10px;border-bottom:1px solid #1e2d3e;font-size:13px;vertical-align:top;word-break:break-all}}</style></head>
<body><h1>PublicEye OSINT Report</h1>
<p>Generated: {datetime.datetime.now().isoformat()}</p>
<p>Target: {data.get('target','')}</p>
{modules_html}
<p style="margin-top:24px;color:#4a5d70;font-size:12px">PublicEye v{VERSION} — github.com/SiteQ8/PublicEye</p>
</body></html>"""
        with open(path, "w") as f:
            f.write(html)


# ═══════════════════════════════════════════════════════════════════════
# CLI INTERFACE
# ═══════════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description="PublicEye — Open Source Intelligence Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modules:
  domain       Domain intelligence (DNS, WHOIS, HTTP headers, security)
  ssl          SSL/TLS certificate and protocol analysis
  subdomains   Subdomain enumeration (CT logs + DNS brute-force)
  ip           IP intelligence (geolocation, reverse DNS, ASN)
  email        Email infrastructure analysis (MX, SPF, DMARC, DKIM)
  tech         Web technology fingerprinting
  ports        Lightweight TCP port scanner
  social       Social media username discovery
  full         Run all applicable modules

Examples:
  publiceye.py -t example.com -m domain
  publiceye.py -t example.com -m full
  publiceye.py -t 8.8.8.8 -m ip
  publiceye.py -t user@example.com -m email
  publiceye.py -t johndoe -m social
  publiceye.py -t example.com -m subdomains -o html
        """
    )
    parser.add_argument("-t", "--target", required=True, help="Target (domain, IP, email, username)")
    parser.add_argument("-m", "--module", required=True, help="Module to run (domain,ssl,subdomains,ip,email,tech,ports,social,full)")
    parser.add_argument("-o", "--output", choices=["json", "csv", "html"], default="json", help="Output format")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--threads", type=int, default=10, help="Max concurrent threads")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("--version", action="version", version=f"PublicEye v{VERSION}")

    args = parser.parse_args()

    CONFIG["verbose"] = args.verbose
    CONFIG["max_threads"] = args.threads
    CONFIG["timeout"] = args.timeout

    print(BANNER)

    modules_to_run = args.module.lower().split(",")
    all_results = {"target": args.target, "timestamp": datetime.datetime.now().isoformat(),
                   "version": VERSION, "modules": []}

    MODULE_MAP = {
        "domain": DomainIntel,
        "ssl": SSLAnalysis,
        "subdomains": SubdomainEnum,
        "ip": IPIntel,
        "email": EmailIntel,
        "tech": TechFingerprint,
        "ports": PortScanner,
        "social": SocialDiscovery,
    }

    if "full" in modules_to_run:
        # Determine applicable modules based on target type
        if "@" in args.target:
            modules_to_run = ["email"]
        elif re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", args.target):
            modules_to_run = ["ip", "ports"]
        elif "." in args.target:
            modules_to_run = ["domain", "ssl", "subdomains", "ip", "email", "tech", "ports"]
        else:
            modules_to_run = ["social"]

    for mod_name in modules_to_run:
        mod_class = MODULE_MAP.get(mod_name)
        if mod_class:
            print(f"\n{'='*60}")
            result = mod_class.run(args.target)
            all_results["modules"].append(result)
        else:
            log(f"Unknown module: {mod_name}", "warn")

    # Save report
    print(f"\n{'='*60}")
    Reporter.save(all_results, args.target, args.output)
    Reporter.save(all_results, args.target, "html")

    # Summary
    total_findings = sum(len(m.get("findings", {})) for m in all_results["modules"])
    print(f"\n{Colors.BOLD}{'='*60}{Colors.N}")
    print(f"  PublicEye Scan Complete")
    print(f"{'='*60}")
    print(f"  Target:   {args.target}")
    print(f"  Modules:  {len(all_results['modules'])}")
    print(f"  Findings: {total_findings}")
    print(f"  Output:   {OUTPUT_DIR}/")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
