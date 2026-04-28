#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║   SPAT CLI - Security Posture Analysis Tool          ║
║   by Antibody Cyber Technology, LLC                  ║
║   https://antibodycyber.com                          ║
╚══════════════════════════════════════════════════════╝
"""

import argparse
import json
import os
import re
import socket
import ssl
import struct
import subprocess
import sys
import time
import threading

# ── Force UTF-8 output on Windows (avoids cp1252 UnicodeEncodeError) ───────
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr.encoding and sys.stderr.encoding.lower() != "utf-8":
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

# ── Rich (optional, falls back to plain ANSI) ──────────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.progress import Progress, SpinnerColumn, TextColumn
    console = Console()
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    console = None

# ── ANSI fallback colours ──────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

VERSION = "1.0.0"

BANNER = rf"""
{CYAN}{BOLD}
  ███████╗██████╗  █████╗ ████████╗
  ██╔════╝██╔══██╗██╔══██╗╚══██╔══╝
  ███████╗██████╔╝███████║   ██║
  ╚════██║██╔═══╝ ██╔══██║   ██║
  ███████║██║     ██║  ██║   ██║
  ╚══════╝╚═╝     ╚═╝  ╚═╝   ╚═╝   {RED}CLI v{VERSION}{CYAN}

  Security Posture Analysis Tool
  by Antibody Cyber Technology, LLC
{RESET}"""


# ═══════════════════════════════════════════════════════════════════════════
# OUTPUT HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def _status_icon(status: str) -> str:
    return {"pass": f"{GREEN}✔{RESET}", "warn": f"{YELLOW}⚠{RESET}",
            "fail": f"{RED}✘{RESET}", "info": f"{CYAN}ℹ{RESET}"}.get(status, "?")


def print_finding(finding: dict):
    icon = _status_icon(finding.get("status", "info"))
    cat  = finding.get("category", "")
    name = finding.get("name", "")
    desc = finding.get("description", "")
    ev   = finding.get("evidence", "")
    rem  = finding.get("remediation", "")
    sev  = finding.get("severity", "")

    sev_color = {"HIGH": RED, "MEDIUM": YELLOW, "LOW": GREEN, "INFO": CYAN}.get(sev, "")

    if HAS_RICH:
        sev_style = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "green", "INFO": "cyan"}.get(sev, "white")
        rich_icon = {"pass": "[green]✔[/]", "warn": "[yellow]⚠[/]",
                     "fail": "[red]✘[/]", "info": "[cyan]ℹ[/]"}.get(finding.get("status", "info"), "?")
        console.print(f"  {rich_icon}  [{sev_style}]{name}[/]  [cyan]\\[{cat}][/cyan]")
        if desc:
            console.print(f"       {desc}")
        if ev:
            console.print(f"       [dim]Evidence: {ev[:120]}[/dim]")
        if rem and finding.get("status") in ("fail", "warn"):
            console.print(f"       [yellow]Fix: {rem}[/yellow]")
    else:
        print(f"  {icon}  {BOLD}{name}{RESET}  {CYAN}[{cat}]{RESET}")
        if desc:
            print(f"       {desc}")
        if ev:
            print(f"       Evidence: {ev[:120]}")
        if rem and finding.get("status") in ("fail", "warn"):
            print(f"       {YELLOW}Fix: {rem}{RESET}")


def print_section(title: str):
    line = "─" * 54
    print(f"\n{CYAN}{BOLD}{line}{RESET}")
    print(f"{CYAN}{BOLD}  {title}{RESET}")
    print(f"{CYAN}{BOLD}{line}{RESET}")


def print_score(score: int):
    if score >= 80:
        color, grade = GREEN, "A"
    elif score >= 65:
        color, grade = YELLOW, "B"
    elif score >= 50:
        color, grade = YELLOW, "C"
    else:
        color, grade = RED, "F"
    bar_len = score // 5
    bar = "█" * bar_len + "░" * (20 - bar_len)
    print(f"\n{BOLD}  Security Score:  {color}{score}/100  Grade: {grade}{RESET}")
    print(f"  [{color}{bar}{RESET}]")


# ═══════════════════════════════════════════════════════════════════════════
# DNS CHECK
# ═══════════════════════════════════════════════════════════════════════════

def check_dns(hostname: str) -> list:
    findings = []
    try:
        ips = list({r[4][0] for r in socket.getaddrinfo(hostname, None)})
        findings.append({
            "name": "DNS Resolution", "category": "DNS", "severity": "INFO",
            "description": f"Resolved to {', '.join(ips)}",
            "evidence": f"IPs: {', '.join(ips)}", "remediation": "",
            "status": "pass", "score_impact": 0
        })
    except socket.gaierror as e:
        findings.append({
            "name": "DNS Resolution", "category": "DNS", "severity": "HIGH",
            "description": f"Cannot resolve hostname: {e}",
            "evidence": str(e),
            "remediation": "Verify the hostname is correct and DNS is configured.",
            "status": "fail", "score_impact": 20
        })
    return findings


# ═══════════════════════════════════════════════════════════════════════════
# TLS / SSL CHECKS
# ═══════════════════════════════════════════════════════════════════════════

def check_tls(hostname: str) -> list:
    findings = []
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                proto = ssock.version()
                cipher = ssock.cipher()

        not_after = datetime.strptime(
            cert["notAfter"].rsplit(" ", 1)[0], "%b %d %H:%M:%S %Y"
        ).replace(tzinfo=timezone.utc)
        days_left = (not_after - datetime.now(timezone.utc)).days

        subject = dict(x[0] for x in cert.get("subject", ()))
        issuer  = dict(x[0] for x in cert.get("issuer", ()))
        cn = subject.get("commonName", "unknown")
        issuer_name = issuer.get("organizationName", "unknown")

        # Expiry
        if days_left < 0:
            findings.append({
                "name": "TLS Certificate Expired", "category": "TLS/SSL",
                "severity": "HIGH",
                "description": f"Certificate expired {abs(days_left)} days ago.",
                "evidence": f"CN={cn}, Expired: {cert['notAfter']}",
                "remediation": "Renew the certificate immediately.",
                "status": "fail", "score_impact": 20
            })
        elif days_left < 30:
            findings.append({
                "name": "TLS Certificate Expiring Soon", "category": "TLS/SSL",
                "severity": "MEDIUM",
                "description": f"Certificate expires in {days_left} days.",
                "evidence": f"Expires: {cert['notAfter']}",
                "remediation": "Renew the certificate before it expires.",
                "status": "warn", "score_impact": 8
            })
        else:
            findings.append({
                "name": "TLS Certificate Valid", "category": "TLS/SSL",
                "severity": "INFO",
                "description": f"Valid for {days_left} days. CN={cn}, Issuer={issuer_name}",
                "evidence": f"Proto={proto}, Cipher={cipher[0]}",
                "remediation": "", "status": "pass", "score_impact": 0
            })
    except ssl.CertificateError as e:
        findings.append({
            "name": "TLS Certificate Error", "category": "TLS/SSL",
            "severity": "HIGH",
            "description": f"Certificate validation failed: {e}",
            "evidence": str(e),
            "remediation": "Check certificate chain and hostname matching.",
            "status": "fail", "score_impact": 15
        })
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        findings.append({
            "name": "TLS Not Available", "category": "TLS/SSL",
            "severity": "HIGH",
            "description": f"Cannot connect to port 443: {e}",
            "evidence": str(e),
            "remediation": "Ensure HTTPS is enabled on the server.",
            "status": "fail", "score_impact": 15
        })
    return findings


def check_tls_protocols(hostname: str) -> list:
    findings = []
    weak = []
    strong = []
    proto_map = {
        "TLSv1":   (ssl.PROTOCOL_TLS_CLIENT, {"minimum_version": ssl.TLSVersion.TLSv1},   True),
        "TLSv1.1": (ssl.PROTOCOL_TLS_CLIENT, {"minimum_version": ssl.TLSVersion.TLSv1_1}, True),
        "TLSv1.2": (ssl.PROTOCOL_TLS_CLIENT, {"minimum_version": ssl.TLSVersion.TLSv1_2}, False),
        "TLSv1.3": (ssl.PROTOCOL_TLS_CLIENT, {"minimum_version": ssl.TLSVersion.TLSv1_3}, False),
    }
    for proto_name, (_, opts, is_weak) in proto_map.items():
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            if hasattr(ssl, "TLSVersion"):
                ver = opts.get("minimum_version")
                if ver:
                    try:
                        ctx.minimum_version = ver
                        ctx.maximum_version = ver
                    except (AttributeError, ssl.SSLError):
                        continue
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname):
                    if is_weak:
                        weak.append(proto_name)
                    else:
                        strong.append(proto_name)
        except Exception:
            pass

    if weak:
        findings.append({
            "name": "Weak TLS Protocols Enabled", "category": "TLS/SSL",
            "severity": "HIGH",
            "description": f"Deprecated protocols accepted: {', '.join(weak)}",
            "evidence": f"Weak: {', '.join(weak)}",
            "remediation": "Disable TLSv1.0 and TLSv1.1 in server config. Allow only TLSv1.2+.",
            "status": "fail", "score_impact": 10
        })
    if strong:
        findings.append({
            "name": "Strong TLS Protocols", "category": "TLS/SSL",
            "severity": "INFO",
            "description": f"Modern TLS supported: {', '.join(strong)}",
            "evidence": f"Strong: {', '.join(strong)}",
            "remediation": "", "status": "pass", "score_impact": 0
        })
    return findings


# ═══════════════════════════════════════════════════════════════════════════
# HTTP HEADERS CHECK
# ═══════════════════════════════════════════════════════════════════════════

def _http_get(url: str, max_redirs: int = 3) -> tuple:
    """Returns (status_code, headers_dict, body) via curl."""
    try:
        result = subprocess.run(
            ["curl", "-sk", "-D", "-", "--max-time", "10",
             "--max-redirs", str(max_redirs), "-o", os.devnull, url],
            capture_output=True, text=True, timeout=15
        )
        output = result.stdout
        lines = output.split("\n")
        status_code = 0
        headers = {}
        for line in lines:
            line = line.strip()
            if line.startswith("HTTP/"):
                try:
                    status_code = int(line.split()[1])
                except (IndexError, ValueError):
                    pass
            elif ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()
        return status_code, headers, ""
    except Exception:
        return 0, {}, ""


def check_http_headers(hostname: str) -> list:
    findings = []
    _, headers, _ = _http_get(f"https://{hostname}/")
    if not headers:
        return findings

    security_headers = {
        "strict-transport-security": ("HSTS",                  "HIGH",   6),
        "content-security-policy":   ("Content-Security-Policy","HIGH",   6),
        "x-frame-options":           ("X-Frame-Options",        "MEDIUM", 4),
        "x-content-type-options":    ("X-Content-Type-Options", "MEDIUM", 3),
        "referrer-policy":           ("Referrer-Policy",        "LOW",    2),
        "permissions-policy":        ("Permissions-Policy",     "LOW",    2),
    }
    missing = []
    present = []
    for h, (name, sev, _) in security_headers.items():
        if h in headers:
            present.append(name)
        else:
            missing.append(name)

    if missing:
        findings.append({
            "name": "Missing Security Headers", "category": "HTTP Security",
            "severity": "MEDIUM",
            "description": f"Missing: {', '.join(missing)}",
            "evidence": f"Present: {', '.join(present) or 'none'}",
            "remediation": "Add missing headers to your web server or application config.",
            "status": "fail" if len(missing) > 2 else "warn",
            "score_impact": min(len(missing) * 2, 12)
        })
    else:
        findings.append({
            "name": "Security Headers Complete", "category": "HTTP Security",
            "severity": "INFO",
            "description": "All recommended security headers are present.",
            "evidence": f"Present: {', '.join(present)}",
            "remediation": "", "status": "pass", "score_impact": 0
        })

    # Server/tech disclosure
    info_headers = {
        "server": headers.get("server", ""),
        "x-powered-by": headers.get("x-powered-by", "")
    }
    disclosed = [f"{k}: {v}" for k, v in info_headers.items() if v]
    if disclosed:
        findings.append({
            "name": "Server Version Disclosure", "category": "HTTP Security",
            "severity": "LOW",
            "description": "Server is leaking version information.",
            "evidence": "; ".join(disclosed),
            "remediation": "Remove or genericize Server and X-Powered-By headers.",
            "status": "warn", "score_impact": 3
        })
    return findings


def check_http_redirect(hostname: str) -> list:
    findings = []
    status, headers, _ = _http_get(f"http://{hostname}/", max_redirs=0)
    if status in (301, 302, 307, 308):
        loc = headers.get("location", "")
        if loc.startswith("https://"):
            findings.append({
                "name": "HTTP→HTTPS Redirect", "category": "HTTP Security",
                "severity": "INFO",
                "description": f"HTTP redirects to HTTPS ({status}).",
                "evidence": f"Location: {loc[:80]}",
                "remediation": "", "status": "pass", "score_impact": 0
            })
        else:
            findings.append({
                "name": "HTTP Redirect Not HTTPS", "category": "HTTP Security",
                "severity": "MEDIUM",
                "description": f"HTTP redirects but not to HTTPS: {loc[:60]}",
                "evidence": f"Status={status}, Location={loc[:60]}",
                "remediation": "Ensure HTTP redirects to HTTPS only.",
                "status": "warn", "score_impact": 5
            })
    elif status == 200:
        findings.append({
            "name": "No HTTP→HTTPS Redirect", "category": "HTTP Security",
            "severity": "HIGH",
            "description": "Site is accessible over plain HTTP without redirect.",
            "evidence": f"HTTP 200 on http://{hostname}/",
            "remediation": "Add a 301 redirect from HTTP to HTTPS.",
            "status": "fail", "score_impact": 8
        })
    return findings


# ═══════════════════════════════════════════════════════════════════════════
# PORT SCAN
# ═══════════════════════════════════════════════════════════════════════════

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 1433: "MSSQL", 1521: "Oracle", 2222: "Alt-SSH",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB"
}

RISKY_PORTS = {23, 445, 1433, 1521, 3389, 5900, 6379, 27017}
EXPECTED_OPEN = {22, 80, 443}


def _probe_port(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def check_ports(hostname: str) -> list:
    findings = []
    open_ports = {}

    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        return findings

    with ThreadPoolExecutor(max_workers=30) as ex:
        futures = {ex.submit(_probe_port, ip, p): p for p in COMMON_PORTS}
        for fut in as_completed(futures):
            p = futures[fut]
            if fut.result():
                open_ports[p] = COMMON_PORTS[p]

    unexpected = {p: s for p, s in open_ports.items() if p not in EXPECTED_OPEN}
    risky_open  = {p: s for p, s in unexpected.items() if p in RISKY_PORTS}

    # Telnet check
    if 23 in open_ports:
        findings.append({
            "name": "Telnet Open (Port 23)", "category": "Network",
            "severity": "HIGH",
            "description": "Telnet transmits data in cleartext — replace with SSH.",
            "evidence": "Port 23 open",
            "remediation": "Disable Telnet. Use SSH instead.",
            "status": "fail", "score_impact": 15
        })

    if risky_open:
        findings.append({
            "name": "High-Risk Ports Exposed", "category": "Network",
            "severity": "HIGH",
            "description": f"Sensitive services reachable from internet: "
                           f"{', '.join(f'{p}/{s}' for p,s in risky_open.items())}",
            "evidence": str(risky_open),
            "remediation": "Restrict access with firewall rules. Expose only necessary ports.",
            "status": "fail", "score_impact": 10
        })
    elif unexpected:
        findings.append({
            "name": "Non-Standard Ports Open", "category": "Network",
            "severity": "MEDIUM",
            "description": f"Open: {', '.join(f'{p}/{s}' for p,s in unexpected.items())}",
            "evidence": str(unexpected),
            "remediation": "Review if these ports need to be publicly accessible.",
            "status": "warn", "score_impact": 4
        })
    else:
        findings.append({
            "name": "Port Exposure OK", "category": "Network",
            "severity": "INFO",
            "description": f"Only expected ports open: {', '.join(f'{p}/{s}' for p,s in open_ports.items())}",
            "evidence": str(open_ports),
            "remediation": "", "status": "pass", "score_impact": 0
        })
    return findings


# ═══════════════════════════════════════════════════════════════════════════
# ROBOTS.TXT
# ═══════════════════════════════════════════════════════════════════════════

def check_robots(hostname: str) -> list:
    findings = []
    try:
        result = subprocess.run(
            ["curl", "-sk", "--max-time", "8", f"https://{hostname}/robots.txt"],
            capture_output=True, text=True, timeout=12
        )
        body = result.stdout
        if body and "user-agent" in body.lower():
            findings.append({
                "name": "robots.txt Present", "category": "Web",
                "severity": "INFO",
                "description": "robots.txt found and readable.",
                "evidence": body[:200],
                "remediation": "", "status": "pass", "score_impact": 0
            })
        else:
            findings.append({
                "name": "robots.txt Missing", "category": "Web",
                "severity": "LOW",
                "description": "No robots.txt found.",
                "evidence": "404 or empty response",
                "remediation": "Add a robots.txt to control crawler access.",
                "status": "warn", "score_impact": 1
            })
    except Exception:
        pass
    return findings


# ═══════════════════════════════════════════════════════════════════════════
# SSH CHECKS  ← New in SPAT CLI
# ═══════════════════════════════════════════════════════════════════════════

def _ssh_banner(hostname: str, port: int = 22, timeout: float = 8.0) -> str:
    """Connect to SSH port and grab the version banner."""
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            banner = sock.recv(256).decode("utf-8", errors="replace").strip()
            return banner
    except Exception:
        return ""


def _ssh_kex_algorithms(hostname: str, port: int = 22, timeout: float = 10.0) -> dict:
    """
    Perform a raw SSH handshake to extract algorithm lists from SSH_MSG_KEXINIT.
    Returns dict with keys: kex, server_host_key, enc_cs, enc_sc, mac_cs, mac_sc.
    """
    result = {}
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            # Read server banner
            sock.recv(256)
            # Send client banner
            sock.sendall(b"SSH-2.0-SPAT_CLI_1.0\r\n")
            # Read SSH_MSG_KEXINIT (starts with 4-byte length + 1-byte padding + type 20)
            raw = b""
            start = time.time()
            while len(raw) < 5 and (time.time() - start) < timeout:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                raw += chunk

            if len(raw) < 5:
                return result

            # Parse packet: uint32 length | byte padding_length | payload
            pkt_len = struct.unpack(">I", raw[:4])[0]
            # Read remaining bytes if needed
            while len(raw) < 4 + pkt_len and (time.time() - start) < timeout:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                raw += chunk

            padding_len = raw[4]
            payload = raw[5: 4 + pkt_len - padding_len]

            if not payload or payload[0] != 20:  # SSH_MSG_KEXINIT
                return result

            pos = 1 + 16  # skip type byte + 16-byte cookie
            algo_fields = [
                "kex", "server_host_key",
                "enc_cs", "enc_sc",
                "mac_cs", "mac_sc",
                "compress_cs", "compress_sc"
            ]

            for field in algo_fields:
                if pos + 4 > len(payload):
                    break
                name_len = struct.unpack(">I", payload[pos:pos+4])[0]
                pos += 4
                if pos + name_len > len(payload):
                    break
                algos = payload[pos:pos+name_len].decode("utf-8", errors="replace")
                result[field] = [a.strip() for a in algos.split(",") if a.strip()]
                pos += name_len

    except Exception:
        pass
    return result


# Weak algorithm sets
WEAK_KEX = {
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
    "gss-gex-sha1-",
    "gss-group1-sha1-",
    "gss-group14-sha1-",
}
WEAK_CIPHERS = {
    "3des-cbc", "blowfish-cbc", "cast128-cbc", "arcfour", "arcfour128",
    "arcfour256", "aes128-cbc", "aes192-cbc", "aes256-cbc",
    "rijndael-cbc@lysator.liu.se",
}
WEAK_MACS = {
    "hmac-md5", "hmac-md5-96", "hmac-sha1", "hmac-sha1-96",
    "umac-64@openssh.com", "hmac-md5-etm@openssh.com",
    "hmac-md5-96-etm@openssh.com", "hmac-sha1-etm@openssh.com",
    "hmac-sha1-96-etm@openssh.com", "umac-64-etm@openssh.com",
}
WEAK_HOST_KEYS = {"ssh-dss", "ssh-dsa"}


def check_ssh(hostname: str, port: int = 22) -> list:
    findings = []

    # ── 1. Port reachability ───────────────────────────────────────────────
    if not _probe_port(hostname, port, timeout=5):
        findings.append({
            "name": f"SSH Port {port} Closed", "category": "SSH",
            "severity": "INFO",
            "description": f"No SSH service detected on port {port}.",
            "evidence": f"Connection refused to {hostname}:{port}",
            "remediation": "", "status": "info", "score_impact": 0
        })
        return findings

    # ── 2. Banner / version ────────────────────────────────────────────────
    banner = _ssh_banner(hostname, port)
    if banner:
        # Check for SSHv1
        if banner.startswith("SSH-1."):
            findings.append({
                "name": "SSH Protocol Version 1", "category": "SSH",
                "severity": "HIGH",
                "description": "SSHv1 is cryptographically broken and must not be used.",
                "evidence": banner,
                "remediation": "Disable SSHv1. Set 'Protocol 2' in sshd_config.",
                "status": "fail", "score_impact": 20
            })
        else:
            # Version disclosure
            findings.append({
                "name": "SSH Banner", "category": "SSH",
                "severity": "INFO",
                "description": f"SSH service is running.",
                "evidence": banner[:80],
                "remediation": "", "status": "pass", "score_impact": 0
            })
        # Check for old OpenSSH versions with known CVEs
        version_match = re.search(r"OpenSSH[_\s](\d+\.\d+)", banner)
        if version_match:
            ver = float(version_match.group(1))
            if ver < 8.0:
                findings.append({
                    "name": "Outdated OpenSSH Version", "category": "SSH",
                    "severity": "MEDIUM",
                    "description": f"OpenSSH {ver} has known vulnerabilities. Current stable is 9.x.",
                    "evidence": banner,
                    "remediation": "Upgrade OpenSSH to the latest stable version.",
                    "status": "warn", "score_impact": 8
                })
    else:
        findings.append({
            "name": "SSH No Banner", "category": "SSH",
            "severity": "LOW",
            "description": "Could not retrieve SSH banner.",
            "evidence": "Empty response", "remediation": "",
            "status": "warn", "score_impact": 0
        })

    # ── 3. Algorithm analysis ──────────────────────────────────────────────
    algos = _ssh_kex_algorithms(hostname, port)
    if not algos:
        findings.append({
            "name": "SSH Algorithm Probe Failed", "category": "SSH",
            "severity": "INFO",
            "description": "Could not parse SSH algorithm lists (may require nmap).",
            "evidence": "No kex_init parsed",
            "remediation": "Run: nmap --script ssh2-enum-algos -p 22 " + hostname,
            "status": "info", "score_impact": 0
        })
        return findings

    # KEX algorithms
    weak_kex_found = [a for a in algos.get("kex", [])
                      if any(a.startswith(w) for w in WEAK_KEX)]
    if weak_kex_found:
        findings.append({
            "name": "Weak SSH Key Exchange Algorithms", "category": "SSH",
            "severity": "HIGH",
            "description": f"Weak KEX algorithms accepted: {', '.join(weak_kex_found)}",
            "evidence": f"All KEX: {', '.join(algos.get('kex', [])[:5])}...",
            "remediation": "Remove weak KEX from KexAlgorithms in sshd_config. "
                           "Use: curve25519-sha256, diffie-hellman-group16-sha512, etc.",
            "status": "fail", "score_impact": 10
        })
    else:
        findings.append({
            "name": "SSH Key Exchange Algorithms OK", "category": "SSH",
            "severity": "INFO",
            "description": f"KEX: {', '.join(algos.get('kex', [])[:3])}...",
            "evidence": "No weak KEX detected",
            "remediation": "", "status": "pass", "score_impact": 0
        })

    # Encryption ciphers
    weak_enc = [a for a in algos.get("enc_cs", []) if a in WEAK_CIPHERS]
    if weak_enc:
        findings.append({
            "name": "Weak SSH Ciphers", "category": "SSH",
            "severity": "HIGH",
            "description": f"Weak ciphers accepted: {', '.join(weak_enc)}",
            "evidence": f"All ciphers: {', '.join(algos.get('enc_cs', [])[:5])}...",
            "remediation": "Update Ciphers in sshd_config. "
                           "Use: aes256-gcm@openssh.com, chacha20-poly1305@openssh.com, aes128-gcm@openssh.com.",
            "status": "fail", "score_impact": 10
        })
    else:
        findings.append({
            "name": "SSH Ciphers OK", "category": "SSH",
            "severity": "INFO",
            "description": f"Ciphers: {', '.join(algos.get('enc_cs', [])[:3])}...",
            "evidence": "No weak ciphers detected",
            "remediation": "", "status": "pass", "score_impact": 0
        })

    # MAC algorithms
    weak_mac = [a for a in algos.get("mac_cs", []) if a in WEAK_MACS]
    if weak_mac:
        findings.append({
            "name": "Weak SSH MAC Algorithms", "category": "SSH",
            "severity": "MEDIUM",
            "description": f"Weak MACs accepted: {', '.join(weak_mac)}",
            "evidence": f"All MACs: {', '.join(algos.get('mac_cs', [])[:5])}...",
            "remediation": "Update MACs in sshd_config. "
                           "Use: hmac-sha2-512-etm@openssh.com, hmac-sha2-256-etm@openssh.com.",
            "status": "warn", "score_impact": 5
        })
    else:
        findings.append({
            "name": "SSH MAC Algorithms OK", "category": "SSH",
            "severity": "INFO",
            "description": f"MACs: {', '.join(algos.get('mac_cs', [])[:3])}...",
            "evidence": "No weak MACs detected",
            "remediation": "", "status": "pass", "score_impact": 0
        })

    # Host key types
    weak_hk = [a for a in algos.get("server_host_key", []) if a in WEAK_HOST_KEYS]
    if weak_hk:
        findings.append({
            "name": "Weak SSH Host Key Types", "category": "SSH",
            "severity": "HIGH",
            "description": f"Weak host key algorithms offered: {', '.join(weak_hk)}",
            "evidence": f"Host keys: {', '.join(algos.get('server_host_key', []))}",
            "remediation": "Remove DSA host keys. Use Ed25519 or RSA-SHA2-512.",
            "status": "fail", "score_impact": 8
        })
    else:
        findings.append({
            "name": "SSH Host Key Types OK", "category": "SSH",
            "severity": "INFO",
            "description": f"Host keys: {', '.join(algos.get('server_host_key', []))}",
            "evidence": "No weak host key types",
            "remediation": "", "status": "pass", "score_impact": 0
        })

    return findings


def check_ssh_auth(hostname: str, port: int = 22) -> list:
    """
    Check if password authentication is enabled by attempting a
    deliberately-failed login and reading the auth methods from the response.
    Uses ssh -v with a non-existent key to probe auth methods.
    """
    findings = []
    if not _probe_port(hostname, port, timeout=5):
        return findings
    try:
        result = subprocess.run(
            ["ssh", "-v", "-o", "BatchMode=yes",
             "-o", "StrictHostKeyChecking=no",
             "-o", "ConnectTimeout=8",
             "-p", str(port),
             f"spat_probe_user@{hostname}"],
            capture_output=True, text=True, timeout=12
        )
        debug = result.stderr.lower()
        auth_methods = []
        for line in debug.split("\n"):
            if "authentications that can continue" in line:
                methods_str = line.split(":")[-1].strip()
                auth_methods = [m.strip() for m in methods_str.split(",")]
                break

        if auth_methods:
            if "password" in auth_methods:
                findings.append({
                    "name": "SSH Password Authentication Enabled", "category": "SSH",
                    "severity": "MEDIUM",
                    "description": "Password auth is enabled — vulnerable to brute-force attacks.",
                    "evidence": f"Auth methods: {', '.join(auth_methods)}",
                    "remediation": "Set 'PasswordAuthentication no' in sshd_config. Use key-based auth only.",
                    "status": "warn", "score_impact": 6
                })
            else:
                findings.append({
                    "name": "SSH Password Authentication Disabled", "category": "SSH",
                    "severity": "INFO",
                    "description": "Only public-key authentication is accepted.",
                    "evidence": f"Auth methods: {', '.join(auth_methods)}",
                    "remediation": "", "status": "pass", "score_impact": 0
                })
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return findings


# ═══════════════════════════════════════════════════════════════════════════
# EMAIL SECURITY  (SPF · DMARC · DKIM · MX)
# ═══════════════════════════════════════════════════════════════════════════

def _dns_txt_records(hostname: str) -> list:
    """Return TXT records for hostname using nslookup (cross-platform)."""
    records = []
    try:
        result = subprocess.run(
            ["nslookup", "-type=TXT", hostname],
            capture_output=True, text=True, timeout=10, errors="replace"
        )
        for line in result.stdout.split("\n"):
            if '"' in line:
                parts = re.findall(r'"([^"]*)"', line)
                if parts:
                    records.append(" ".join(parts))
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    if not records:
        try:
            result = subprocess.run(
                ["dig", "+short", hostname, "TXT"],
                capture_output=True, text=True, timeout=10, errors="replace"
            )
            for line in result.stdout.strip().split("\n"):
                if line.strip():
                    records.append(line.strip().replace('"', ""))
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
    return [r.strip() for r in records if r.strip()]


def _dns_mx_records(hostname: str) -> list:
    """Return MX records for hostname."""
    records = []
    try:
        result = subprocess.run(
            ["nslookup", "-type=MX", hostname],
            capture_output=True, text=True, timeout=10, errors="replace"
        )
        for line in result.stdout.split("\n"):
            lower = line.lower()
            if "mail exchanger" in lower or "mail exchange" in lower:
                records.append(line.strip())
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return records


def check_email_security(hostname: str) -> list:
    """Check SPF, DMARC, DKIM (common selectors), and MX records."""
    findings = []

    # ── MX records ─────────────────────────────────────────────────────────
    mx = _dns_mx_records(hostname)
    if mx:
        findings.append({
            "name": "MX Records Present", "category": "Email Security",
            "severity": "INFO",
            "description": f"Found {len(mx)} MX record(s) for {hostname}.",
            "evidence": "; ".join(mx[:3]),
            "remediation": "", "status": "pass", "score_impact": 0
        })
    else:
        findings.append({
            "name": "No MX Records", "category": "Email Security",
            "severity": "LOW",
            "description": f"No MX records found for {hostname}.",
            "evidence": "nslookup -type=MX returned empty",
            "remediation": "If this domain sends email, add MX records.",
            "status": "info", "score_impact": 0
        })

    # ── SPF ────────────────────────────────────────────────────────────────
    txt_records = _dns_txt_records(hostname)
    spf_records = [r for r in txt_records if r.startswith("v=spf1")]
    if not spf_records:
        findings.append({
            "name": "SPF Record Missing", "category": "Email Security",
            "severity": "HIGH",
            "description": "No SPF TXT record found. Anyone can spoof email from this domain.",
            "evidence": f"TXT records found: {len(txt_records)}",
            "remediation": 'Add a TXT record: "v=spf1 include:your-mail-provider.com ~all"',
            "status": "fail", "score_impact": 10
        })
    elif len(spf_records) > 1:
        findings.append({
            "name": "Multiple SPF Records", "category": "Email Security",
            "severity": "HIGH",
            "description": "More than one SPF record found — only one is allowed per RFC 7208.",
            "evidence": "; ".join(spf_records),
            "remediation": "Merge into a single SPF TXT record.",
            "status": "fail", "score_impact": 8
        })
    else:
        spf = spf_records[0]
        # Evaluate policy strength
        if "-all" in spf:
            qualifier, sev, impact = "hard fail (-all)", "pass", 0
        elif "~all" in spf:
            qualifier, sev, impact = "soft fail (~all) — spoofed mail may be accepted", "warn", 3
        elif "?all" in spf:
            qualifier, sev, impact = "neutral (?all) — provides no protection", "warn", 6
        elif "+all" in spf:
            qualifier, sev, impact = "+all ALLOWS ALL SENDERS — effectively useless", "fail", 12
        else:
            qualifier, sev, impact = "no explicit all — weak policy", "warn", 4
        status = "pass" if sev == "pass" else ("warn" if sev == "warn" else "fail")
        findings.append({
            "name": f"SPF Policy: {qualifier[:50]}", "category": "Email Security",
            "severity": "MEDIUM" if status in ("warn", "fail") else "INFO",
            "description": f"SPF record found. Policy: {qualifier}",
            "evidence": spf[:200],
            "remediation": 'Use "-all" (hard fail) instead of "~all" or weaker.',
            "status": status, "score_impact": impact
        })

    # ── DMARC ──────────────────────────────────────────────────────────────
    dmarc_host = f"_dmarc.{hostname}"
    dmarc_records = _dns_txt_records(dmarc_host)
    dmarc_found = [r for r in dmarc_records if "v=dmarc1" in r.lower()]
    if not dmarc_found:
        findings.append({
            "name": "DMARC Record Missing", "category": "Email Security",
            "severity": "HIGH",
            "description": "No DMARC policy. Phishing/spoofing attacks are not mitigated.",
            "evidence": f"_dmarc.{hostname} returned no DMARC record",
            "remediation": 'Add: _dmarc.{hostname} TXT "v=DMARC1; p=reject; rua=mailto:dmarc@{hostname}"',
            "status": "fail", "score_impact": 10
        })
    else:
        dmarc = dmarc_found[0]
        # Extract policy
        p_match = re.search(r'\bp=([^;]+)', dmarc, re.IGNORECASE)
        policy = p_match.group(1).strip().lower() if p_match else "none"
        if policy == "reject":
            status, impact, desc = "pass", 0, "DMARC policy=reject — full enforcement."
        elif policy == "quarantine":
            status, impact, desc = "warn", 4, "DMARC policy=quarantine — spoofed mail goes to spam, not rejected."
        else:  # none or missing
            status, impact, desc = "fail", 8, "DMARC policy=none — monitoring only, no enforcement."
        sp_match = re.search(r'\bsp=([^;]+)', dmarc, re.IGNORECASE)
        subdomain_policy = sp_match.group(1).strip() if sp_match else "not set (inherits p=)"
        findings.append({
            "name": f"DMARC Policy: {policy}", "category": "Email Security",
            "severity": "MEDIUM" if status in ("warn", "fail") else "INFO",
            "description": desc + f" Subdomain policy: {subdomain_policy}",
            "evidence": dmarc[:200],
            "remediation": 'Set p=reject and sp=reject. Add rua= for aggregate reports.',
            "status": status, "score_impact": impact
        })

    # ── DKIM (probe common selectors) ──────────────────────────────────────
    common_selectors = ["default", "google", "selector1", "selector2",
                        "k1", "dkim", "mail", "smtp", "s1", "s2"]
    dkim_found = []
    for sel in common_selectors:
        probe = f"{sel}._domainkey.{hostname}"
        records = _dns_txt_records(probe)
        if any("p=" in r and "v=dkim1" in r.lower() for r in records):
            dkim_found.append(sel)
    if dkim_found:
        findings.append({
            "name": "DKIM Key Found", "category": "Email Security",
            "severity": "INFO",
            "description": f"DKIM public key found for selector(s): {', '.join(dkim_found)}",
            "evidence": f"Selectors with valid keys: {', '.join(dkim_found)}",
            "remediation": "", "status": "pass", "score_impact": 0
        })
    else:
        findings.append({
            "name": "DKIM Key Not Detected", "category": "Email Security",
            "severity": "MEDIUM",
            "description": "No DKIM key found for common selectors. Outgoing email may be rejected or marked spam.",
            "evidence": f"Probed selectors: {', '.join(common_selectors)}",
            "remediation": "Configure DKIM signing and publish the public key as a DNS TXT record.",
            "status": "warn", "score_impact": 5
        })

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# TLS CIPHER SUITE ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════

# Cipher names/substrings that indicate weakness
_WEAK_CIPHER_PATTERNS = [
    "RC4", "3DES", "DES", "NULL", "EXPORT", "anon",
    "MD5", "ARIA", "SEED",
]
# Cipher patterns that indicate forward secrecy
_FS_PATTERNS = ["ECDHE", "DHE"]

# Specific weak cipher suites to probe
_WEAK_SUITE_STRINGS = [
    "RC4",
    "3DES",
    "DES:@SECLEVEL=0",
    "NULL:@SECLEVEL=0",
    "EXPORT:@SECLEVEL=0",
    "aNULL:@SECLEVEL=0",
]


def check_tls_ciphers(hostname: str) -> list:
    findings = []

    # ── Get negotiated cipher from default TLS handshake ───────────────────
    negotiated_name = ""
    negotiated_bits = 0
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                name, _, bits = ssock.cipher()
                negotiated_name = name or ""
                negotiated_bits = bits or 0
                negotiated_proto = ssock.version() or ""
    except Exception:
        return findings  # TLS not available — already covered by check_tls()

    # Forward secrecy check
    # TLS 1.3 ciphers (named TLS_*) always use ephemeral key exchange — FS is
    # guaranteed by the protocol regardless of the cipher name pattern.
    is_tls13 = negotiated_proto == "TLSv1.3" or negotiated_name.startswith("TLS_")
    has_fs = is_tls13 or any(p in negotiated_name for p in _FS_PATTERNS)
    if not has_fs:
        findings.append({
            "name": "No Forward Secrecy", "category": "TLS/SSL - Ciphers",
            "severity": "HIGH",
            "description": f"Negotiated cipher lacks forward secrecy: {negotiated_name}",
            "evidence": f"Cipher: {negotiated_name}, Bits: {negotiated_bits}",
            "remediation": "Prefer ECDHE or DHE cipher suites to enable Perfect Forward Secrecy.",
            "status": "fail", "score_impact": 10
        })
    else:
        fs_note = "TLS 1.3 guarantees ephemeral key exchange" if is_tls13 else f"Cipher uses ECDHE/DHE: {negotiated_name}"
        findings.append({
            "name": "Forward Secrecy Supported", "category": "TLS/SSL - Ciphers",
            "severity": "INFO",
            "description": f"Forward secrecy confirmed. {fs_note}",
            "evidence": f"Cipher: {negotiated_name}, Bits: {negotiated_bits}",
            "remediation": "", "status": "pass", "score_impact": 0
        })

    # Bit-strength check
    if 0 < negotiated_bits < 128:
        findings.append({
            "name": f"Weak Cipher Key Length ({negotiated_bits}-bit)", "category": "TLS/SSL - Ciphers",
            "severity": "HIGH",
            "description": f"Negotiated cipher uses fewer than 128 bits: {negotiated_name}.",
            "evidence": f"Key bits: {negotiated_bits}",
            "remediation": "Configure server to prefer AES-128 or AES-256 suites.",
            "status": "fail", "score_impact": 10
        })

    # Probe for accepted weak cipher suites
    weak_accepted = []
    for suite_str in _WEAK_SUITE_STRINGS:
        try:
            ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx2.check_hostname = False
            ctx2.verify_mode = ssl.CERT_NONE
            ctx2.set_ciphers(suite_str)
            with socket.create_connection((hostname, 443), timeout=4) as sock:
                with ctx2.wrap_socket(sock, server_hostname=hostname) as ssock:
                    accepted = ssock.cipher()
                    if accepted:
                        cipher_name = accepted[0] or ""
                        # set_ciphers() does NOT control TLS 1.3 ciphers; if the
                        # server fell back to a TLS 1.3 suite (TLS_*) the weak
                        # probe was effectively rejected — don't flag it.
                        if not cipher_name.startswith("TLS_"):
                            weak_accepted.append(cipher_name)
        except ssl.SSLError:
            pass  # cipher not accepted
        except Exception:
            pass

    if weak_accepted:
        findings.append({
            "name": "Weak Cipher Suites Accepted", "category": "TLS/SSL - Ciphers",
            "severity": "HIGH",
            "description": f"Server accepts deprecated/weak ciphers: {', '.join(weak_accepted)}",
            "evidence": f"Accepted: {', '.join(weak_accepted)}",
            "remediation": "Disable weak cipher suites. Use AES-GCM or ChaCha20-Poly1305.",
            "status": "fail", "score_impact": 12
        })
    else:
        findings.append({
            "name": "No Weak Cipher Suites", "category": "TLS/SSL - Ciphers",
            "severity": "INFO",
            "description": "Server rejected RC4, 3DES, NULL, and EXPORT cipher suites.",
            "evidence": f"Probed {len(_WEAK_SUITE_STRINGS)} weak suite patterns; all rejected.",
            "remediation": "", "status": "pass", "score_impact": 0
        })

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# COOKIE SECURITY
# ═══════════════════════════════════════════════════════════════════════════

def check_cookie_security(hostname: str) -> list:
    findings = []
    try:
        result = subprocess.run(
            ["curl", "-sk", "-D", "-", "--max-time", "10", "-o", os.devnull,
             "-A", "Mozilla/5.0",
             f"https://{hostname}/"],
            capture_output=True, text=True, timeout=15
        )
        raw_headers = result.stdout
    except Exception:
        return findings

    cookies_raw = re.findall(
        r'(?i)^set-cookie:\s*(.+)$', raw_headers, re.MULTILINE
    )
    if not cookies_raw:
        findings.append({
            "name": "No Cookies Set", "category": "Cookie Security",
            "severity": "INFO",
            "description": "No Set-Cookie headers found on the home page.",
            "evidence": "curl response contained no Set-Cookie headers.",
            "remediation": "", "status": "info", "score_impact": 0
        })
        return findings

    missing_secure    = []
    missing_httponly  = []
    missing_samesite  = []
    samesite_none     = []

    for raw in cookies_raw:
        # Extract cookie name
        name_match = re.match(r'([^=;,\s]+)', raw)
        name = name_match.group(1) if name_match else raw[:20]
        lower = raw.lower()
        if "secure" not in lower:
            missing_secure.append(name)
        if "httponly" not in lower:
            missing_httponly.append(name)
        ss_match = re.search(r'samesite=(\w+)', lower)
        if not ss_match:
            missing_samesite.append(name)
        elif ss_match.group(1) == "none":
            samesite_none.append(name)

    total = len(cookies_raw)
    if missing_secure:
        findings.append({
            "name": "Cookies Missing Secure Flag", "category": "Cookie Security",
            "severity": "HIGH",
            "description": f"{len(missing_secure)}/{total} cookie(s) lack the Secure flag — transmitted over HTTP.",
            "evidence": f"Affected: {', '.join(missing_secure[:5])}",
            "remediation": "Add the Secure attribute to all sensitive cookies.",
            "status": "fail", "score_impact": 8
        })
    if missing_httponly:
        findings.append({
            "name": "Cookies Missing HttpOnly Flag", "category": "Cookie Security",
            "severity": "MEDIUM",
            "description": f"{len(missing_httponly)}/{total} cookie(s) lack HttpOnly — readable by JavaScript (XSS risk).",
            "evidence": f"Affected: {', '.join(missing_httponly[:5])}",
            "remediation": "Add the HttpOnly attribute to all session/auth cookies.",
            "status": "warn", "score_impact": 5
        })
    if missing_samesite:
        findings.append({
            "name": "Cookies Missing SameSite Attribute", "category": "Cookie Security",
            "severity": "MEDIUM",
            "description": f"{len(missing_samesite)}/{total} cookie(s) lack SameSite — vulnerable to CSRF.",
            "evidence": f"Affected: {', '.join(missing_samesite[:5])}",
            "remediation": "Add SameSite=Strict or SameSite=Lax to all cookies.",
            "status": "warn", "score_impact": 4
        })
    if samesite_none:
        findings.append({
            "name": "Cookies with SameSite=None", "category": "Cookie Security",
            "severity": "MEDIUM",
            "description": f"{len(samesite_none)} cookie(s) use SameSite=None — sent on cross-site requests.",
            "evidence": f"Affected: {', '.join(samesite_none[:5])}",
            "remediation": "Only use SameSite=None when truly required (e.g. embedded widgets). Ensure Secure is also set.",
            "status": "warn", "score_impact": 3
        })
    if not any(f["status"] in ("fail", "warn") for f in findings):
        findings.append({
            "name": "Cookie Security Flags OK", "category": "Cookie Security",
            "severity": "INFO",
            "description": f"All {total} cookie(s) have Secure, HttpOnly, and SameSite set.",
            "evidence": f"Checked {total} Set-Cookie header(s).",
            "remediation": "", "status": "pass", "score_impact": 0
        })
    return findings


# ═══════════════════════════════════════════════════════════════════════════
# CORS MISCONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

def check_cors(hostname: str) -> list:
    findings = []
    try:
        result = subprocess.run(
            ["curl", "-sk", "-D", "-", "--max-time", "10", "-o", os.devnull,
             "-H", "Origin: https://evil.example.com",
             f"https://{hostname}/"],
            capture_output=True, text=True, timeout=15
        )
        raw = result.stdout.lower()
    except Exception:
        return findings

    acao = ""
    acac = ""
    for line in raw.split("\n"):
        if line.startswith("access-control-allow-origin:"):
            acao = line.split(":", 1)[1].strip()
        if line.startswith("access-control-allow-credentials:"):
            acac = line.split(":", 1)[1].strip()

    if not acao:
        findings.append({
            "name": "CORS Not Enabled", "category": "CORS",
            "severity": "INFO",
            "description": "No Access-Control-Allow-Origin header — CORS requests blocked by default.",
            "evidence": "No ACAO header in response.",
            "remediation": "", "status": "pass", "score_impact": 0
        })
        return findings

    if acao == "*" and acac == "true":
        findings.append({
            "name": "CORS Wildcard + Credentials — CRITICAL", "category": "CORS",
            "severity": "CRITICAL",
            "description": "ACAO: * combined with ACAC: true is invalid per spec and signals a misconfiguration. Browsers block it, but some frameworks bypass it.",
            "evidence": f"ACAO: {acao}, ACAC: {acac}",
            "remediation": "Never combine ACAO: * with ACAC: true. Explicitly whitelist allowed origins.",
            "status": "fail", "score_impact": 20
        })
    elif acao == "*":
        findings.append({
            "name": "CORS Wildcard Origin (ACAO: *)", "category": "CORS",
            "severity": "MEDIUM",
            "description": "Any origin can read responses. Acceptable for public APIs; dangerous for authenticated endpoints.",
            "evidence": f"ACAO: {acao}",
            "remediation": "Restrict ACAO to known trusted origins if the API uses cookies or auth tokens.",
            "status": "warn", "score_impact": 5
        })
    elif acao == "https://evil.example.com":
        findings.append({
            "name": "CORS Origin Reflection — HIGH", "category": "CORS",
            "severity": "HIGH",
            "description": "Server echoes the request Origin header back without validation — any attacker origin is trusted.",
            "evidence": f"Sent Origin: https://evil.example.com → ACAO: {acao}",
            "remediation": "Validate the Origin against an explicit allowlist before reflecting it.",
            "status": "fail", "score_impact": 15
        })
    else:
        findings.append({
            "name": "CORS Origin Restricted", "category": "CORS",
            "severity": "INFO",
            "description": f"CORS origin is restricted: {acao}",
            "evidence": f"ACAO: {acao}",
            "remediation": "", "status": "pass", "score_impact": 0
        })
    return findings


# ═══════════════════════════════════════════════════════════════════════════
# DNSSEC VALIDATION
# ═══════════════════════════════════════════════════════════════════════════

def check_dnssec(hostname: str) -> list:
    findings = []

    # Try nslookup -type=DNSKEY first, fall back to dig
    def _has_dnssec_records(qtype: str, name: str) -> bool:
        try:
            r = subprocess.run(
                ["nslookup", f"-type={qtype}", name],
                capture_output=True, text=True, timeout=10, errors="replace"
            )
            out = r.stdout.lower()
            return qtype.lower() in out or "answer" in out and len(r.stdout.strip()) > 100
        except Exception:
            return False

    def _dig_has(qtype: str, name: str) -> bool:
        try:
            r = subprocess.run(
                ["dig", "+short", name, qtype],
                capture_output=True, text=True, timeout=10, errors="replace"
            )
            return bool(r.stdout.strip())
        except Exception:
            return False

    # Check for DNSKEY record (zone is signed)
    # We use dig if available for more reliable DNSSEC data
    dnskey_found = _dig_has("DNSKEY", hostname) or _dig_has("DNSKEY", hostname.split(".", 1)[-1] if "." in hostname else hostname)
    ds_found     = _dig_has("DS", hostname)
    rrsig_found  = _dig_has("RRSIG", hostname)

    if dnskey_found or rrsig_found:
        findings.append({
            "name": "DNSSEC Enabled", "category": "DNSSEC",
            "severity": "INFO",
            "description": "DNSSEC is configured — DNS responses are cryptographically signed.",
            "evidence": f"DNSKEY found: {dnskey_found}, RRSIG found: {rrsig_found}",
            "remediation": "", "status": "pass", "score_impact": 0
        })
    else:
        findings.append({
            "name": "DNSSEC Not Configured", "category": "DNSSEC",
            "severity": "MEDIUM",
            "description": "No DNSSEC records detected. DNS responses can be spoofed (DNS cache poisoning).",
            "evidence": "No DNSKEY or RRSIG records found via dig.",
            "remediation": "Enable DNSSEC signing at your DNS registrar/provider and add DS records.",
            "status": "warn", "score_impact": 5
        })

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# CSP QUALITY ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════

_CSP_UNSAFE = {
    "unsafe-inline":   ("Allows inline scripts/styles — bypasses XSS protection",           "HIGH",   8),
    "unsafe-eval":     ("Allows eval() — common XSS vector",                                 "HIGH",   6),
    "unsafe-hashes":   ("Allows inline event handlers — limited protection",                 "MEDIUM", 4),
    "unsafe-allows-redirects": ("Allows redirects from unsafe sources",                      "MEDIUM", 3),
}

_CSP_WILDCARD_DIRECTIVES = ["script-src", "default-src", "object-src", "frame-src"]


def check_csp_quality(hostname: str) -> list:
    findings = []
    try:
        result = subprocess.run(
            ["curl", "-sk", "-D", "-", "--max-time", "10", "-o", os.devnull,
             f"https://{hostname}/"],
            capture_output=True, text=True, timeout=15
        )
        raw = result.stdout
    except Exception:
        return findings

    csp_value = ""
    for line in raw.split("\n"):
        if line.lower().startswith("content-security-policy:"):
            csp_value = line.split(":", 1)[1].strip()
            break

    if not csp_value:
        # Already covered by check_http_headers; skip to avoid duplication
        return findings

    directives = {}
    for part in csp_value.split(";"):
        part = part.strip()
        if part:
            tokens = part.split()
            if tokens:
                directives[tokens[0].lower()] = tokens[1:]

    issues = []
    score_hit = 0

    # Check for unsafe keywords
    csp_lower = csp_value.lower()
    for kw, (desc, sev, impact) in _CSP_UNSAFE.items():
        if kw in csp_lower:
            issues.append(f"'{kw}': {desc}")
            score_hit += impact

    # Wildcard source in critical directives
    effective_src = directives.get("script-src") or directives.get("default-src", [])
    if "*" in effective_src:
        issues.append("'*' wildcard in script-src/default-src — any script from any domain is allowed")
        score_hit += 10

    # object-src not restricted
    if "object-src" not in directives and "default-src" not in directives:
        issues.append("object-src not set — plugins (Flash, Java applets) unrestricted")
        score_hit += 4
    elif "object-src" not in directives:
        obj_src = directives.get("default-src", [])
        if "*" in obj_src or not obj_src:
            issues.append("object-src not explicitly set to 'none' — inherited wildcard")
            score_hit += 3

    # No script-src or default-src
    if "script-src" not in directives and "default-src" not in directives:
        issues.append("No script-src or default-src — CSP provides no script restriction")
        score_hit += 8

    # No upgrade-insecure-requests (for mixed content)
    if "upgrade-insecure-requests" not in directives and "block-all-mixed-content" not in directives:
        issues.append("upgrade-insecure-requests not set — mixed content (HTTP on HTTPS) possible")
        score_hit += 2

    if issues:
        findings.append({
            "name": f"CSP Policy Weaknesses ({len(issues)})", "category": "CSP Analysis",
            "severity": "HIGH" if score_hit >= 10 else "MEDIUM",
            "description": "Content Security Policy is present but has significant weaknesses.",
            "evidence": " | ".join(issues),
            "remediation": "Remove unsafe-inline/unsafe-eval. Use nonces or hashes. Set object-src 'none'.",
            "status": "fail" if score_hit >= 8 else "warn",
            "score_impact": min(score_hit, 15)
        })
    else:
        findings.append({
            "name": "CSP Policy Strong", "category": "CSP Analysis",
            "severity": "INFO",
            "description": "Content Security Policy has no obvious weaknesses detected.",
            "evidence": csp_value[:200],
            "remediation": "", "status": "pass", "score_impact": 0
        })

    # Report the actual CSP for reference
    findings.append({
        "name": "CSP Policy (reference)", "category": "CSP Analysis",
        "severity": "INFO",
        "description": "Full CSP header for review.",
        "evidence": csp_value[:400],
        "remediation": "", "status": "info", "score_impact": 0
    })

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# SCORE CALCULATION
# ═══════════════════════════════════════════════════════════════════════════

def calculate_score(findings: list) -> int:
    score = 100
    for f in findings:
        score -= f.get("score_impact", 0)
    return max(0, min(100, score))


# ═══════════════════════════════════════════════════════════════════════════
# REPORT EXPORT
# ═══════════════════════════════════════════════════════════════════════════

def export_json(hostname: str, findings: list, score: int, outfile: str):
    data = {
        "tool": "SPAT CLI",
        "version": VERSION,
        "hostname": hostname,
        "scan_date": datetime.now(timezone.utc).isoformat(),
        "score": score,
        "findings": findings
    }
    Path(outfile).write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"\n  {GREEN}✔{RESET} JSON report saved: {outfile}")


def export_html(hostname: str, findings: list, score: int, outfile: str):
    status_color = {"pass": "#2ea043", "warn": "#d29922", "fail": "#f85149", "info": "#58a6ff"}

    if score >= 80:
        grade, sc = "A", "#2ea043"
    elif score >= 65:
        grade, sc = "B", "#3fb950"
    elif score >= 50:
        grade, sc = "C", "#d29922"
    else:
        grade, sc = "F", "#f85149"

    # Category colour mapping for visual grouping — must be defined before rows loop
    cat_colours = {
        "DNS":                "#58a6ff",
        "TLS/SSL":            "#79c0ff",
        "TLS/SSL - Ciphers":  "#79c0ff",
        "HTTP Security":      "#d2a8ff",
        "CSP Analysis":       "#d2a8ff",
        "Cookie Security":    "#f2cc60",
        "CORS":               "#ff7b72",
        "Email Security":     "#3fb950",
        "DNSSEC":             "#58a6ff",
        "Network":            "#ffa657",
        "SSH":                "#ffa657",
        "Web":                "#8b949e",
    }

    rows = ""
    for f in findings:
        sc_f = status_color.get(f.get("status", "info"), "#8b949e")
        icon = {"pass": "✔", "warn": "⚠", "fail": "✘", "info": "ℹ"}.get(f.get("status"), "?")
        cat = f.get("category", "")
        cat_clr = cat_colours.get(cat, "#8b949e")
        rows += f"""
        <tr>
          <td style="color:{sc_f};text-align:center;font-size:1.2em">{icon}</td>
          <td><strong>{f.get('name','')}</strong></td>
          <td style="color:{cat_clr}">{cat}</td>
          <td style="color:{sc_f}">{f.get('severity','')}</td>
          <td>{f.get('description','')}</td>
          <td style="color:#d29922">{f.get('remediation','') or '—'}</td>
        </tr>"""

    # Build category failure summary
    from collections import Counter
    cat_status = Counter()
    for f in findings:
        if f.get("status") == "fail":
            cat_status[f.get("category", "Other")] += 1

    cat_badges = "".join(
        f'<span style="display:inline-block;margin:3px;padding:3px 10px;border-radius:4px;'
        f'font-size:0.78em;background:#161b22;border:1px solid #21262d;color:#f85149">'
        f'{cat} ({n} fail{"s" if n > 1 else ""})</span>'
        for cat, n in sorted(cat_status.items())
    )
    if not cat_badges:
        cat_badges = '<span style="color:#2ea043">No failures detected across all categories.</span>'

    checks_run = list({f.get("category", "") for f in findings})

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SPAT Report - {hostname}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: #0d1117; color: #e6edf3; margin: 0; padding: 24px; }}
  h1 {{ color: #e94560; margin: 0 0 4px; }}
  h2 {{ color: #58a6ff; margin: 24px 0 12px; }}
  .score-block {{ display: flex; align-items: center; gap: 32px; margin: 16px 0 24px; }}
  .score {{ font-size: 3.5em; font-weight: 900; color: {sc}; line-height: 1; }}
  .grade {{ font-size: 2.5em; font-weight: 900; color: {sc}; line-height: 1; }}
  .score-label {{ font-size: 0.75em; color: #8b949e; margin-top: 2px; }}
  .coverage {{ background: #161b22; border: 1px solid #21262d; border-radius: 8px;
               padding: 12px 16px; margin-bottom: 20px; }}
  .coverage h3 {{ color: #8b949e; font-size: 0.8em; text-transform: uppercase;
                  letter-spacing: 1px; margin: 0 0 8px; }}
  .badge {{ display:inline-block; margin:3px; padding:3px 10px; border-radius:4px;
            font-size:0.78em; background:#0d1117; border:1px solid #21262d; color:#58a6ff; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 8px; }}
  th {{ background: #161b22; color: #8b949e; padding: 10px; text-align: left;
        border-bottom: 1px solid #21262d; font-size: 0.82em; text-transform: uppercase;
        letter-spacing: 0.5px; }}
  td {{ padding: 10px; border-bottom: 1px solid #21262d; vertical-align: top;
        font-size: 0.88em; }}
  tr:hover {{ background: #161b22; }}
  .meta {{ color: #8b949e; font-size: 0.88em; margin-bottom: 8px; }}
  .logo {{ font-size: 1.4em; letter-spacing: 4px; color: #e94560; font-weight: 900; }}
  .evidence {{ font-family: monospace; font-size: 0.82em; color: #8b949e;
               word-break: break-all; }}
  .fail-summary {{ margin-bottom: 20px; }}
</style>
</head>
<body>
<div class="logo">SPAT CLI</div>
<div class="meta">Security Posture Analysis Tool &mdash; Antibody Cyber Technology, LLC</div>
<h1>Scan Report: {hostname}</h1>
<p class="meta">Scanned: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</p>

<div class="score-block">
  <div>
    <div class="score">{score}/100</div>
    <div class="score-label">Security Score</div>
  </div>
  <div>
    <div class="grade">{grade}</div>
    <div class="score-label">Grade</div>
  </div>
</div>

<div class="coverage">
  <h3>Scan Coverage ({len(checks_run)} categories)</h3>
  {''.join(f'<span class="badge">{c}</span>' for c in sorted(checks_run))}
</div>

<div class="fail-summary">
  <h3 style="color:#8b949e;font-size:0.8em;text-transform:uppercase;letter-spacing:1px;margin:0 0 8px">Failures by Category</h3>
  {cat_badges}
</div>

<h2>Findings</h2>
<table>
  <thead>
    <tr>
      <th style="width:36px"></th>
      <th>Finding</th>
      <th>Category</th>
      <th>Severity</th>
      <th>Description</th>
      <th>Remediation</th>
    </tr>
  </thead>
  <tbody>{rows}</tbody>
</table>
<p class="meta" style="margin-top:30px">&copy; 2026 Antibody Cyber Technology, LLC &mdash; https://antibodycyber.com</p>
</body>
</html>"""
    Path(outfile).write_text(html, encoding="utf-8")
    print(f"  {GREEN}✔{RESET} HTML report saved: {outfile}")


# ═══════════════════════════════════════════════════════════════════════════
# VIRUSTOTAL REPUTATION CHECK
# ═══════════════════════════════════════════════════════════════════════════

def check_virustotal(hostname: str) -> list:
    findings = []
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        # Fallback: read from a .env file next to this script
        _env_path = Path(__file__).parent / ".env"
        if _env_path.exists():
            for _line in _env_path.read_text(encoding="utf-8").splitlines():
                _line = _line.strip()
                if _line.startswith("VIRUSTOTAL_API_KEY=") and not _line.startswith("#"):
                    api_key = _line.split("=", 1)[1].strip().strip('"').strip("'")
                    break
    if not api_key:
        return findings  # silently skip if no key configured

    url = f"https://www.virustotal.com/api/v3/domains/{hostname}"
    headers = {"x-apikey": api_key}

    try:
        import urllib.request
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        findings.append({
            "name": "VirusTotal Reputation", "category": "Threat Intelligence",
            "severity": "INFO",
            "description": "VirusTotal lookup could not be completed.",
            "evidence": str(e), "remediation": "",
            "status": "info", "score_impact": 0
        })
        return findings

    attrs    = data.get("data", {}).get("attributes", {})
    stats    = attrs.get("last_analysis_stats", {})
    malicious   = int(stats.get("malicious", 0))
    suspicious  = int(stats.get("suspicious", 0))
    harmless    = int(stats.get("harmless", 0))
    undetected  = int(stats.get("undetected", 0))
    total       = malicious + suspicious + harmless + undetected
    categories  = attrs.get("categories", {})
    reputation  = attrs.get("reputation", 0)
    tags        = attrs.get("tags", [])

    cat_summary = ", ".join(set(categories.values()))[:200] if categories else "N/A"
    tag_summary = ", ".join(tags[:10]) if tags else ""

    # ── Malicious detections ──────────────────────────────────────────────
    if malicious >= 5:
        findings.append({
            "name": f"VirusTotal: Malicious ({malicious}/{total} vendors)",
            "category": "Threat Intelligence",
            "severity": "CRITICAL",
            "description": f"{malicious} of {total} security vendors flagged this domain as malicious.",
            "evidence": f"Malicious: {malicious} | Suspicious: {suspicious} | Harmless: {harmless} | Categories: {cat_summary}",
            "remediation": "Investigate immediately. Domain may be hosting malware, phishing, or C2 infrastructure.",
            "status": "fail", "score_impact": 25
        })
    elif malicious >= 1:
        findings.append({
            "name": f"VirusTotal: Suspicious ({malicious} vendor flag)",
            "category": "Threat Intelligence",
            "severity": "HIGH",
            "description": f"{malicious} security vendor(s) flagged this domain. May be a false positive — review recommended.",
            "evidence": f"Malicious: {malicious} | Suspicious: {suspicious} | Harmless: {harmless} | Categories: {cat_summary}",
            "remediation": "Review the VirusTotal report at https://www.virustotal.com/gui/domain/" + hostname,
            "status": "warn", "score_impact": 10
        })
    elif suspicious >= 3:
        findings.append({
            "name": f"VirusTotal: Potentially Suspicious ({suspicious} vendors)",
            "category": "Threat Intelligence",
            "severity": "MEDIUM",
            "description": f"{suspicious} vendor(s) marked the domain as suspicious.",
            "evidence": f"Malicious: {malicious} | Suspicious: {suspicious} | Harmless: {harmless} | Categories: {cat_summary}",
            "remediation": "Review the VirusTotal report.",
            "status": "warn", "score_impact": 5
        })
    else:
        findings.append({
            "name": "VirusTotal: Clean",
            "category": "Threat Intelligence",
            "severity": "INFO",
            "description": f"No malicious detections. {harmless} vendors marked clean, {malicious} malicious, {suspicious} suspicious.",
            "evidence": f"Reputation score: {reputation} | Categories: {cat_summary}" + (f" | Tags: {tag_summary}" if tag_summary else ""),
            "remediation": "", "status": "pass", "score_impact": 0
        })

    # ── Negative reputation warning ───────────────────────────────────────
    if reputation < -10:
        findings.append({
            "name": f"VirusTotal: Negative Reputation Score ({reputation})",
            "category": "Threat Intelligence",
            "severity": "HIGH",
            "description": f"Community reputation score is {reputation} (negative = distrust). Often indicates historical abuse.",
            "evidence": f"VT reputation: {reputation}",
            "remediation": "Investigate domain history on VirusTotal.",
            "status": "warn", "score_impact": 5
        })

    # ── Phishing / malware category tag ──────────────────────────────────
    bad_cats = [c.lower() for c in categories.values()
                if any(w in c.lower() for w in ("phish", "malware", "spam", "scam", "fraud", "exploit"))]
    if bad_cats:
        findings.append({
            "name": f"VirusTotal: Threat Category — {', '.join(bad_cats[:3])}",
            "category": "Threat Intelligence",
            "severity": "HIGH",
            "description": "One or more vendors categorised this domain under a threat category.",
            "evidence": ", ".join(bad_cats),
            "remediation": "Review domain classification and remediate if owned.",
            "status": "fail", "score_impact": 10
        })

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# MAIN SCAN RUNNER
# ═══════════════════════════════════════════════════════════════════════════

def run_scan(hostname: str, ssh_port: int = 22, skip_ssh: bool = False,
             ssh_only: bool = False) -> list:
    all_findings = []

    checks = []
    if not ssh_only:
        checks += [
            ("DNS",                lambda: check_dns(hostname)),
            ("TLS/SSL Cert",       lambda: check_tls(hostname)),
            ("TLS Protocols",      lambda: check_tls_protocols(hostname)),
            ("TLS Cipher Suites",  lambda: check_tls_ciphers(hostname)),
            ("HTTP Headers",       lambda: check_http_headers(hostname)),
            ("HTTP Redirect",      lambda: check_http_redirect(hostname)),
            ("CSP Analysis",       lambda: check_csp_quality(hostname)),
            ("Cookie Security",    lambda: check_cookie_security(hostname)),
            ("CORS",               lambda: check_cors(hostname)),
            ("Email Security",     lambda: check_email_security(hostname)),
            ("DNSSEC",             lambda: check_dnssec(hostname)),
            ("Port Scan",          lambda: check_ports(hostname)),
            ("robots.txt",         lambda: check_robots(hostname)),
            ("VirusTotal",         lambda: check_virustotal(hostname)),
        ]
    if not skip_ssh:
        checks += [
            ("SSH Algorithms",     lambda: check_ssh(hostname, ssh_port)),
            ("SSH Auth Methods",   lambda: check_ssh_auth(hostname, ssh_port)),
        ]

    total = len(checks)
    for i, (label, fn) in enumerate(checks, 1):
        print(f"  {CYAN}[{i}/{total}]{RESET} Checking {label}...", end="\r", flush=True)
        try:
            results = fn()
            all_findings.extend(results)
        except Exception as e:
            all_findings.append({
                "name": f"{label} Check Error", "category": label,
                "severity": "INFO",
                "description": f"Check failed: {e}",
                "evidence": str(e), "remediation": "",
                "status": "info", "score_impact": 0
            })
        print(" " * 60, end="\r")  # clear line

    return all_findings


# ═══════════════════════════════════════════════════════════════════════════
# CLI ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        prog="spat",
        description="SPAT CLI — Security Posture Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  spat example.com
  spat example.com --ssh-port 2222
  spat example.com --ssh-only
  spat example.com --skip-ssh --json report.json
  spat example.com --html report.html --json report.json
        """
    )
    parser.add_argument("hostname",            help="Target hostname (e.g. example.com)")
    parser.add_argument("--ssh-port",          type=int, default=22, metavar="PORT",
                        help="SSH port to scan (default: 22)")
    parser.add_argument("--skip-ssh",          action="store_true",
                        help="Skip all SSH checks")
    parser.add_argument("--ssh-only",          action="store_true",
                        help="Run SSH checks only")
    parser.add_argument("--json",              metavar="FILE",
                        help="Save JSON report to file")
    parser.add_argument("--html",              metavar="FILE",
                        help="Save HTML report to file")
    parser.add_argument("--quiet", "-q",       action="store_true",
                        help="Only show failures and warnings")
    if len(sys.argv) == 1:
        print(BANNER)
        parser.print_help()
        sys.exit(0)
    args = parser.parse_args()

    # Sanitize hostname
    hostname = re.sub(r"https?://", "", args.hostname).rstrip("/").lower().strip()
    if not re.match(r"^[a-z0-9][a-z0-9.\-]{0,252}[a-z0-9]$", hostname):
        print(f"{RED}Error: Invalid hostname '{hostname}'{RESET}")
        sys.exit(1)

    print(BANNER)
    print(f"  {BOLD}Target:{RESET}  {CYAN}{hostname}{RESET}")
    print(f"  {BOLD}SSH Port:{RESET} {args.ssh_port}")
    print(f"  {BOLD}Started:{RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    findings = run_scan(
        hostname,
        ssh_port=args.ssh_port,
        skip_ssh=args.skip_ssh,
        ssh_only=args.ssh_only
    )
    score = calculate_score(findings)

    # Group by category
    categories = {}
    for f in findings:
        cat = f.get("category", "Other")
        categories.setdefault(cat, []).append(f)

    for cat, items in categories.items():
        print_section(cat)
        for f in items:
            if args.quiet and f.get("status") == "pass":
                continue
            print_finding(f)

    print_score(score)

    fails  = sum(1 for f in findings if f.get("status") == "fail")
    warns  = sum(1 for f in findings if f.get("status") == "warn")
    passes = sum(1 for f in findings if f.get("status") == "pass")
    print(f"\n  {RED}✘ {fails} fail{RESET}  {YELLOW}⚠ {warns} warn{RESET}  {GREEN}✔ {passes} pass{RESET}")
    print()

    if args.json:
        export_json(hostname, findings, score, args.json)
    if args.html:
        export_html(hostname, findings, score, args.html)

    sys.exit(0 if fails == 0 else 1)


if __name__ == "__main__":
    main()
