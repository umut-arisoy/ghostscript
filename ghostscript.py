#!/usr/bin/env python3
"""
Ghostscript (CVE-2023-36664)PoC toolkit.

This script intentionally avoids exploit generation and command execution payloads.
It provides safe helpers for:
1) Marker obfuscation
2) Benign payload/profile selection
3) Local listener (127.0.0.1 only)
4) PDF carrier marker embedding
5) Automatic interface/IP detection (reporting only)
"""

import argparse
import base64
import os
import re
import socket
import sys
import threading
from datetime import datetime


RISKY_PATTERNS = [
    r"%pipe%",
    r"\(.*\)\s+\(w\)\s+file",
    r"/DCTDecode\s+filter",
]


def detect_local_ips():
    """Return local interface guesses without external probing."""
    ip_candidates = {"127.0.0.1"}
    hostname = socket.gethostname()
    try:
        for info in socket.getaddrinfo(hostname, None, family=socket.AF_INET):
            ip = info[4][0]
            ip_candidates.add(ip)
    except socket.gaierror:
        pass

    # Fallback trick: no packets are sent, but OS picks a route.
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_candidates.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass

    ips = sorted(ip_candidates)
    preferred = next((ip for ip in ips if ip != "127.0.0.1"), "127.0.0.1")
    return {"hostname": hostname, "preferred_ip": preferred, "all_ipv4": ips}


def obfuscate_marker(marker, mode):
    if mode == "none":
        return marker
    if mode == "base64":
        return base64.b64encode(marker.encode("utf-8")).decode("ascii")
    if mode == "hex":
        return marker.encode("utf-8").hex()
    raise ValueError(f"Unknown obfuscation mode: {mode}")


def build_marker(profile, token):
    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    return f"POC_MARKER::{profile}::{token}::{timestamp}"


def select_profile(profile_name):
    """Benign test profile selector (no shell, no command execution)."""
    profiles = {
        "marker-only": {
            "title": "Safe Marker Profile",
            "description": "Embeds a static marker string into test documents.",
        },
        "telemetry-tag": {
            "title": "Telemetry Tag Profile",
            "description": "Embeds marker plus host/time identifiers for log correlation.",
        },
        "scanner-check": {
            "title": "Scanner Check Profile",
            "description": "Generates content used to verify detection and triage tooling.",
        },
    }
    if profile_name not in profiles:
        raise ValueError(f"Unknown profile: {profile_name}")
    return profiles[profile_name]


def generate_ps_eps_file(filename, extension, marker):
    if extension == "ps":
        content = f"""%!PS
/Times-Roman findfont
18 scalefont
setfont
100 200 moveto
(Defensive PoC Validation File) show
100 170 moveto
({marker}) show
showpage
"""
    elif extension == "eps":
        content = f"""%!PS-Adobe-3.0 EPSF-3.0
%%BoundingBox: 0 0 400 300
%%Title: Defensive PoC EPS
/Times-Roman findfont
18 scalefont
setfont
50 200 moveto
(Defensive PoC Validation File) show
50 170 moveto
({marker}) show
showpage
"""
    else:
        raise ValueError("Extension must be 'ps' or 'eps'.")

    output_name = f"{filename}.{extension}"
    with open(output_name, "w", encoding="utf-8") as file:
        file.write(content)
    return output_name


def inject_marker_into_file(filename, marker):
    if filename.lower().endswith(".eps"):
        with open(filename, "r", encoding="utf-8") as f:
            lines = f.readlines()
        insert_line = f"%%POC-MARKER: {marker}\n"
        for i, line in enumerate(lines):
            if not line.strip().startswith("%"):
                lines.insert(i, insert_line)
                break
        else:
            lines.append(insert_line)
        with open(filename, "w", encoding="utf-8") as f:
            f.writelines(lines)
        return True

    if filename.lower().endswith(".ps"):
        with open(filename, "a", encoding="utf-8") as f:
            f.write(f"\n% POC-MARKER: {marker}\n")
        return True

    if filename.lower().endswith(".pdf"):
        # Safe PDF carrier behavior: append a comment marker.
        with open(filename, "ab") as f:
            f.write(f"\n% POC-MARKER: {marker}\n".encode("utf-8"))
        return True

    return False


def scan_file_for_risky_patterns(filename):
    with open(filename, "r", encoding="utf-8", errors="ignore") as f:
        data = f.read()
    findings = []
    for pattern in RISKY_PATTERNS:
        matches = re.findall(pattern, data, flags=re.IGNORECASE)
        if matches:
            findings.append({"pattern": pattern, "count": len(matches)})
    return findings


def run_local_listener(bind_ip, port, timeout):
    """Local-only listener for PoC callbacks; rejects non-loopback binding."""
    if bind_ip != "127.0.0.1":
        raise ValueError("Listener is restricted to 127.0.0.1 for safety.")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind_ip, port))
    sock.listen(1)
    sock.settimeout(timeout)
    print(f"[+] Local listener started on {bind_ip}:{port} (timeout: {timeout}s)")

    try:
        conn, addr = sock.accept()
        data = conn.recv(2048)
        print(f"[+] Callback from {addr[0]}:{addr[1]} | bytes={len(data)}")
        conn.close()
    except socket.timeout:
        print("[i] Listener timeout reached without callback.")
    finally:
        sock.close()


def parse_args():
    parser = argparse.ArgumentParser(
        description="Defensive Ghostscript PoC auxiliary toolkit (exploit-disabled)."
    )
    parser.add_argument("--profile", choices=["marker-only", "telemetry-tag", "scanner-check"], default="marker-only")
    parser.add_argument("--token", default="DEFAULT")
    parser.add_argument("--obfuscation", choices=["none", "base64", "hex"], default="none")

    parser.add_argument("--generate", action="store_true", help="Generate a safe PS/EPS test file.")
    parser.add_argument("--inject", action="store_true", help="Inject marker into existing PS/EPS/PDF file.")
    parser.add_argument("--scan", action="store_true", help="Scan file for risky Ghostscript patterns.")
    parser.add_argument("--carrier-pdf", action="store_true", help="Enable PDF marker carrier behavior on --inject.")

    parser.add_argument("--extension", choices=["ps", "eps"], help="File extension for generated output.")
    parser.add_argument("--filename", default="poc_safe", help="Target filename or output prefix.")

    parser.add_argument("--detect-net", action="store_true", help="Report local interface/IP detection.")
    parser.add_argument("--listener", action="store_true", help="Run local callback listener (127.0.0.1 only).")
    parser.add_argument("--listen-ip", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=9001)
    parser.add_argument("--listen-timeout", type=int, default=20)
    return parser.parse_args()


def main():
    args = parse_args()
    profile = select_profile(args.profile)
    marker = build_marker(args.profile, args.token)
    marker = obfuscate_marker(marker, args.obfuscation)

    print(f"[i] Selected profile: {profile['title']}")
    print(f"[i] Description: {profile['description']}")

    if args.detect_net:
        net_info = detect_local_ips()
        print(f"[i] Hostname: {net_info['hostname']}")
        print(f"[i] Preferred IPv4: {net_info['preferred_ip']}")
        print(f"[i] All IPv4: {', '.join(net_info['all_ipv4'])}")

    if args.listener:
        t = threading.Thread(
            target=run_local_listener,
            args=(args.listen_ip, args.listen_port, args.listen_timeout),
            daemon=False,
        )
        t.start()
        t.join()

    if args.generate:
        if not args.extension:
            print("[-] --extension is required with --generate.")
            sys.exit(1)
        output = generate_ps_eps_file(args.filename, args.extension, marker)
        print(f"[+] Generated safe file: {output}")

    if args.inject:
        if not os.path.exists(args.filename):
            print(f"[-] File not found: {args.filename}")
            sys.exit(1)
        if args.filename.lower().endswith(".pdf") and not args.carrier_pdf:
            print("[-] PDF injection requires --carrier-pdf flag.")
            sys.exit(1)
        ok = inject_marker_into_file(args.filename, marker)
        if not ok:
            print("[-] Only .ps, .eps, and .pdf are supported for safe marker injection.")
            sys.exit(1)
        print(f"[+] Marker injected into: {args.filename}")

    if args.scan:
        if not os.path.exists(args.filename):
            print(f"[-] File not found: {args.filename}")
            sys.exit(1)
        findings = scan_file_for_risky_patterns(args.filename)
        if not findings:
            print("[+] No risky Ghostscript patterns detected.")
        else:
            print("[!] Risky patterns detected:")
            for item in findings:
                print(f"    - pattern={item['pattern']} count={item['count']}")

    if not any([args.generate, args.inject, args.scan, args.detect_net, args.listener]):
        print("[i] No action requested. Use --help for available modules.")


if __name__ == "__main__":
    main()
