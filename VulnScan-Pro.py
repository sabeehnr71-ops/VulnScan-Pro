#!/usr/bin/env python3
# VulnScan-Pro – Main Entry File

import sys
import os

# Ensure project root is in path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Imports
from utils.banner import show_banner
from utils.logger import log
from scanner.xss_scanner import scan_xss


def main():
    show_banner()

    print("\n[+] VulnScan-Pro started\n")
    log("VulnScan-Pro started")

    target = input("Enter target URL (example: http://testphp.vulnweb.com): ").strip()

    if not target.startswith("http"):
        print("[-] Invalid URL. Must start with http or https")
        log("Invalid URL entered", "error")
        return

    print("\n[+] Starting XSS Scan...\n")
    log(f"Starting XSS scan on {target}")

    try:
        vulnerabilities = scan_xss(target)

        if vulnerabilities:
            print("\n[!] XSS Vulnerabilities Found:\n")
            for vuln in vulnerabilities:
                print(f" - {vuln}")
                log(f"XSS Found: {vuln}", "warning")
        else:
            print("\n[+] No XSS vulnerabilities found.")
            log("No XSS vulnerabilities found")

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        log("Scan interrupted by user", "warning")

    except Exception as e:
        print(f"\n[-] Error occurred: {e}")
        log(f"Error occurred: {e}", "error")

    print("\n[+] Scan completed")
    log("Scan completed")


if __name__ == "__main__":
    main()