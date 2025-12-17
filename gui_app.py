import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading

from scanner.xss_scanner import scan_xss
from utils.banner import show_banner


class VulnScanApp:
    def __init__(self, root):
        self.root = root
        self.root.title("VulnScan-Pro | Advanced Vulnerability Scanner")
        self.root.geometry("800x550")
        self.root.resizable(False, False)

        self.build_ui()

    def build_ui(self):
        # Title
        title = tk.Label(
            self.root,
            text="VulnScan-Pro",
            font=("Consolas", 20, "bold")
        )
        title.pack(pady=10)

        subtitle = tk.Label(
            self.root,
            text="Advanced Web Vulnerability Scanner",
            font=("Consolas", 11)
        )
        subtitle.pack()

        # URL input
        frame = tk.Frame(self.root)
        frame.pack(pady=15)

        tk.Label(frame, text="Target URL:", font=("Consolas", 11)).grid(row=0, column=0, padx=5)
        self.url_entry = tk.Entry(frame, width=55, font=("Consolas", 11))
        self.url_entry.grid(row=0, column=1, padx=5)

        # Scan button
        self.scan_btn = tk.Button(
            self.root,
            text="Start Scan",
            width=20,
            font=("Consolas", 11, "bold"),
            command=self.start_scan
        )
        self.scan_btn.pack(pady=10)

        # Output area
        self.output = scrolledtext.ScrolledText(
            self.root,
            width=95,
            height=18,
            font=("Consolas", 10)
        )
        self.output.pack(padx=10, pady=10)

        self.log("[+] VulnScan-Pro ready\n")

    def log(self, message):
        self.output.insert(tk.END, message)
        self.output.see(tk.END)

    def start_scan(self):
        url = self.url_entry.get().strip()

        if not url.startswith("http"):
            messagebox.showerror("Invalid URL", "URL must start with http or https")
            return

        self.output.delete(1.0, tk.END)
        self.log("[+] Starting scan...\n")

        self.scan_btn.config(state=tk.DISABLED)

        thread = threading.Thread(target=self.run_scan, args=(url,))
        thread.start()

    def run_scan(self, url):
        try:
            self.log(f"[+] Target: {url}\n\n")
            results = scan_xss(url)

            if not results:
                self.log("[✓] No XSS vulnerabilities found\n")
            else:
                self.log("[!] XSS Vulnerabilities Found:\n")
                for res in results:
                    self.log(f"    → {res}\n")

            self.log("\n[+] Scan completed successfully\n")

        except Exception as e:
            self.log(f"\n[-] Error occurred: {e}\n")

        finally:
            self.scan_btn.config(state=tk.NORMAL)


if __name__ == "__main__":
    root = tk.Tk()
    app = VulnScanApp(root)
    root.mainloop()