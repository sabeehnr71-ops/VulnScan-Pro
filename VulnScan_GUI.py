import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import threading

# Import scanners
from scanner.header_scanner import scan_headers
from scanner.port_scanner import scan_ports

# Import report functions
from utils.report_generator import save_json_report, generate_pdf_report


class VulnScannerGUI:

    def __init__(self, root):
        self.root = root
        self.root.title("VulnScan-Pro — Vulnerability Scanner Tool")
        self.root.geometry("900x600")

        self.header_results = {}
        self.port_results = {}

        # URL / IP Input
        tk.Label(root, text="Enter Target URL / IP:", font=("Arial", 12)).pack(pady=5)

        self.url_entry = tk.Entry(root, width=60, font=("Arial", 12))
        self.url_entry.pack(pady=5)

        # Scan Buttons
        tk.Button(root, text="Scan Security Headers", font=("Arial", 12),
                  command=self.run_header_scan).pack(pady=5)

        tk.Button(root, text="Scan Open Ports", font=("Arial", 12),
                  command=self.run_port_scan).pack(pady=5)

        # Results Box
        tk.Label(root, text="Scan Output:", font=("Arial", 12)).pack(pady=5)

        self.output_box = scrolledtext.ScrolledText(root, width=110, height=20, font=("Consolas", 10))
        self.output_box.pack(pady=10)

        # REPORT BUTTON
        tk.Button(root, text="Generate Report", font=("Arial", 12),
                  command=self.generate_report).pack(pady=10)

    # -------------------------------
    # HEADER SCANNER
    # -------------------------------
    def run_header_scan(self):
        threading.Thread(target=self.header_scan_thread).start()

    def header_scan_thread(self):
        target = self.url_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a valid URL!")
            return

        self.output_box.insert(tk.END, f"\n[+] Scanning headers for: {target}\n")
        self.output_box.see(tk.END)

        try:
            self.header_results = scan_headers(target)
            self.output_box.insert(tk.END, f"[✓] Header scan completed.\n\n")
            self.output_box.insert(tk.END, str(self.header_results) + "\n\n")

        except Exception as e:
            self.output_box.insert(tk.END, f"[!] Header scan error: {e}\n\n")

    # -------------------------------
    # PORT SCANNER
    # -------------------------------
    def run_port_scan(self):
        threading.Thread(target=self.port_scan_thread).start()

    def port_scan_thread(self):
        target = self.url_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a valid URL or IP!")
            return

        self.output_box.insert(tk.END, f"\n[+] Scanning ports for: {target}\n")
        self.output_box.see(tk.END)

        try:
            self.port_results = scan_ports(target)
            self.output_box.insert(tk.END, f"[✓] Port scan completed.\n\n")
            self.output_box.insert(tk.END, str(self.port_results) + "\n\n")

        except Exception as e:
            self.output_box.insert(tk.END, f"[!] Port scan error: {e}\n\n")

    # -------------------------------
    # REPORT GENERATION
    # -------------------------------
    def generate_report(self):
        try:
            target = self.url_entry.get().strip()
            if not target:
                messagebox.showerror("Error", "Enter URL/IP before generating report!")
                return

            # Merge results
            results = {
                "headers": self.header_results,
                "ports": self.port_results
            }

            json_file = save_json_report(target, results)
            pdf_file = generate_pdf_report(target, results)

            messagebox.showinfo("Success",
                                f"Report generated!\n\nJSON: {json_file}\nPDF: {pdf_file}")

        except Exception as e:
            messagebox.showerror("Error", f"Report generation failed:\n{e}")


# -------------------------------
# MAIN PROGRAM
# -------------------------------
if __name__ == "__main__":
    root = tk.Tk()
    app = VulnScannerGUI(root)
    root.mainloop()