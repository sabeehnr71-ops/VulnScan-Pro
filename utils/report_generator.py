# utils/report_generator.py

import os
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from datetime import datetime
import json

REPORTS_DIR = os.path.join(os.getcwd(), "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)


def save_json_report(target, results):
    fname = os.path.join(REPORTS_DIR, f"vulnscan_{target.replace(':','_')}.json")
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    return fname


def generate_pdf_report(target, results, filename=None):
    if filename is None:
        filename = os.path.join(REPORTS_DIR, f"vulnscan_{target.replace(':','_')}.pdf")

    c = canvas.Canvas(filename, pagesize=letter)
    width, height = letter

    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, height - 50, "Vulnerability Scan Report")

    c.setFont("Helvetica", 12)
    c.drawString(50, height - 80, f"Target: {target}")
    c.drawString(50, height - 100, f"Generated: {datetime.now()}")

    y = height - 150
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "Scan Results:")
    y -= 20

    c.setFont("Helvetica", 12)

    for section, data in results.items():
        c.drawString(50, y, f"- {section.upper()}:")
        y -= 20

        if isinstance(data, dict):
            for key, value in data.items():
                c.drawString(70, y, f"{key}: {value}")
                y -= 20
        elif isinstance(data, list):
            for item in data:
                c.drawString(70, y, f"- {item}")
                y -= 20
        else:
            c.drawString(70, y, str(data))
            y -= 20

        y -= 10

    c.save()
    return filename