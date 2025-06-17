from fpdf import FPDF
import os
from datetime import datetime

class PDFReport(FPDF):
    def header(self):
        self.set_font("Arial", "B", 16)
        self.cell(0, 10, "Rapport de Scan Réseau", ln=True, align="C")
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font("Arial", "I", 8)
        self.cell(0, 10, f"Page {self.page_no()}", align="C")

    def add_scan_results(self, title, results):
        self.set_font("Arial", "B", 12)
        self.cell(0, 10, title, ln=True)
        self.set_font("Arial", "", 10)
        self.multi_cell(0, 10, results)
        self.ln(5)

def generate_pdf_report(scan_results, output_path="scan_report.pdf"):
    pdf = PDFReport()
    pdf.add_page()

    for tool, result in scan_results.items():
        pdf.add_scan_results(tool, result)

    pdf.output(output_path)
    return output_path
