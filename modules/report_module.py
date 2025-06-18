from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle,
    Paragraph, Spacer, PageBreak
)
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from datetime import datetime
import os

def generate_pdf_report(scan_results, output_path="static/scan_report.pdf"):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    doc = SimpleDocTemplate(output_path, pagesize=A4)
    elements = []

    styles = getSampleStyleSheet()
    title_style = styles['Title']
    header_style = styles['Heading2']
    normal_style = styles['BodyText']
    small_style = ParagraphStyle("small", parent=normal_style, fontSize=8)

    # Titre principal
    date_now = datetime.now().strftime("%d/%m/%Y à %H:%M")
    elements.append(Paragraph("Rapport d’Audit de Sécurité Réseau", title_style))
    elements.append(Paragraph(f"Généré le : {date_now}", small_style))
    elements.append(Spacer(1, 20))

    if not scan_results:
        elements.append(Paragraph("Aucun scan disponible.", normal_style))
    else:
        for module, result in scan_results.items():
            # Nom du module
            elements.append(Paragraph(f"🛠️ Module : {module}", header_style))
            elements.append(Spacer(1, 8))

            # Détails du scan
            rows = []
            for i, line in enumerate(result.split('\n')):
                line = line.strip()
                if line:
                    rows.append([str(i + 1), line])

            if not rows:
                rows.append(["-", "Aucun résultat."])

            # Tableau avec styles
            table = Table([["#", "Résultat"]] + rows, colWidths=[30, 450])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
                ('GRID', (0, 0), (-1, -1), 0.25, colors.grey),
            ]))

            elements.append(table)
            elements.append(Spacer(1, 20))
            elements.append(PageBreak())

    doc.build(elements)
