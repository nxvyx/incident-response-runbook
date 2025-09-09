"""
report_generator.py
Generates CSV and a polished PDF executive report from enriched alerts DataFrame.
Improved table wrapping using Paragraphs and dynamic column widths.
"""

import pandas as pd
import matplotlib.pyplot as plt
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
import io
from datetime import datetime


def save_csv(df: pd.DataFrame, path: str):
    df.to_csv(path, index=False)
    print(f"[+] CSV saved -> {path}")


def create_classification_chart(df, chart_type="bar"):
    """Generate a chart (bar or pie) and return it as a BytesIO image."""
    counts = df["classification"].value_counts()

    fig, ax = plt.subplots(figsize=(5, 3))
    # color mapping: ensure consistent ordering
    categories = ["Malware", "Phishing", "Benign"]
    values = [counts.get(cat, 0) for cat in categories]
    colors_plot = ["#E57373", "#FFB74D", "#81C784"]  # red, orange, salmon, green

    ax.bar(categories, values, color=colors_plot)
    ax.set_title("Incident Classification Breakdown")
    ax.set_ylabel("Count")
    plt.xticks(rotation=0)
    plt.tight_layout()
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format="png")
    plt.close(fig)
    img_buffer.seek(0)
    return img_buffer


def create_pdf_report(df, pdf_path: str):
    # Page/margins
    left_margin = right_margin = top_margin = bottom_margin = 40
    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=A4,
        leftMargin=left_margin,
        rightMargin=right_margin,
        topMargin=top_margin,
        bottomMargin=bottom_margin,
    )
    elements = []
    styles = getSampleStyleSheet()

    # Custom paragraph styles for table cells
    header_style = ParagraphStyle(
        "tbl_header",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=11,
        alignment=0,
    )
    cell_style = ParagraphStyle(
        "tbl_cell",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=10,
        alignment=0,
    )
    small_italic = ParagraphStyle(
        "small_italic",
        parent=styles["Normal"],
        fontName="Helvetica-Oblique",
        fontSize=8,
        leading=10,
        alignment=0,
    )

    # Title
    title = Paragraph("<b>SOC Incident Report</b>", styles["Title"])
    elements.append(title)
    elements.append(Spacer(1, 8))

    # Generated timestamp
    ts = Paragraph(f"<i>Generated: {datetime.utcnow().isoformat()} UTC</i>", small_italic)
    elements.append(ts)
    elements.append(Spacer(1, 12))

    # Executive summary
    total_alerts = len(df)
    malware_count = int((df["classification"] == "Malware").sum()) if "classification" in df.columns else 0
    phishing_count = int((df["classification"] == "Phishing").sum()) if "classification" in df.columns else 0
    benign_count = int((df["classification"] == "Benign").sum()) if "classification" in df.columns else 0
    suspicious_ip_count = int((df["classification"] == "Suspicious-IP").sum()) if "classification" in df.columns else 0

    summary_text = (
        f"<b>Executive Summary:</b><br/>"
        f"Total Alerts: {total_alerts}<br/>"
        f"Malware: {malware_count} &nbsp;&nbsp; "
        f"Phishing: {phishing_count} &nbsp;&nbsp; "
        f"Suspicious IP: {suspicious_ip_count} &nbsp;&nbsp; "
        f"Benign: {benign_count}"
    )
    elements.append(Paragraph(summary_text, styles["Normal"]))
    elements.append(Spacer(1, 14))

    # Add chart
    chart_img = create_classification_chart(df, chart_type="bar")
    elements.append(Image(chart_img, width=420, height=240))
    elements.append(Spacer(1, 16))

    # Table of top incidents
    elements.append(Paragraph("<b>Top Incidents</b>", styles["Heading2"]))
    elements.append(Spacer(1, 6))

    # Build table data as Paragraphs for wrapping
    header = ["Alert ID", "Timestamp", "Source IP", "Destination IP", "URL", "Classification", "Recommended Action"]
    table_rows = []
    table_rows.append([Paragraph(h, header_style) for h in header])

    # Use top N rows for PDF display (keeps it readable). Use head(10) by default.
    topn = df.head(10)
    for _, row in topn.iterrows():
        row_cells = [
            Paragraph(str(row.get("alert_id", "")), cell_style),
            Paragraph(str(row.get("timestamp", "")), cell_style),
            Paragraph(str(row.get("src_ip", "")), cell_style),
            Paragraph(str(row.get("dst_ip", "")), cell_style),
            Paragraph(str(row.get("url", "")), cell_style),
            Paragraph(str(row.get("classification", "")), cell_style),
            Paragraph(str(row.get("recommended_action", "")), cell_style),
        ]
        table_rows.append(row_cells)

    # Compute dynamic column widths based on available page width
    page_width = A4[0]
    usable_width = page_width - left_margin - right_margin

    # Relative weights for columns (sums to 1.0)
    weights = [0.05, 0.18, 0.12, 0.12, 0.35, 0.08, 0.20]
    col_widths = [w * usable_width for w in weights]

    # Create table
    table = Table(table_rows, colWidths=col_widths, repeatRows=1)

    # Table style: compact, top-aligned, word-wrapped via Paragraphs
    style = TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
    ])

    # Color rows based on classification (iterate data rows)
    for i, data_row in enumerate(table_rows[1:], start=1):
        # classification is in column index 5
        try:
            classification_para = data_row[5]  # Paragraph object
            classification_text = classification_para.getPlainText().strip()
        except Exception:
            classification_text = ""

        if classification_text == "Malware":
            style.add("BACKGROUND", (0, i), (-1, i), colors.HexColor("#FADBD8"))  # light red
        elif classification_text == "Phishing":
            style.add("BACKGROUND", (0, i), (-1, i), colors.HexColor("#FFF3CD"))  # light yellow
        elif classification_text == "Benign":
            style.add("BACKGROUND", (0, i), (-1, i), colors.HexColor("#E8F8F5"))  # light green
        elif classification_text == "Suspicious-IP":
            style.add("BACKGROUND", (0, i), (-1, i), colors.HexColor("#FFE6CC"))  # light orange

    table.setStyle(style)
    elements.append(table)
    elements.append(Spacer(1, 12))

    # Footer note
    footer = Paragraph("<i>Automated SOC Runbook Report – Confidential</i>", small_italic)
    elements.append(footer)

    # Build PDF
    doc.build(elements)
    print(f"[+] PDF report created -> {pdf_path}")
