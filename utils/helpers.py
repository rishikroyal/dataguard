"""
Helper utilities for the Sensitive Data Detection backend.
No Streamlit dependencies.
"""

import io
import json
from datetime import datetime
from typing import List, Dict, Any


def timestamp_now() -> str:
    """Return current timestamp string."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def file_size_str(size_bytes: int) -> str:
    """Human-readable file size."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def detections_to_csv(detections: List[Dict[str, Any]]) -> str:
    """Convert detection dicts to CSV string."""
    import csv
    import io

    if not detections:
        return "No detections found."

    output = io.StringIO()
    fieldnames = ["type", "value", "masked_value", "confidence", "risk", "context", "line_number"]
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
    writer.writeheader()

    for det in detections:
        writer.writerow({
            "type":         det.get("data_type", ""),
            "value":        det.get("value", ""),
            "masked_value": det.get("masked_value", ""),
            "confidence":   f"{det.get('confidence', 0.0):.2%}",
            "risk":         det.get("risk_contribution", ""),
            "context":      det.get("context", "")[:100],
            "line_number":  det.get("line_number", ""),
        })

    return output.getvalue()


def detections_to_json(detections: List[Dict[str, Any]]) -> str:
    """Convert detections to formatted JSON."""
    return json.dumps(detections, indent=2, ensure_ascii=False)


def generate_pdf_report(
    filename: str,
    detections: List[Dict[str, Any]],
    risk_profile: Dict[str, Any],
    summary: str,
) -> bytes:
    """
    Generate a professional PDF compliance report.
    Returns PDF as bytes.
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            HRFlowable
        )

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=2*cm,
            leftMargin=2*cm,
            topMargin=2.5*cm,
            bottomMargin=2*cm,
        )

        styles = getSampleStyleSheet()
        story = []

        # Title
        title_style = ParagraphStyle(
            "CustomTitle",
            parent=styles["Title"],
            fontSize=22,
            spaceAfter=6,
            textColor=colors.HexColor("#111111"),
            fontName="Helvetica-Bold",
        )
        story.append(Paragraph("Sensitive Data Detection Report", title_style))
        story.append(Paragraph(f"Document: <b>{filename}</b>", styles["Normal"]))
        story.append(Paragraph(f"Generated: {timestamp_now()}", styles["Normal"]))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#111111")))
        story.append(Spacer(1, 0.4*cm))

        # Risk summary table
        summary_data = [
            ["Metric", "Value"],
            ["Risk Level", risk_profile.get("overall_risk", "LOW")],
            ["Risk Score", f"{risk_profile.get('risk_score', 0.0):.1f} / 100"],
            ["Total Detections", str(risk_profile.get("total_detections", 0))],
            ["Critical", str(risk_profile.get("critical_count", 0))],
            ["High", str(risk_profile.get("high_count", 0))],
            ["Medium", str(risk_profile.get("medium_count", 0))],
            ["Low", str(risk_profile.get("low_count", 0))],
            ["Document Clearance", risk_profile.get("document_clearance", "")],
        ]

        t = Table(summary_data, colWidths=[8*cm, 8*cm])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#111111")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8F8F8")]),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E8E8E8")),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(t)
        story.append(Spacer(1, 0.5*cm))

        # AI Summary
        story.append(Paragraph("Compliance Summary", styles["Heading2"]))
        # Strip markdown for PDF
        clean_summary = summary.replace("##", "").replace("**", "").replace("*", "").replace("#", "")
        for line in clean_summary.split("\n"):
            if line.strip():
                story.append(Paragraph(line.strip(), styles["Normal"]))
                story.append(Spacer(1, 0.1*cm))

        story.append(Spacer(1, 0.3*cm))

        # Detection table
        if detections:
            story.append(Paragraph("Detection Details", styles["Heading2"]))
            det_data = [["#", "Type", "Masked Value", "Risk", "Confidence"]]
            for i, det in enumerate(detections[:50], 1):
                det_data.append([
                    str(i),
                    det.get("data_type", ""),
                    det.get("masked_value", "")[:30],
                    det.get("risk_contribution", ""),
                    f"{det.get('confidence', 0.0):.0%}",
                ])

            det_table = Table(det_data, colWidths=[1*cm, 5*cm, 5*cm, 3*cm, 2.5*cm])
            det_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#222222")),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8F8F8")]),
                ('GRID', (0, 0), (-1, -1), 0.3, colors.HexColor("#CBD5E1")),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('LEFTPADDING', (0, 0), (-1, -1), 5),
            ]))
            story.append(det_table)

        doc.build(story)
        return buffer.getvalue()
    except Exception as e:
        print(f"PDF generation failed: {e}")
        return b""
