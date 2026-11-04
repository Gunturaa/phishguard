from io import BytesIO
from typing import Any, Dict

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas


def build_pdf(title: str, result: Dict[str, Any]) -> BytesIO:
    output = BytesIO()
    document = canvas.Canvas(output, pagesize=A4)
    _, height = A4
    y = height - 48

    document.setTitle(title)
    document.setFont("Helvetica-Bold", 16)
    document.drawString(40, y, title)
    y -= 28
    document.setFont("Helvetica", 10)

    lines = [
        f"Target: {result.get('target') or result.get('url', 'Unavailable')}",
        f"Status: {result.get('status') or result.get('final_status', 'Unavailable')}",
        f"Risk score: {result.get('risk_score', 'Unavailable')}",
        f"Findings: {result.get('findings_count', 'Unavailable')}",
        "",
        "This report contains passive checks only. It is not a penetration test.",
    ]
    for line in lines:
        document.drawString(40, y, str(line)[:120])
        y -= 18

    findings = result.get("findings", [])
    if findings:
        y -= 8
        document.setFont("Helvetica-Bold", 11)
        document.drawString(40, y, "Findings")
        y -= 18
        document.setFont("Helvetica", 9)
        for finding in findings[:30]:
            text = f"[{finding.get('severity', 'INFO')}] {finding.get('title', finding.get('rule', 'Finding'))}"
            document.drawString(48, y, text[:115])
            y -= 14
            if y < 50:
                document.showPage()
                y = height - 48
                document.setFont("Helvetica", 9)

    document.save()
    output.seek(0)
    return output
