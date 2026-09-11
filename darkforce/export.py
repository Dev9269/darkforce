import csv
import io
import json

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle


def to_csv(records):
    if not records:
        return ""
    fields = []
    for r in records:
        for k in r:
            if k not in fields:
                fields.append(k)
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    w.writeheader()
    for r in records:
        w.writerow({k: ("" if v is None else str(v)) for k, v in r.items()})
    return buf.getvalue()


def to_json(records):
    return json.dumps(records, indent=2, default=str)


def to_pdf(records, title="Dark Force report"):
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4)
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Title"], fontSize=18)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=12)
    body = ParagraphStyle("b", parent=styles["BodyText"], fontSize=8)
    flow = [Paragraph(title, h1), Spacer(1, 8)]

    def esc(x):
        x = "" if x is None else str(x)
        return x.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    if records:
        cols = list(records[0].keys())
        data = [[esc(c) for c in cols]]
        for r in records:
            data.append([esc(r.get(c)) for c in cols])
        t = Table(data, repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        flow.append(t)
    doc.build(flow)
    return buf.getvalue()


def export(results, fmt, title="Dark Force export"):
    if fmt == "csv":
        return to_csv(results).encode("utf-8"), "text/csv", "export.csv"
    if fmt == "json":
        return to_json(results).encode("utf-8"), "application/json", "export.json"
    if fmt == "pdf":
        return to_pdf(results, title), "application/pdf", "export.pdf"
    raise ValueError(fmt)