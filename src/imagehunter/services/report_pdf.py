"""Optional compact PDF export for an ImageHunter scan summary."""
from __future__ import annotations
from pathlib import Path

def write_pdf(summary: dict, destination: str | Path) -> str:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
    except ImportError as exc:
        raise RuntimeError("PDF export requires optional dependency reportlab") from exc
    path=Path(destination); path.parent.mkdir(parents=True,exist_ok=True)
    styles=getSampleStyleSheet(); story=[]
    esc=lambda v: str(v).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
    story += [Paragraph("CipherSight Forensic Investigation Report",styles["Title"]),Spacer(1,12)]
    inp=summary.get("input",{})
    rows=[["Field","Value"],["Input",esc(inp.get("path",""))],["SHA-256",esc(inp.get("sha256",""))],["Size",esc(inp.get("size",""))],["Status",esc(summary.get("status",""))],["Scan ID",esc(summary.get("scan_id",""))]]
    table=Table(rows,colWidths=[90,420]); table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#26364a")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),.4,colors.grey),("VALIGN",(0,0),(-1,-1),"TOP")])); story.append(table)
    story += [Spacer(1,14),Paragraph("Findings",styles["Heading1"])]
    for f in summary.get("findings",[]):
        ev=f.get("evidence",{}); detail=esc(f.get("description",""))
        if ev.get("text"): detail += "<br/><b>Evidence:</b> "+esc(ev.get("text"))
        story.append(KeepTogether([Paragraph(f"<b>{esc(f.get('id',''))} — {esc(f.get('kind',''))}</b> ({esc(f.get('confidence_label',''))})",styles["Heading3"]),Paragraph(detail,styles["BodyText"]),Spacer(1,6)]))
    story.append(Paragraph("Warnings and limitations",styles["Heading1"]))
    for warning in summary.get("warnings",[]): story.append(Paragraph("• "+esc(warning),styles["BodyText"]))
    SimpleDocTemplate(str(path),pagesize=A4,rightMargin=36,leftMargin=36,topMargin=36,bottomMargin=36).build(story)
    return str(path)
