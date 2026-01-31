from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

def export_pdf(results: list[dict], out_path: str = "ioc_report.pdf"):
    c = canvas.Canvas(out_path, pagesize=letter)
    width, height = letter

    y = height - 50
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "IOC Reputation Report (VirusTotal)")
    y -= 30

    c.setFont("Helvetica", 10)
    for r in results:
        line = f"{r.get('ioc_defanged')} | {r.get('type')} | {r['verdict']['verdict']} | score={r['verdict']['score']}"
        c.drawString(50, y, line[:120])
        y -= 15
        if y < 50:
            c.showPage()
            y = height - 50
            c.setFont("Helvetica", 10)

    c.save()
