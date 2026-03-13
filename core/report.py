# core/report.py dosyasındaki build_pdf fonksiyonu (ilgili kısım güncellenmiş hali)

from reportlab.lib import colors
from reportlab.platypus import Paragraph, Table, TableStyle, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.graphics.shapes import Drawing, String
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from datetime import datetime
import json
import os

# ... (diğer import'lar ve sabitler aynı kalabilir)

def safe_hex_color(color_value):
    """
    Her türlü renk string'ini reportlab'ın kabul edeceği #rrggbb formatına çevirir
    """
    if not color_value:
        return "#000000"
    
    # string'e çevir ve küçük harfe getir
    raw = str(color_value).lower().strip()
    
    # başındaki #, 0x, x gibi şeyleri temizle
    cleaned = raw.lstrip('#0x')
    
    # hex karakter kontrolü
    hex_chars = set('0123456789abcdef')
    if len(cleaned) == 6 and all(c in hex_chars for c in cleaned):
        return f"#{cleaned}"
    
    # 3 haneli shorthand (#rgb) → 6 haneye çevir
    if len(cleaned) == 3 and all(c in hex_chars for c in cleaned):
        return f"#{cleaned[0]*2}{cleaned[1]*2}{cleaned[2]*2}"
    
    # geçersiz → güvenli varsayılan renk
    print(f"Uyarı: Geçersiz renk değeri '{raw}' → gri kullanılıyor")
    return "#808080"


def build_pdf(json_path: str) -> str:
    # JSON dosyasını oku
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    meta = data.get("meta", {})
    results = data.get("results", {})

    target = meta.get("target", "Bilinmeyen hedef")
    mode = meta.get("mode", "Bilinmeyen mod")
    timestamp = meta.get("timestamp", datetime.now().isoformat())

    pdf_filename = f"report_{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
    pdf_path = os.path.join(REPORTS_DIR, pdf_filename)

    from reportlab.pdfgen import canvas
    c = canvas.Canvas(pdf_path, pagesize=A4)
    width, height = A4

    styles = getSampleStyleSheet()
    ST = {
        "title": ParagraphStyle('Title', parent=styles['Title'], fontSize=18, spaceAfter=12),
        "heading": ParagraphStyle('Heading2', parent=styles['Heading2'], fontSize=14, spaceAfter=8),
        "normal": styles['Normal'],
        "small": ParagraphStyle('Small', parent=styles['Normal'], fontSize=9),
        "code": ParagraphStyle('Code', parent=styles['Code'], fontSize=10, spaceAfter=4),
        "vuln_low": ParagraphStyle('Low', parent=styles['Normal'], textColor=colors.green, fontName='Helvetica-Bold'),
        "vuln_med": ParagraphStyle('Medium', parent=styles['Normal'], textColor=colors.orange, fontName='Helvetica-Bold'),
        "vuln_high": ParagraphStyle('High', parent=styles['Normal'], textColor=colors.red, fontName='Helvetica-Bold'),
        "vuln_crit": ParagraphStyle('Critical', parent=styles['Normal'], textColor=colors.pink, fontName='Helvetica-Bold'),
        "tc": ParagraphStyle('TableCell', parent=styles['Normal'], alignment=TA_LEFT, fontSize=10),
    }

    # Başlık
    c.setFont("Helvetica-Bold", 20)
    c.drawCentredString(width/2, height - 40*mm, "GREYPHANTOM v3 - Pentest Raporu")
    c.setFont("Helvetica", 12)
    c.drawCentredString(width/2, height - 55*mm, f"Hedef: {target}")
    c.drawCentredString(width/2, height - 65*mm, f"Tarih: {timestamp}")
    c.drawCentredString(width/2, height - 75*mm, f"Mod: {mode}")
    c.showPage()

    y = height - 30*mm

    # ── Özet ────────────────────────────────────────────────────────────────
    c.setFont("Helvetica-Bold", 16)
    c.drawString(20*mm, y, "1. Özet")
    y -= 12*mm

    findings_count = {
        "critical": len(results.get("critical_findings", [])),
        "high": len(results.get("nuclei_findings", [])) + len(results.get("high_severity", [])),
        "medium": len(results.get("medium_severity", [])),
        "low": len(results.get("low_severity", [])),
    }

    summary_text = f"""
    Toplam subdomain: {len(results.get('subdomains', []))}<br/>
    Canlı host: {len(results.get('alive_hosts', []))}<br/>
    Keşfedilen URL: {len(results.get('urls', []))}<br/>
    Bulunan secret: {len(results.get('js_secrets', [])) + len(results.get('secret_findings', []))}<br/>
    Nuclei bulguları: {len(results.get('nuclei_findings', []))}<br/>
    """
    p = Paragraph(summary_text, ST["normal"])
    w, h = p.wrap(width - 40*mm, y - 100*mm)
    p.drawOn(c, 20*mm, y - h)
    y -= (h + 10*mm)

    # ── Vulnerability Tablosu Örneği ────────────────────────────────────────
    c.setFont("Helvetica-Bold", 14)
    c.drawString(20*mm, y, "2. Kritik & Yüksek Bulgular")
    y -= 10*mm

    table_data = [["Seviye", "Açıklama", "URL", "Detay"]]
    for finding in results.get("nuclei_findings", [])[:20]:  # ilk 20 ile sınırlı örnek
        sev = finding.get("info", {}).get("severity", "unknown").upper()
        name = finding.get("info", {}).get("name", "İsimsiz")
        url = finding.get("host", "") + finding.get("matched-at", "")
        
        # RENK DÜZELTME BURADA YAPILIYOR
        color_str = {
            "CRITICAL": "#ff1493",
            "HIGH":     "#ff0000",
            "MEDIUM":   "#ffa500",
            "LOW":      "#008000",
            "INFO":     "#1e90ff",
        }.get(sev, "#808080")
        
        # ya da fg objen varsa:
        # color_str = safe_hex_color(fg)   # ← senin orijinal fg objen varsa

        cell_sev = Paragraph(f'<font color="{color_str}"><b>{sev}</b></font>', ST["tc"])
        
        table_data.append([
            cell_sev,
            Paragraph(name, ST["tc"]),
            Paragraph(url[:80] + "..." if len(url) > 80 else url, ST["small"]),
            Paragraph(finding.get("info", {}).get("description", "")[:120] + "...", ST["small"])
        ])

    if len(table_data) > 1:
        t = Table(table_data, colWidths=[30*mm, 60*mm, 60*mm, 60*mm])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.grey),
            ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 11),
            ('BOTTOMPADDING', (0,0), (-1,0), 12),
            ('GRID', (0,0), (-1,-1), 1, colors.black),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        w, h = t.wrapOn(c, width - 40*mm, 100*mm)
        t.drawOn(c, 20*mm, y - h)
        y -= (h + 15*mm)

    # ... diğer bölümleri aynı şekilde devam ettirebilirsin

    c.save()
    return pdf_path