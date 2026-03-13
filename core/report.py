# core/report.py
from reportlab.lib import colors
from reportlab.platypus import Paragraph, Table, TableStyle, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from datetime import datetime
import json
import os
import re

# ── CONFIG ───────────────────────────────────────────────────────────────
from config import REPORTS_DIR

# Klasör yoksa oluştur
os.makedirs(REPORTS_DIR, exist_ok=True)

def safe_hex_color(color_value):
    """
    Her türlü renk string'ini reportlab'ın kabul edeceği #rrggbb formatına çevirir
    """
    if not color_value:
        return "#000000"
    
    raw = str(color_value).lower().strip()
    cleaned = raw.lstrip('#0x')
    
    hex_chars = set('0123456789abcdef')
    if len(cleaned) == 6 and all(c in hex_chars for c in cleaned):
        return f"#{cleaned}"
    
    if len(cleaned) == 3 and all(c in hex_chars for c in cleaned):
        return f"#{cleaned[0]*2}{cleaned[1]*2}{cleaned[2]*2}"
    
    print(f"Uyarı: Geçersiz renk değeri '{raw}' → gri kullanılıyor")
    return "#808080"


def build_pdf(json_path: str) -> str:
    """
    JSON rapor dosyasından PDF üretir
    """
    # JSON dosyasını oku
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        raise ValueError(f"JSON okuma hatası: {e}")

    meta = data.get("meta", {})
    results = data.get("results", {})

    target = meta.get("target", "Bilinmeyen hedef")
    mode = meta.get("mode", "Bilinmeyen mod")
    timestamp = meta.get("timestamp", datetime.now().isoformat())

    # Güvenli dosya adı oluştur
    safe_target = re.sub(r'[^a-zA-Z0-9_-]', '_', target.strip())
    pdf_filename = f"report_{safe_target}_{datetime.now():%Y%m%d_%H%M}.pdf"
    pdf_path = os.path.join(REPORTS_DIR, pdf_filename)

    # PDF oluşturma
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

    # ── Sayfa 1: Başlık ─────────────────────────────────────────────────────
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
    <b>Toplam subdomain:</b> {len(results.get('subdomains', []))}<br/>
    <b>Canlı host:</b> {len(results.get('alive_hosts', []))}<br/>
    <b>Keşfedilen URL:</b> {len(results.get('urls', []))}<br/>
    <b>Bulunan secret:</b> {len(results.get('js_secrets', [])) + len(results.get('secret_findings', []))}<br/>
    <b>Nuclei bulguları:</b> {len(results.get('nuclei_findings', []))}<br/>
    """
    p = Paragraph(summary_text, ST["normal"])
    w, h = p.wrap(width - 40*mm, height)
    p.drawOn(c, 20*mm, y - h)
    y -= (h + 15*mm)

    # ── Kritik & Yüksek Bulgular Tablosu ────────────────────────────────────
    c.setFont("Helvetica-Bold", 14)
    c.drawString(20*mm, y, "2. Kritik & Yüksek Bulgular")
    y -= 10*mm

    table_data = [["Seviye", "Açıklama", "URL", "Detay"]]

    for finding in results.get("nuclei_findings", [])[:30]:  # ilk 30 ile sınırlı
        info = finding.get("info", {})
        sev = info.get("severity", "unknown").upper()
        name = info.get("name", "İsimsiz")
        url = (finding.get("host", "") + finding.get("matched-at", "")).strip()
        desc = info.get("description", "")[:150] + ("..." if len(info.get("description", "")) > 150 else "")

        color_map = {
            "CRITICAL": "#ff1493",
            "HIGH":     "#ff0000",
            "MEDIUM":   "#ffa500",
            "LOW":      "#008000",
            "INFO":     "#1e90ff",
            "UNKNOWN":  "#808080"
        }
        color_str = color_map.get(sev, "#808080")

        cell_sev = Paragraph(f'<font color="{color_str}"><b>{sev}</b></font>', ST["tc"])

        table_data.append([
            cell_sev,
            Paragraph(name, ST["tc"]),
            Paragraph(url[:80] + "..." if len(url) > 80 else url, ST["small"]),
            Paragraph(desc, ST["small"])
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
            ('BOX', (0,0), (-1,-1), 1, colors.black),
        ]))
        tw, th = t.wrapOn(c, width - 40*mm, y - 50*mm)
        t.drawOn(c, 20*mm, y - th)
        y -= (th + 20*mm)

    # ── Sonlandırma ─────────────────────────────────────────────────────────
    c.showPage()
    c.save()

    print(f"PDF oluşturuldu: {pdf_path}")
    return pdf_path