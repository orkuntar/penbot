# core/report.py
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Table, TableStyle, Spacer, PageBreak,
    KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from datetime import datetime
import json
import os
import re

from config import REPORTS_DIR

# ── Font kayıtları ───────────────────────────────────────────────────────────
# Ubuntu/Debian sistem font yolunu tercih ediyoruz
DEJAVU_PATH = "/usr/share/fonts/truetype/dejavu"

FONTS_LOADED = False

try:
    pdfmetrics.registerFont(TTFont('DejaVuSans', os.path.join(DEJAVU_PATH, 'DejaVuSans.ttf')))
    pdfmetrics.registerFont(TTFont('DejaVuSans-Bold', os.path.join(DEJAVU_PATH, 'DejaVuSans-Bold.ttf')))
    FONTS_LOADED = True
    print("DejaVuSans fontları sistemden başarıyla yüklendi")
except Exception as e:
    print(f"DejaVuSans yüklenemedi: {e}")
    print("Helvetica fallback kullanılacak → Türkçe karakterlerde sorun çıkabilir")

# ── Renk paleti ──────────────────────────────────────────────────────────────
COLORS = {
    'primary':   colors.HexColor('#0F2B5B'),    # koyu mavi
    'accent':    colors.HexColor('#00A0DF'),    # parlak mavi
    'danger':    colors.HexColor('#D32F2F'),
    'warning':   colors.HexColor('#F57C00'),
    'success':   colors.HexColor('#388E3C'),
    'info':      colors.HexColor('#1976D2'),
    'light_bg':  colors.HexColor('#F8FAFC'),
    'border':    colors.HexColor('#E2E8F0'),
    'text':      colors.HexColor('#1E293B'),
}

# ── Stil tanımları ───────────────────────────────────────────────────────────
styles = getSampleStyleSheet()

ST = {
    'title': ParagraphStyle(
        name='Title',
        fontName='DejaVuSans-Bold' if FONTS_LOADED else 'Helvetica-Bold',
        fontSize=26,
        textColor=COLORS['primary'],
        alignment=TA_CENTER,
        spaceAfter=8*mm,
        leading=30
    ),
    'subtitle': ParagraphStyle(
        name='Subtitle',
        fontName='DejaVuSans' if FONTS_LOADED else 'Helvetica',
        fontSize=14,
        textColor=colors.gray,
        alignment=TA_CENTER,
        spaceAfter=20*mm
    ),
    'section': ParagraphStyle(
        name='Section',
        fontName='DejaVuSans-Bold' if FONTS_LOADED else 'Helvetica-Bold',
        fontSize=18,
        textColor=COLORS['primary'],
        spaceBefore=20*mm,
        spaceAfter=10*mm,
        leading=22
    ),
    'normal': ParagraphStyle(
        name='Normal',
        fontName='DejaVuSans' if FONTS_LOADED else 'Helvetica',
        fontSize=11,
        leading=14,
        textColor=COLORS['text'],
        spaceAfter=5*mm
    ),
    'small': ParagraphStyle(
        name='Small',
        fontName='DejaVuSans' if FONTS_LOADED else 'Helvetica',
        fontSize=9,
        leading=11,
        textColor=colors.gray
    ),
    'severity_crit': ParagraphStyle('Crit', fontName='DejaVuSans-Bold' if FONTS_LOADED else 'Helvetica-Bold', textColor=colors.white, backColor=COLORS['danger'], fontSize=11, alignment=TA_CENTER, spaceAfter=2*mm, spaceBefore=2*mm, borderPadding=4),
    'severity_high': ParagraphStyle('High', fontName='DejaVuSans-Bold' if FONTS_LOADED else 'Helvetica-Bold', textColor=colors.white, backColor=COLORS['warning'], fontSize=11, alignment=TA_CENTER, spaceAfter=2*mm, spaceBefore=2*mm, borderPadding=4),
    'severity_med':  ParagraphStyle('Med',  fontName='DejaVuSans-Bold' if FONTS_LOADED else 'Helvetica-Bold', textColor=colors.white, backColor=COLORS['info'],   fontSize=11, alignment=TA_CENTER, spaceAfter=2*mm, spaceBefore=2*mm, borderPadding=4),
    'severity_low':  ParagraphStyle('Low',  fontName='DejaVuSans-Bold' if FONTS_LOADED else 'Helvetica-Bold', textColor=colors.white, backColor=COLORS['success'], fontSize=11, alignment=TA_CENTER, spaceAfter=2*mm, spaceBefore=2*mm, borderPadding=4),
}

def severity_badge(sev: str) -> Paragraph:
    sev = sev.upper()
    if sev == "CRITICAL": return Paragraph(f"<b>{sev}</b>", ST['severity_crit'])
    if sev == "HIGH":     return Paragraph(f"<b>{sev}</b>", ST['severity_high'])
    if sev == "MEDIUM":   return Paragraph(f"<b>{sev}</b>", ST['severity_med'])
    return Paragraph(f"<b>{sev}</b>", ST['severity_low'])

class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        canvas.Canvas.__init__(self, *args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.setFont("DejaVuSans" if FONTS_LOADED else "Helvetica", 9)
            self.setFillColor(colors.gray)
            self.drawRightString(self._pagesize[0] - 20*mm, 12*mm, f"Sayfa {self.getPageNumber()} / {num_pages}")
            self.drawString(20*mm, 12*mm, "GREYPHANTOM v3 • Gizli / Confidential")
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

def build_pdf(json_path: str) -> str:
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        raise ValueError(f"JSON okuma hatası: {e}")

    meta = data.get("meta", {})
    results = data.get("results", {})

    target    = meta.get("target", "Bilinmeyen Hedef")
    mode      = meta.get("mode", "Bilinmeyen").title()
    timestamp = meta.get("timestamp", datetime.now().isoformat())[:19].replace("T", " ")

    safe_target = re.sub(r'[^a-zA-Z0-9_-]', '_', target.strip())
    pdf_filename = f"GreyPhantom_Rapor_{safe_target}_{datetime.now():%Y%m%d_%H%M}.pdf"
    pdf_path = os.path.join(REPORTS_DIR, pdf_filename)

    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=A4,
        rightMargin=20*mm,
        leftMargin=20*mm,
        topMargin=25*mm,
        bottomMargin=20*mm,
    )

    elements = []

    # ── Kapak sayfası ────────────────────────────────────────────────────────
    elements.append(Paragraph("GREYPHANTOM v3", ST['title']))
    elements.append(Spacer(1, 4*mm))
    elements.append(Paragraph("Penetrasyon Testi Raporu", ST['title']))
    elements.append(Spacer(1, 10*mm))
    elements.append(Paragraph(f"Hedef: {target}", ST['subtitle']))
    elements.append(Paragraph(f"Tarih: {timestamp}", ST['subtitle']))
    elements.append(Paragraph(f"Mod: {mode}", ST['subtitle']))
    elements.append(Spacer(1, 50*mm))
    elements.append(Paragraph("Bu rapor gizlidir. Yetkisiz erişim ve kullanım yasaktır.", ST['small']))
    elements.append(PageBreak())

    # ── Yönetici Özeti ───────────────────────────────────────────────────────
    elements.append(Paragraph("1. Yönetici Özeti", ST['section']))

    summary_data = [
        ["Metrik", "Değer"],
        ["Toplam Subdomain", len(results.get('subdomains', []))],
        ["Canlı Host", len(results.get('alive_hosts', []))],
        ["Keşfedilen URL", len(results.get('urls', []))],
        ["Bulunan Secret", len(results.get('js_secrets', [])) + len(results.get('secret_findings', []))],
        ["Nuclei Bulguları", len(results.get('nuclei_findings', []))],
    ]

    summary_table = Table(summary_data, colWidths=[90*mm, 70*mm])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), COLORS['primary']),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('FONTNAME', (0,0), (-1,0), 'DejaVuSans-Bold' if FONTS_LOADED else 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,0), 12),
        ('BOTTOMPADDING', (0,0), (-1,0), 10),
        ('BACKGROUND', (0,1), (-1,-1), COLORS['light_bg']),
        ('GRID', (0,0), (-1,-1), 0.5, COLORS['border']),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))

    elements.append(summary_table)
    elements.append(Spacer(1, 15*mm))

    # ── Bulgular Tablosu ─────────────────────────────────────────────────────
    elements.append(Paragraph("2. Tespit Edilen Bulgular", ST['section']))

    table_data = [["Seviye", "Başlık", "URL", "Açıklama"]]

    for finding in results.get("nuclei_findings", [])[:40]:
        info = finding.get("info", {})
        sev = info.get("severity", "unknown")
        name = info.get("name", "—")
        url_raw = (finding.get("host", "") + finding.get("matched-at", "")).strip()
        url = url_raw[:100] + "..." if len(url_raw) > 100 else url_raw
        desc = info.get("description", "—")[:180] + "..." if len(info.get("description", "")) > 180 else info.get("description", "—")

        table_data.append([
            severity_badge(sev),
            Paragraph(name, ST['normal']),
            Paragraph(url, ST['small']),
            Paragraph(desc, ST['small'])
        ])

    if len(table_data) > 1:
        findings_table = Table(table_data, colWidths=[28*mm, 55*mm, 55*mm, 55*mm])
        findings_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), COLORS['primary']),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (0,0), 'CENTER'),
            ('ALIGN', (1,0), (-1,-1), 'LEFT'),
            ('FONTNAME', (0,0), (-1,0), 'DejaVuSans-Bold' if FONTS_LOADED else 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,0), 11),
            ('BOTTOMPADDING', (0,0), (-1,0), 10),
            ('GRID', (0,0), (-1,-1), 0.5, COLORS['border']),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, COLORS['light_bg']]),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ]))
        elements.append(KeepTogether(findings_table))
    else:
        elements.append(Paragraph("Bu taramada herhangi bir yüksek/kritik seviye bulgu tespit edilmedi.", ST['normal']))

    # ── PDF'i oluştur ve kaydet ───────────────────────────────────────────────
    doc.build(elements, canvasmaker=NumberedCanvas)

    print(f"PDF oluşturuldu: {pdf_path}")
    return pdf_path