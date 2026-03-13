# core/report.py
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Table, TableStyle, Spacer, PageBreak,
    Frame, KeepTogether, Flowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.graphics.shapes import Drawing, Rect, String
from datetime import datetime
import json
import os
import re

from config import REPORTS_DIR

# ── Font kayıtları (DejaVuSans kullanacağız - Türkçe tam destek) ──────────────
FONT_PATH = "/home/ork/penbot/fonts"  # kendi yolunu kontrol et
pdfmetrics.registerFont(TTFont('DejaVuSans', os.path.join(FONT_PATH, 'DejaVuSans.ttf')))
pdfmetrics.registerFont(TTFont('DejaVuSans-Bold', os.path.join(FONT_PATH, 'DejaVuSans-Bold.ttf')))

# ── Renk paleti (modern cyber theme) ────────────────────────────────────────
COLORS = {
    'primary': colors.HexColor('#0F2B5B'),      # koyu mavi - başlık
    'accent': colors.HexColor('#00A0DF'),       # parlak mavi - vurgu
    'danger': colors.HexColor('#D32F2F'),       # kritik
    'warning': colors.HexColor('#F57C00'),      # yüksek
    'info': colors.HexColor('#1976D2'),
    'success': colors.HexColor('#388E3C'),
    'light_bg': colors.HexColor('#F8FAFC'),
    'border': colors.HexColor('#E2E8F0'),
    'text': colors.HexColor('#1E293B'),
}

# ── Stil tanımları ───────────────────────────────────────────────────────────
styles = getSampleStyleSheet()
ST = {
    'title': ParagraphStyle(
        name='Title',
        fontName='DejaVuSans-Bold',
        fontSize=24,
        textColor=COLORS['primary'],
        spaceAfter=6*mm,
        alignment=TA_CENTER,
        leading=28
    ),
    'subtitle': ParagraphStyle(
        name='Subtitle',
        fontName='DejaVuSans',
        fontSize=14,
        textColor=colors.gray,
        alignment=TA_CENTER,
        spaceAfter=20*mm
    ),
    'section': ParagraphStyle(
        name='Section',
        fontName='DejaVuSans-Bold',
        fontSize=16,
        textColor=COLORS['primary'],
        spaceBefore=18*mm,
        spaceAfter=8*mm,
        leading=20
    ),
    'subsection': ParagraphStyle(
        name='Subsection',
        fontName='DejaVuSans-Bold',
        fontSize=13,
        textColor=COLORS['text'],
        spaceBefore=12*mm,
        spaceAfter=6*mm
    ),
    'normal': ParagraphStyle(
        name='Normal',
        fontName='DejaVuSans',
        fontSize=11,
        leading=14,
        textColor=COLORS['text'],
        spaceAfter=4*mm
    ),
    'small': ParagraphStyle(
        name='Small',
        fontName='DejaVuSans',
        fontSize=9,
        leading=11,
        textColor=colors.gray
    ),
    'severity_crit': ParagraphStyle('Crit', fontName='DejaVuSans-Bold', textColor=COLORS['danger'], fontSize=11, alignment=TA_CENTER),
    'severity_high': ParagraphStyle('High', fontName='DejaVuSans-Bold', textColor=COLORS['warning'], fontSize=11, alignment=TA_CENTER),
    'severity_med': ParagraphStyle('Med',  fontName='DejaVuSans-Bold', textColor=COLORS['info'], fontSize=11, alignment=TA_CENTER),
    'severity_low': ParagraphStyle('Low',  fontName='DejaVuSans-Bold', textColor=COLORS['success'], fontSize=11, alignment=TA_CENTER),
}

class NumberedCanvas(canvas.Canvas):
    """Sayfa numarası ve footer ekler"""
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
            self.setFont("DejaVuSans", 9)
            self.setFillColor(colors.gray)
            self.drawRightString(self._pagesize[0]-20*mm, 12*mm, f"Sayfa {self.getPageNumber()} / {num_pages}")
            self.drawString(20*mm, 12*mm, "GREYPHANTOM v3 • Gizli / Confidential")
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

def severity_badge(sev: str) -> Paragraph:
    """Severity için renkli badge"""
    sev_upper = sev.upper()
    if sev_upper == "CRITICAL": style = ST['severity_crit']; bg = COLORS['danger']
    elif sev_upper == "HIGH":     style = ST['severity_high']; bg = COLORS['warning']
    elif sev_upper == "MEDIUM":   style = ST['severity_med'];  bg = COLORS['info']
    else:                         style = ST['severity_low'];  bg = COLORS['success']
    
    return Paragraph(f'<font color="white"><b>{sev_upper}</b></font>', style)

def build_pdf(json_path: str) -> str:
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        raise ValueError(f"JSON okuma hatası: {e}")

    meta = data.get("meta", {})
    results = data.get("results", {})

    target = meta.get("target", "Bilinmeyen Hedef")
    mode = meta.get("mode", "Bilinmeyen").title()
    timestamp = meta.get("timestamp", datetime.now().isoformat())[:19].replace("T", " ")

    safe_target = re.sub(r'[^a-zA-Z0-9_-]', '_', target)
    pdf_filename = f"GreyPhantom_Report_{safe_target}_{datetime.now():%Y%m%d_%H%M}.pdf"
    pdf_path = os.path.join(REPORTS_DIR, pdf_filename)

    # ── Doküman ───────────────────────────────────────────────────────────────
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
    elements.append(Paragraph("Penetrasyon Testi Raporu", ST['title']))
    elements.append(Spacer(1, 8*mm))
    elements.append(Paragraph(f"Hedef: {target}", ST['subtitle']))
    elements.append(Paragraph(f"Tarih: {timestamp}", ST['subtitle']))
    elements.append(Paragraph(f"Mod: {mode}", ST['subtitle']))
    elements.append(Spacer(1, 40*mm))
    elements.append(Paragraph("Gizli / Özel – Yetkisiz erişim yasaktır", ST['small']))
    elements.append(PageBreak())

    # ── Özet bölümü ──────────────────────────────────────────────────────────
    elements.append(Paragraph("1. Yönetici Özeti", ST['section']))

    summary_data = [
        ["Metrik", "Değer"],
        ["Toplam Subdomain", str(len(results.get('subdomains', [])))],
        ["Canlı Host", str(len(results.get('alive_hosts', [])))],
        ["Keşfedilen URL", str(len(results.get('urls', [])))],
        ["Bulunan Secret", str(len(results.get('js_secrets', [])) + len(results.get('secret_findings', [])))],
        ["Nuclei Bulguları", str(len(results.get('nuclei_findings', [])))],
    ]

    summary_table = Table(summary_data, colWidths=[80*mm, 80*mm])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), COLORS['primary']),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('FONTNAME', (0,0), (-1,0), 'DejaVuSans-Bold'),
        ('FONTSIZE', (0,0), (-1,0), 12),
        ('BOTTOMPADDING', (0,0), (-1,0), 10),
        ('BACKGROUND', (0,1), (-1,-1), COLORS['light_bg']),
        ('GRID', (0,0), (-1,-1), 0.5, COLORS['border']),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))

    elements.append(summary_table)
    elements.append(Spacer(1, 15*mm))

    # ── Bulgular bölümü ──────────────────────────────────────────────────────
    elements.append(Paragraph("2. Bulgular", ST['section']))

    table_data = [["Seviye", "Başlık", "URL", "Açıklama"]]
    for finding in results.get("nuclei_findings", [])[:30]:
        info = finding.get("info", {})
        sev = info.get("severity", "unknown")
        name = info.get("name", "—")
        url = (finding.get("host", "") + finding.get("matched-at", ""))[:90] + ("..." if len(finding.get("host", "") + finding.get("matched-at", "")) > 90 else "")
        desc = info.get("description", "")[:160] + ("..." if len(info.get("description", "")) > 160 else "")

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
            ('FONTNAME', (0,0), (-1,0), 'DejaVuSans-Bold'),
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
        elements.append(Paragraph("Bu taramada kritik/yüksek seviye bulgu tespit edilmedi.", ST['normal']))

    # ── Son sayfalar için boşluk bırakabilirsin (metodoloji, öneriler vs. eklemek istersen) ──

    doc.build(elements, canvasmaker=NumberedCanvas)
    print(f"PDF oluşturuldu: {pdf_path}")
    return pdf_path