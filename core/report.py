# core/report.py  ── TÜRKÇE KARAKTER SORUNUNU ÇÖZEN + PROFESYONEL TASARIM ──

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

# ── Fontlar ────────────────────────────────────────────────────────────────
DEJAVU_PATH = "/usr/share/fonts/truetype/dejavu"

FONT_REGISTERED = False

try:
    pdfmetrics.registerFont(TTFont('DejaVuSans',      os.path.join(DEJAVU_PATH, 'DejaVuSans.ttf')))
    pdfmetrics.registerFont(TTFont('DejaVuSans-Bold', os.path.join(DEJAVU_PATH, 'DejaVuSans-Bold.ttf')))
    FONT_REGISTERED = True
    print("DejaVuSans başarıyla kaydedildi → Türkçe destek aktif")
except Exception as e:
    print(f"DejaVuSans kaydedilemedi: {e} → Helvetica fallback")
    print("Not: Eğer Türkçe karakterler hâlâ bozuluyorsa sistemde fonts-dejavu-extra kurulu olmalı")

# ── Renk paleti ────────────────────────────────────────────────────────────
COLORS = {
    'header':    colors.HexColor('#0D1B46'),      # koyu lacivert
    'accent':    colors.HexColor('#00A3E0'),      # mavi vurgu
    'critical':  colors.HexColor('#C62828'),
    'high':      colors.HexColor('#F57C00'),
    'medium':    colors.HexColor('#1976D2'),
    'low':       colors.HexColor('#2E7D32'),
    'bg_light':  colors.HexColor('#F8FAFC'),
    'border':    colors.HexColor('#CFD8DC'),
    'text':      colors.HexColor('#263238'),
}

# ── Stil tanımları ─────────────────────────────────────────────────────────
styles = getSampleStyleSheet()

def get_font(bold=False):
    if FONT_REGISTERED:
        return 'DejaVuSans-Bold' if bold else 'DejaVuSans'
    return 'Helvetica-Bold' if bold else 'Helvetica'

ST = {
    'title': ParagraphStyle(
        'Title', fontName=get_font(bold=True), fontSize=28,
        textColor=COLORS['header'], alignment=TA_CENTER,
        spaceAfter=10*mm, leading=32
    ),
    'report_type': ParagraphStyle(
        'ReportType', fontName=get_font(bold=True), fontSize=20,
        textColor=COLORS['accent'], alignment=TA_CENTER,
        spaceAfter=25*mm
    ),
    'meta': ParagraphStyle(
        'Meta', fontName=get_font(), fontSize=13,
        textColor=colors.grey, alignment=TA_CENTER,
        spaceAfter=6*mm
    ),
    'section': ParagraphStyle(
        'Section', fontName=get_font(bold=True), fontSize=18,
        textColor=COLORS['header'], spaceBefore=18*mm, spaceAfter=8*mm,
        leading=22
    ),
    'normal': ParagraphStyle(
        'Normal', fontName=get_font(), fontSize=11,
        leading=14, textColor=COLORS['text'], spaceAfter=4*mm
    ),
    'small': ParagraphStyle(
        'Small', fontName=get_font(), fontSize=9,
        leading=11, textColor=colors.grey
    ),
}

# Severity badge stilleri
SEVERITY_STYLES = {
    'CRITICAL': ParagraphStyle('Crit', fontName=get_font(bold=True), fontSize=11,
                               textColor=colors.white, backColor=COLORS['critical'],
                               alignment=TA_CENTER, borderPadding=6, borderRadius=4),
    'HIGH': ParagraphStyle('High', fontName=get_font(bold=True), fontSize=11,
                           textColor=colors.white, backColor=COLORS['high'],
                           alignment=TA_CENTER, borderPadding=6, borderRadius=4),
    'MEDIUM': ParagraphStyle('Med', fontName=get_font(bold=True), fontSize=11,
                             textColor=colors.white, backColor=COLORS['medium'],
                             alignment=TA_CENTER, borderPadding=6, borderRadius=4),
    'LOW': ParagraphStyle('Low', fontName=get_font(bold=True), fontSize=11,
                          textColor=colors.white, backColor=COLORS['low'],
                          alignment=TA_CENTER, borderPadding=6, borderRadius=4),
    'UNKNOWN': ParagraphStyle('Unk', fontName=get_font(bold=True), fontSize=11,
                              textColor=colors.white, backColor=colors.grey,
                              alignment=TA_CENTER, borderPadding=6, borderRadius=4),
}

def severity_paragraph(sev):
    sev_upper = sev.upper()
    style = SEVERITY_STYLES.get(sev_upper, SEVERITY_STYLES['UNKNOWN'])
    return Paragraph(f"<b>{sev_upper}</b>", style)

# ── Footer için canvas ─────────────────────────────────────────────────────
class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.setFont(get_font(), 9)
            self.setFillColor(colors.grey)
            self.drawString(20*mm, 10*mm, "GREYPHANTOM v3 • Gizli / Confidential")
            self.drawRightString(A4[0] - 20*mm, 10*mm, f"Sayfa {self.getPageNumber()} / {num_pages}")
            super().showPage()
        super().save()

# ── PDF oluşturma fonksiyonu ───────────────────────────────────────────────
def build_pdf(json_path: str) -> str:
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    meta = data.get("meta", {})
    results = data.get("results", {})

    target = meta.get("target", "Bilinmeyen Hedef")
    mode = meta.get("mode", "Bilinmeyen").title()
    timestamp = meta.get("timestamp", datetime.now().isoformat())[:19].replace("T", " ")

    safe_target = re.sub(r'[^a-zA-Z0-9_-]', '_', target)
    pdf_filename = f"GreyPhantom_Rapor_{safe_target}_{datetime.now():%Y%m%d_%H%M}.pdf"
    pdf_path = os.path.join(REPORTS_DIR, pdf_filename)

    doc = SimpleDocTemplate(
        pdf_path, pagesize=A4,
        leftMargin=22*mm, rightMargin=22*mm,
        topMargin=30*mm, bottomMargin=25*mm
    )

    elements = []

    # ── Kapak Sayfası ──────────────────────────────────────────────────────
    elements.append(Paragraph("GREYPHANTOM v3", ST['title']))
    elements.append(Spacer(1, 4*mm))
    elements.append(Paragraph("Penetrasyon Testi Raporu", ST['report_type']))
    elements.append(Spacer(1, 30*mm))

    for line in [f"Hedef: {target}", f"Tarih: {timestamp}", f"Mod: {mode}"]:
        elements.append(Paragraph(line, ST['meta']))

    elements.append(Spacer(1, 60*mm))
    elements.append(Paragraph("Bu belge gizlidir. Yetkisiz kullanım ve dağıtım yasaktır.", ST['small']))
    elements.append(PageBreak())

    # ── Yönetici Özeti ─────────────────────────────────────────────────────
    elements.append(Paragraph("1. Yönetici Özeti", ST['section']))

    summary_data = [
        ["Metrik", "Değer"],
        ["Toplam Subdomain", str(len(results.get('subdomains', [])))],
        ["Canlı Host", str(len(results.get('alive_hosts', [])))],
        ["Keşfedilen URL", str(len(results.get('urls', [])))],
        ["Bulunan Secret", str(len(results.get('js_secrets', [])) + len(results.get('secret_findings', [])))],
        ["Nuclei Bulguları", str(len(results.get('nuclei_findings', [])))],
    ]

    summary_table = Table(summary_data, colWidths=[100*mm, 60*mm])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), COLORS['header']),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('FONTNAME', (0,0), (-1,0), get_font(bold=True)),
        ('FONTSIZE', (0,0), (-1,0), 12),
        ('BOTTOMPADDING', (0,0), (-1,0), 10),
        ('BACKGROUND', (0,1), (-1,-1), COLORS['bg_light']),
        ('GRID', (0,0), (-1,-1), 0.8, COLORS['border']),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('LEFTPADDING', (0,0), (-1,-1), 12),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 18*mm))

    # ── Bulgular Tablosu ───────────────────────────────────────────────────
    elements.append(Paragraph("2. Tespit Edilen Bulgular", ST['section']))

    findings_data = [["Seviye", "Başlık", "URL", "Açıklama"]]

    for item in results.get("nuclei_findings", [])[:30]:
        info = item.get("info", {})
        sev = info.get("severity", "unknown")
        title = info.get("name", "—")
        url = (item.get("host", "") + item.get("matched-at", ""))[:110]
        if len(url) > 110: url = url[:107] + "..."
        desc = info.get("description", "—")[:220]
        if len(desc) > 220: desc = desc[:217] + "..."

        findings_data.append([
            severity_paragraph(sev),
            Paragraph(title, ST['normal']),
            Paragraph(url, ST['small']),
            Paragraph(desc, ST['small'])
        ])

    if len(findings_data) > 1:
        findings_table = Table(findings_data, colWidths=[30*mm, 55*mm, 55*mm, 55*mm])
        findings_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), COLORS['header']),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (0,0), 'CENTER'),
            ('ALIGN', (1,0), (-1,-1), 'LEFT'),
            ('FONTNAME', (0,0), (-1,0), get_font(bold=True)),
            ('FONTSIZE', (0,0), (-1,0), 11),
            ('BOTTOMPADDING', (0,0), (-1,0), 10),
            ('GRID', (0,0), (-1,-1), 0.6, COLORS['border']),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('BACKGROUND', (0,1), (-1,-1), COLORS['bg_light']),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, COLORS['bg_light']]),
            ('LEFTPADDING', (0,0), (-1,-1), 10),
            ('RIGHTPADDING', (0,0), (-1,-1), 10),
        ]))
        elements.append(KeepTogether(findings_table))
    else:
        elements.append(Paragraph("Henüz yüksek önem dereceli bulgu tespit edilmemiştir.", ST['normal']))

    # ── PDF oluştur ─────────────────────────────────────────────────────────
    doc.build(elements, canvasmaker=NumberedCanvas)

    print(f"PDF oluşturuldu: {pdf_path}")
    return pdf_path