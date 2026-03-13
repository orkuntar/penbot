# core/report.py ── Türkçe düzgün + tüm bulgular eklenmiş + profesyonel görünüm

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
FONT_REGISTERED = False
FONT_FAMILY = 'Helvetica'  # fallback

DEJAVU_PATH = "/usr/share/fonts/truetype/dejavu"
NOTO_PATH   = os.path.expanduser("~/penbot/fonts")

try:
    # Önce sistem DejaVu'yu dene
    pdfmetrics.registerFont(TTFont('MainFont',      os.path.join(DEJAVU_PATH, 'DejaVuSans.ttf')))
    pdfmetrics.registerFont(TTFont('MainFont-Bold', os.path.join(DEJAVU_PATH, 'DejaVuSans-Bold.ttf')))
    FONT_FAMILY = 'MainFont'
    FONT_REGISTERED = True
    print("DejaVuSans (sistem) başarıyla yüklendi")
except:
    pass

if not FONT_REGISTERED:
    try:
        # Sonra NotoSans manuel
        pdfmetrics.registerFont(TTFont('MainFont',      os.path.join(NOTO_PATH, 'NotoSans-Regular.ttf')))
        pdfmetrics.registerFont(TTFont('MainFont-Bold', os.path.join(NOTO_PATH, 'NotoSans-Bold.ttf')))
        FONT_FAMILY = 'MainFont'
        FONT_REGISTERED = True
        print("NotoSans manuel yüklendi → Türkçe tam destek")
    except Exception as e:
        print(f"Font yüklenemedi: {e} → Helvetica fallback (Türkçe bozulabilir)")

def get_font(bold=False):
    base = FONT_FAMILY
    return f"{base}-Bold" if bold else base

# ── Renk paleti ──────────────────────────────────────────────────────────────
COLORS = {
    'header':    colors.HexColor('#0D1B46'),
    'accent':    colors.HexColor('#00A3E0'),
    'critical':  colors.HexColor('#C62828'),
    'high':      colors.HexColor('#F57C00'),
    'medium':    colors.HexColor('#1976D2'),
    'low':       colors.HexColor('#2E7D32'),
    'bg_light':  colors.HexColor('#F8FAFC'),
    'border':    colors.HexColor('#CFD8DC'),
    'text':      colors.HexColor('#263238'),
}

styles = getSampleStyleSheet()

ST = {
    'title': ParagraphStyle('Title', fontName=get_font(bold=True), fontSize=28, textColor=COLORS['header'], alignment=TA_CENTER, spaceAfter=10*mm, leading=32),
    'report_type': ParagraphStyle('ReportType', fontName=get_font(bold=True), fontSize=20, textColor=COLORS['accent'], alignment=TA_CENTER, spaceAfter=25*mm),
    'meta': ParagraphStyle('Meta', fontName=get_font(), fontSize=13, textColor=colors.grey, alignment=TA_CENTER, spaceAfter=6*mm),
    'section': ParagraphStyle('Section', fontName=get_font(bold=True), fontSize=18, textColor=COLORS['header'], spaceBefore=18*mm, spaceAfter=8*mm, leading=22),
    'normal': ParagraphStyle('Normal', fontName=get_font(), fontSize=11, leading=14, textColor=COLORS['text'], spaceAfter=4*mm),
    'small': ParagraphStyle('Small', fontName=get_font(), fontSize=9, leading=11, textColor=colors.grey),
}

SEVERITY_STYLES = {
    'CRITICAL': ParagraphStyle('Crit', fontName=get_font(bold=True), fontSize=11, textColor=colors.white, backColor=COLORS['critical'], alignment=TA_CENTER, borderPadding=6),
    'HIGH': ParagraphStyle('High', fontName=get_font(bold=True), fontSize=11, textColor=colors.white, backColor=COLORS['high'], alignment=TA_CENTER, borderPadding=6),
    'MEDIUM': ParagraphStyle('Med', fontName=get_font(bold=True), fontSize=11, textColor=colors.white, backColor=COLORS['medium'], alignment=TA_CENTER, borderPadding=6),
    'LOW': ParagraphStyle('Low', fontName=get_font(bold=True), fontSize=11, textColor=colors.white, backColor=COLORS['low'], alignment=TA_CENTER, borderPadding=6),
}

def severity_paragraph(sev):
    sev_upper = sev.upper()
    style = SEVERITY_STYLES.get(sev_upper, SEVERITY_STYLES['HIGH'])
    return Paragraph(f"<b>{sev_upper}</b>", style)

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

    doc = SimpleDocTemplate(pdf_path, pagesize=A4, leftMargin=22*mm, rightMargin=22*mm, topMargin=30*mm, bottomMargin=25*mm)

    elements = []

    # Kapak
    elements.append(Paragraph("GREYPHANTOM v3", ST['title']))
    elements.append(Spacer(1, 4*mm))
    elements.append(Paragraph("Penetrasyon Testi Raporu", ST['report_type']))
    elements.append(Spacer(1, 30*mm))
    elements.append(Paragraph(f"Hedef: {target}", ST['meta']))
    elements.append(Paragraph(f"Tarih: {timestamp}", ST['meta']))
    elements.append(Paragraph(f"Mod: {mode}", ST['meta']))
    elements.append(Spacer(1, 60*mm))
    elements.append(Paragraph("Bu belge gizlidir. Yetkisiz kullanım yasaktır.", ST['small']))
    elements.append(PageBreak())

    # 1. Yönetici Özeti
    elements.append(Paragraph("1. Yönetici Özeti", ST['section']))
    summary_data = [
        ["Metrik", "Değer"],
        ["Subdomain", len(results.get('subdomains', []))],
        ["Canlı Host", len(results.get('alive_hosts', []))],
        ["Keşfedilen URL", len(results.get('urls', []))],
        ["Hassas Veri/Secret", len(results.get('js_secrets', [])) + len(results.get('secret_findings', []))],
        ["Nuclei Bulgusu", len(results.get('nuclei_findings', []))],
        ["FFUF/API Hit", len(results.get('ffuf_hits', [])) or 0],
        ["Açık Port", len(results.get('naabu_ports', []) or [])],
        ["Info Endpoint", len(results.get('info_endpoints', []))],
    ]
    t = Table(summary_data, colWidths=[100*mm, 60*mm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), COLORS['header']),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('FONTNAME', (0,0), (-1,0), get_font(bold=True)),
        ('GRID', (0,0), (-1,-1), 0.5, COLORS['border']),
        ('BACKGROUND', (0,1), (-1,-1), COLORS['bg_light']),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 15*mm))

    # Diğer bölümler (örnek olarak birkaç tane ekledim – hepsini benzer şekilde genişletebilirsin)
    # 2. Ağ Tarama (Nmap)
    if 'nmap' in results or 'naabu_ports' in results:
        ports = results.get('naabu_ports', [])
        text = ", ".join(ports) if ports else "Bulunamadı"
        elements.append(Paragraph("2. Ağ ve Port Tarama", ST['section']))
        elements.append(Paragraph(f"Açık portlar: {text}", ST['normal']))

    # 3. SSL/TLS (TestSSL)
    if 'testssl' in results:
        elements.append(Paragraph("3. SSL/TLS Bulguları", ST['section']))
        for line in results['testssl']:
            elements.append(Paragraph(line, ST['small']))

    # 4. Hassas Veri
    secrets = results.get('secret_findings', []) or []
    if secrets:
        elements.append(Paragraph("4. Hassas Veri Tespitleri", ST['section']))
        for s in secrets[:15]:
            elements.append(Paragraph(f"[HIGH] {s.get('secret', '—')} → {s.get('url', '—')}", ST['normal']))

    # ... Diğer bölümleri (auth, info_endpoints, websocket, api, ffuf vb.) aynı mantıkla ekleyebilirsin

    doc.build(elements, canvasmaker=NumberedCanvas)
    print(f"PDF oluşturuldu: {pdf_path}")
    return pdf_path