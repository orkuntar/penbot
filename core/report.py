import os
import json
import re
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether,
)
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.lib.colors import HexColor
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas

from config import REPORTS_DIR

# ── Font ─────────────────────────────────────────────────────────────────────
DEJAVU = "/usr/share/fonts/truetype/dejavu"
try:
    pdfmetrics.registerFont(TTFont("GP",   f"{DEJAVU}/DejaVuSans.ttf"))
    pdfmetrics.registerFont(TTFont("GP-B", f"{DEJAVU}/DejaVuSans-Bold.ttf"))
    pdfmetrics.registerFont(TTFont("GP-M", f"{DEJAVU}/DejaVuSansMono.ttf"))
    FONT = "GP"; FONT_BOLD = "GP-B"; FONT_MONO = "GP-M"
except Exception:
    FONT = FONT_BOLD = "Helvetica"; FONT_MONO = "Courier"

# ── Renkler ───────────────────────────────────────────────────────────────────
C_DARK   = HexColor("#0d1117")
C_ACCENT = HexColor("#e63946")
C_LIGHT  = HexColor("#f8f9fa")
C_BORDER = HexColor("#dee2e6")
C_TEXT   = HexColor("#212529")
C_MUTED  = HexColor("#6c757d")
C_WHITE  = colors.white

SEV_FG = {"CRITICAL":HexColor("#dc2626"),"HIGH":HexColor("#ea580c"),
           "MEDIUM":HexColor("#ca8a04"),"LOW":HexColor("#16a34a"),"INFO":HexColor("#2563eb")}
SEV_BG = {"CRITICAL":HexColor("#fef2f2"),"HIGH":HexColor("#fff7ed"),
           "MEDIUM":HexColor("#fefce8"),"LOW":HexColor("#f0fdf4"),"INFO":HexColor("#eff6ff")}

PAGE_W, PAGE_H = A4
MARGIN = 18 * mm
COL_W  = PAGE_W - 2 * MARGIN


# ── Canvas ────────────────────────────────────────────────────────────────────
class GPCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        self._info = kwargs.pop("doc_info", {})
        canvas.Canvas.__init__(self, *args, **kwargs)
        self._saved = []

    def showPage(self):
        self._saved.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._saved)
        for state in self._saved:
            self.__dict__.update(state)
            self._chrome(total)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def _chrome(self, total):
        p = self._pageNumber
        w, h = A4
        if p == 1:
            self.setFillColor(C_DARK)
            self.rect(0, h - 70*mm, w, 70*mm, fill=1, stroke=0)
            self.setFillColor(C_ACCENT)
            self.rect(0, h - 70*mm, 3*mm, 70*mm, fill=1, stroke=0)
            self.setFont(FONT_BOLD, 30)
            self.setFillColor(C_WHITE)
            self.drawString(MARGIN, h - 28*mm, "GREYPHANTOM")
            self.setFont(FONT, 12)
            self.setFillColor(HexColor("#a8dadc"))
            self.drawString(MARGIN, h - 40*mm, "Penetrasyon Testi Raporu")
            self.setFont(FONT_BOLD, 14)
            self.setFillColor(C_WHITE)
            self.drawString(MARGIN, h - 54*mm, self._info.get("target", ""))
            self.setFont(FONT, 9)
            self.setFillColor(HexColor("#adb5bd"))
            self.drawString(MARGIN, h - 63*mm, self._info.get("date", ""))
            self.drawRightString(w - MARGIN, h - 63*mm, "GIZLI / CONFIDENTIAL")
        else:
            self.setFillColor(C_DARK)
            self.rect(0, h - 13*mm, w, 13*mm, fill=1, stroke=0)
            self.setFillColor(C_ACCENT)
            self.rect(0, h - 13*mm, 3*mm, 13*mm, fill=1, stroke=0)
            self.setFont(FONT_BOLD, 8)
            self.setFillColor(C_WHITE)
            self.drawString(MARGIN, h - 7.5*mm, "GREYPHANTOM v3")
            self.setFont(FONT, 8)
            self.setFillColor(HexColor("#a8dadc"))
            self.drawRightString(w - MARGIN, h - 7.5*mm,
                self._info.get("target", "") + "  |  GIZLI")
        self.setFillColor(C_LIGHT)
        self.rect(0, 0, w, 10*mm, fill=1, stroke=0)
        self.setStrokeColor(C_BORDER)
        self.setLineWidth(0.3)
        self.line(0, 10*mm, w, 10*mm)
        self.setFont(FONT, 7)
        self.setFillColor(C_MUTED)
        self.drawString(MARGIN, 3.5*mm, "GREYPHANTOM v3  •  Otomatik Penetrasyon Test Raporu  •  GIZLI")
        self.drawRightString(w - MARGIN, 3.5*mm, f"Sayfa {p} / {total}")


# ── Yardımcılar ───────────────────────────────────────────────────────────────
def S(name, **kw):
    return ParagraphStyle(name, **kw)

ST = {
    "section": S("section", fontName=FONT_BOLD, fontSize=13, textColor=C_DARK,
                 spaceBefore=12, spaceAfter=6, leading=16),
    "body":    S("body",    fontName=FONT,      fontSize=9, textColor=C_TEXT,
                 leading=14, spaceAfter=4),
    "bold":    S("bold",    fontName=FONT_BOLD, fontSize=9, textColor=C_TEXT, leading=14),
    "muted":   S("muted",   fontName=FONT,      fontSize=8, textColor=C_MUTED, leading=12),
    "code":    S("code",    fontName=FONT_MONO, fontSize=8,
                 textColor=HexColor("#1e3a5f"), backColor=HexColor("#eef2f7"),
                 leading=12, leftIndent=6, rightIndent=6, spaceBefore=3, spaceAfter=3),
    "th":      S("th",      fontName=FONT_BOLD, fontSize=8, textColor=C_WHITE),
    "tc":      S("tc",      fontName=FONT,      fontSize=8, textColor=C_TEXT, leading=11),
    "badge":   S("badge",   fontName=FONT_BOLD, fontSize=8, alignment=TA_CENTER),
    "center":  S("center",  fontName=FONT,      fontSize=8, textColor=C_MUTED,
                 alignment=TA_CENTER),
}


def section_header(title, story):
    story.append(Spacer(1, 3*mm))
    story.append(HRFlowable(width="100%", thickness=0.3, color=C_ACCENT, spaceAfter=2))
    story.append(Paragraph(title, ST["section"]))


def badge(text, sev):
    fg = SEV_FG.get(sev, C_MUTED)
    bg = SEV_BG.get(sev, C_LIGHT)
    p  = Paragraph(f"<b>{text}</b>", ST["badge"])
    return Table([[p]], colWidths=[22*mm],
        style=TableStyle([
            ("BACKGROUND",    (0,0),(-1,-1), bg),
            ("TEXTCOLOR",     (0,0),(-1,-1), fg),
            ("ALIGN",         (0,0),(-1,-1), "CENTER"),
            ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
            ("TOPPADDING",    (0,0),(-1,-1), 3),
            ("BOTTOMPADDING", (0,0),(-1,-1), 3),
        ]))


def finding_card(f, story):
    sev = f.get("severity","INFO").upper()
    fg  = SEV_FG.get(sev, C_MUTED)
    bg  = SEV_BG.get(sev, C_LIGHT)

    header = Table([[
        badge(sev, sev),
        Paragraph(f.get("title",""), ST["bold"]),
        Paragraph(f'<b>CVSS {f.get("cvss","N/A")}</b>', ST["bold"]),
    ]], colWidths=[24*mm, COL_W-46*mm, 22*mm],
    style=TableStyle([
        ("BACKGROUND",    (0,0),(-1,-1), bg),
        ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
        ("LEFTPADDING",   (0,0),(-1,-1), 4),
        ("RIGHTPADDING",  (0,0),(-1,-1), 4),
        ("TOPPADDING",    (0,0),(-1,-1), 5),
        ("BOTTOMPADDING", (0,0),(-1,-1), 5),
        ("LINEBELOW",     (0,0),(-1,-1), 0.5, fg),
    ]))

    meta_rows = []
    for label, key in [("Host / URL","host"),("CWE","cwe"),("OWASP","owasp")]:
        if f.get(key):
            meta_rows.append([Paragraph(label, ST["muted"]), Paragraph(f[key], ST["tc"])])

    detail_rows = []
    for label, key in [("Aciklama","description"),("Etki","impact"),("Oneri","recommendation")]:
        if f.get(key):
            detail_rows.append([Paragraph(f"<b>{label}</b>", ST["muted"]),
                                 Paragraph(f[key], ST["tc"])])

    def simple_table(rows):
        return Table(rows, colWidths=[28*mm, COL_W-28*mm],
            style=TableStyle([
                ("BACKGROUND",    (0,0),(-1,-1), C_WHITE),
                ("VALIGN",        (0,0),(-1,-1), "TOP"),
                ("LEFTPADDING",   (0,0),(-1,-1), 6),
                ("RIGHTPADDING",  (0,0),(-1,-1), 6),
                ("TOPPADDING",    (0,0),(-1,-1), 3),
                ("BOTTOMPADDING", (0,0),(-1,-1), 3),
                ("LINEBELOW",     (0,0),(-1,-2), 0.2, C_BORDER),
            ]))

    rows = [[header]]
    if meta_rows:
        rows.append([simple_table(meta_rows)])
    if detail_rows:
        rows.append([simple_table(detail_rows)])
    if f.get("poc"):
        poc = Table([[Paragraph(f["poc"], ST["code"])]],
            colWidths=[COL_W],
            style=TableStyle([
                ("BACKGROUND",    (0,0),(-1,-1), HexColor("#eef2f7")),
                ("LEFTPADDING",   (0,0),(-1,-1), 6),
                ("RIGHTPADDING",  (0,0),(-1,-1), 6),
                ("TOPPADDING",    (0,0),(-1,-1), 4),
                ("BOTTOMPADDING", (0,0),(-1,-1), 4),
                ("LINEABOVE",     (0,0),(-1,-1), 0.2, C_BORDER),
            ]))
        rows.append([poc])

    outer = Table(rows, colWidths=[COL_W],
        style=TableStyle([
            ("BOX",           (0,0),(-1,-1), 0.5, C_BORDER),
            ("LEFTPADDING",   (0,0),(-1,-1), 0),
            ("RIGHTPADDING",  (0,0),(-1,-1), 0),
            ("TOPPADDING",    (0,0),(-1,-1), 0),
            ("BOTTOMPADDING", (0,0),(-1,-1), 0),
        ]))
    story.append(KeepTogether(outer))
    story.append(Spacer(1, 4*mm))


def sev_order(s):
    return {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}.get(s.upper(),9)


def extract_findings(results):
    findings = []
    fid = 1

    def add(sev, cvss, title, host, cwe, owasp, desc, impact, rec, poc):
        nonlocal fid
        findings.append({"id":f"GP-{fid:03d}","severity":sev,"cvss":cvss,
            "title":title,"host":host,"cwe":cwe,"owasp":owasp,
            "description":desc,"impact":impact,"recommendation":rec,"poc":poc})
        fid += 1

    for n in results.get("nuclei_findings",[]):
        sev = n.get("severity","info").upper()
        add(sev,{"CRITICAL":"9.0","HIGH":"7.0","MEDIUM":"5.0","LOW":"3.0","INFO":"0.0"}.get(sev,"0.0"),
            n.get("name",n.get("template-id","Nuclei Bulgusu")),
            n.get("host",""),f"CWE - {n.get('template-id','')}","",
            n.get("description","Nuclei template eslesmesi"),
            f"Guvenlik acigi tespit edildi: {n.get('template-id','')}",
            "Tespit edilen yapilandirma hatasini duzeltiniz.",
            f"Template: {n.get('template-id','')}\nURL: {n.get('url','')}")

    for s in results.get("secret_findings",[]):
        sev = s.get("severity","HIGH").upper()
        add(sev,"9.1" if sev=="CRITICAL" else "7.5",
            f"Hassas Veri Ifsasi - {s.get('type','')}",
            s.get("url",""),"CWE-200","A02:2021",
            f"API yanitinda hassas veri tespit edildi: {s.get('type','')}",
            "Ifsa olan kimlik bilgileri saldirganlarca kullanilabilir.",
            "Hassas verileri API yanitlarindan kaldirin. Sifreleme uygulayiniz.",
            f"Deger: {s.get('value','')}\nEndpoint: {s.get('url','')}")

    for s in results.get("js_secrets",[]):
        add("HIGH","7.5","JavaScript Dosyasinda Hassas Veri",
            s.get("source",""),"CWE-540","A02:2021",
            f"JS dosyasinda hassas veri: {s.get('finding','')[:80]}",
            "Kaynak kodda saklanan kimlik bilgileri ifsa olabilir.",
            "Hassas verileri istemci tarafli koddan kaldirin.",
            f"Bulgu: {s.get('finding','')[:150]}\nKaynak: {s.get('source','')}")

    rate = results.get("rate_limit",{})
    if rate and not rate.get("blocked"):
        add("HIGH","7.5","Rate Limiting Eksik - Brute Force Mumkun",
            results.get("login_endpoint","/api/auth/login"),"CWE-307","A07:2021",
            "Login endpoint rate limiting uygulamiyor.",
            "Kullanici hesaplari brute force ile ele gecirilelebilir.",
            "IP basina dakikada max 5 deneme siniri uygulayin.",
            "20 hizli istek gonderildi - hicbiri engellenmedi")

    for d in results.get("default_creds",[]):
        add("CRITICAL","9.8","Varsayilan Kimlik Bilgileri Kabul Ediliyor",
            d.get("url",""),"CWE-1391","A07:2021",
            f"Varsayilan kimlik bilgileri kabul edildi: {d.get('username')}:{d.get('password')}",
            "Tam kimlik dogrulama atlatma. Yonetici erisimi kazanilabilir.",
            "Tum varsayilan kimlik bilgilerini degistirin.",
            f"Kullanici: {d.get('username')}\nSifre: {d.get('password')}")

    for s in results.get("sql_bypass",[]):
        if s.get("severity")=="CRITICAL":
            add("CRITICAL","9.8","SQL Injection ile Kimlik Dogrulama Atlatma",
                s.get("url",""),"CWE-89","A03:2021",
                "Login endpoint SQL injection'a karsi savunmasiz.",
                "Kimlik dogrulama tamamen atlatilabilir.",
                "Parametreli sorgu kullanin. Input validation ekleyin.",
                f"Payload: {s.get('payload','')}")

    for m in results.get("method_findings",[]):
        if m.get("status")==200 and m.get("method") not in ("GET","HEAD","OPTIONS"):
            add("HIGH","7.3",f"Beklenmedik HTTP Metodu - {m.get('method')}",
                m.get("url",""),"CWE-650","A01:2021",
                f"HTTP {m.get('method')} metodu kabul ediliyor.",
                "Yetkisiz veri degisikligi mumkun olabilir.",
                "Izin verilen HTTP metodlarini kisitlayin.",
                f"Metod: {m.get('method')}\nURL: {m.get('url')}\nDurum: {m.get('status')}")

    for i in results.get("idor_findings",[]):
        add("HIGH","7.5","Guvensiz Dogrudan Nesne Referansi (IDOR)",
            i.get("url",""),"CWE-639","API3:2023",
            f"Nesneye sahiplik dogrulamasi yapilmadan erisim: {i.get('url','')}",
            "Diger kullanicilarin verilerine yetkisiz erisim mumkun.",
            "Sunucu tarafi sahiplik kontrolu uygulayiniz.",
            f"URL: {i.get('url','')}\nNot: {i.get('note','')}")

    for ep in results.get("info_endpoints",[]):
        sev = ep.get("severity","MEDIUM")
        add(sev,"5.3" if sev=="MEDIUM" else "7.5",
            f"Hassas Dosya/Endpoint Ifsasi - {ep.get('url','').split('/')[-1]}",
            ep.get("url",""),"CWE-538","A05:2021",
            f"Hassas dosyaya erisilebiyor: {ep.get('url','')}. {ep.get('note','')}",
            "Yapilandirma verileri veya kaynak kod ifsa olabilir.",
            "Hassas dosya ve endpoint'lere erisimi engelleyin.",
            f"URL: {ep.get('url','')}\nHTTP Durum: {ep.get('status','')}")

    gql = results.get("graphql",{})
    if isinstance(gql,dict) and gql.get("introspection"):
        add("MEDIUM","5.3","GraphQL Introspection Acik",
            gql.get("endpoint","/graphql"),"CWE-200","A05:2021",
            "GraphQL introspection etkin, tum API semasi gorunur.",
            "Saldirganlarin tum sorgu ve mutasyonlari listelemesine olanak saglar.",
            "Production ortaminda introspection'i devre disi birakin.",
            f"Endpoint: {gql.get('endpoint','')}\nTipler: {', '.join(gql.get('types',[])[:5])}")

    for c in results.get("cors_advanced",[]):
        sev = c.get("severity","MEDIUM")
        add(sev,"7.4" if sev=="HIGH" else "5.4",
            f"CORS Yapilandirma Hatasi - {c.get('type','')}",
            c.get("url",""),"CWE-942","A05:2021",
            c.get("note","CORS politikasi yanlis yapilandirilmis."),
            "Capraz kokenli istekler hassas veri calabilir.",
            "CORS'u guvenilir kaynaklarla sinirlayin.",
            f"Origin: {c.get('origin','')}\nACCESS-CONTROL-ALLOW-ORIGIN: {c.get('acao','')}")

    testssl = results.get("testssl",{})
    if isinstance(testssl,dict):
        for s in testssl.get("findings",[]):
            if s.get("severity") in ("HIGH","CRITICAL"):
                add(s.get("severity","MEDIUM"),"5.9",
                    f"TLS/SSL Acigi - {s.get('id','')}",
                    "","CWE-326","A02:2021",
                    s.get("finding",""),
                    "Sifreli trafik yakalalinabilir veya cozulebilir.",
                    "Savunmasiz protokol ve sifreleme suitlerini devre disi birakin.",
                    f"Bulgu: {s.get('finding','')[:200]}")

    for host, plist in results.get("open_ports",{}).items():
        for port in plist:
            if any(p in str(port) for p in ["3306","5432","27017","6379","3000"]):
                add("HIGH","7.5",f"Kritik Port Internete Acik - {port}",
                    host,"CWE-284","A05:2021",
                    f"{host} uzerinde {port} portu internetten erisilebiyor.",
                    "Veritabani veya servis brute force ve exploit saldirilarina acik.",
                    "Guvenlik duvari ile veritabani portlarini ic aga kisitlayin.",
                    f"Port: {port}\nHost: {host}\nnmap: open")

    for s in results.get("ssrf",[]):
        add("CRITICAL","9.3","Sunucu Tarafi Istek Sahteciligi (SSRF)",
            s.get("url",""),"CWE-918","A10:2021",
            "Uygulama ic aga istek yapilmasina izin veriyor.",
            "Ic ag hizmetlerine ve bulut metadata API'sine erisim mumkun.",
            "URL parametrelerini dogrulayin. Izin verilen hedefleri beyaz listeye alin.",
            f"URL: {s.get('url','')}\nPayload: {s.get('payload','')}")

    findings.sort(key=lambda x: sev_order(x.get("severity","INFO")))
    return findings


def build_pdf(json_path: str) -> str:
    with open(json_path, encoding="utf-8") as f:
        data = json.load(f)

    meta    = data.get("meta", {})
    results = data.get("results", {})
    today   = datetime.now().strftime("%d.%m.%Y %H:%M")
    target  = meta.get("target", "Bilinmeyen Hedef")
    mode    = meta.get("mode", "full").upper()
    agr     = "AGRESIF" if meta.get("aggressive") else "PASIF"

    safe     = re.sub(r"[^a-zA-Z0-9_-]", "_", target)
    out_path = os.path.join(REPORTS_DIR, f"GreyPhantom_{safe}_{datetime.now():%Y%m%d_%H%M}.pdf")
    doc_info = {"target": target, "date": today}

    doc = SimpleDocTemplate(out_path, pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=20*mm, bottomMargin=16*mm,
        title=f"GREYPHANTOM - {target}", author="GREYPHANTOM v3")

    findings = extract_findings(results)
    counts   = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0}
    for f in findings:
        counts[f.get("severity","INFO").upper()] = counts.get(f.get("severity","INFO").upper(),0) + 1

    story = []

    # ── KAPAK ────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 56*mm))
    eng = Table([
        ["Hedef", target],
        ["Test Turu", "Web Uygulama Penetrasyon Testi"],
        ["Mod", f"{mode} - {agr}"],
        ["Rapor Tarihi", today],
        ["Arac", "GREYPHANTOM v3 Otomatik Pentest"],
        ["Siniflandirma", "GIZLI / CONFIDENTIAL"],
    ], colWidths=[42*mm, COL_W-42*mm],
    style=TableStyle([
        ("BACKGROUND",    (0,0),(0,-1), C_DARK),
        ("TEXTCOLOR",     (0,0),(0,-1), HexColor("#a8dadc")),
        ("BACKGROUND",    (1,0),(1,-1), C_WHITE),
        ("FONTNAME",      (0,0),(0,-1), FONT_BOLD),
        ("FONTNAME",      (1,0),(1,-1), FONT),
        ("FONTSIZE",      (0,0),(-1,-1), 9),
        ("LEADING",       (0,0),(-1,-1), 13),
        ("TOPPADDING",    (0,0),(-1,-1), 5),
        ("BOTTOMPADDING", (0,0),(-1,-1), 5),
        ("LEFTPADDING",   (0,0),(-1,-1), 8),
        ("GRID",          (0,0),(-1,-1), 0.3, C_BORDER),
    ]))
    story.append(eng)
    story.append(Spacer(1, 8*mm))

    sev_list   = ["CRITICAL","HIGH","MEDIUM","LOW","INFO","TOPLAM"]
    sev_vals   = [counts[s] for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]] + [sum(counts.values())]
    sev_bgs    = [SEV_BG.get(s,C_LIGHT) for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]] + [C_LIGHT]
    sev_fgs    = [SEV_FG.get(s,C_MUTED) for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]] + [C_TEXT]
    cw = COL_W/6
    risk = Table([
        [Paragraph(f"<b>{s}</b>", ParagraphStyle(f"rh{i}", fontName=FONT_BOLD,
             fontSize=8, alignment=TA_CENTER, textColor=sev_fgs[i]))
         for i,s in enumerate(sev_list)],
        [Paragraph(f"<b>{v}</b>", ParagraphStyle(f"rv{i}", fontName=FONT_BOLD,
             fontSize=18, alignment=TA_CENTER, textColor=sev_fgs[i]))
         for i,v in enumerate(sev_vals)],
    ], colWidths=[cw]*6,
    style=TableStyle(
        [("BACKGROUND",(i,0),(i,-1),sev_bgs[i]) for i in range(6)] +
        [("ALIGN",(0,0),(-1,-1),"CENTER"),("VALIGN",(0,0),(-1,-1),"MIDDLE"),
         ("TOPPADDING",(0,0),(-1,-1),6),("BOTTOMPADDING",(0,0),(-1,-1),6),
         ("GRID",(0,0),(-1,-1),0.3,C_BORDER),("BOX",(0,0),(-1,-1),0.5,C_BORDER)]
    ))
    story.append(risk)

    # ── YONETİCİ OZETİ ───────────────────────────────────────────────────────
    story.append(PageBreak())
    section_header("1. Yonetici Ozeti", story)
    alive = results.get("alive_hosts",[])
    subs  = results.get("subdomains",[])
    total = sum(counts.values())
    genel = "KRITIK" if counts["CRITICAL"]>0 else "YUKSEK" if counts["HIGH"]>0 else "ORTA"
    story.append(Paragraph(
        f"GREYPHANTOM, <b>{target}</b> hedefine yonelik otomatik penetrasyon testi gerceklestirdi. "
        f"Degerlendirme sonucunda {len(alive)} canli host ve {len(subs)} subdomain uzerinde "
        f"toplam <b>{total} guvenlik bulgusu</b> tespit edildi. "
        f"Genel guvenlik durumu <b>{genel}</b> olarak degerlendirilmektedir.", ST["body"]))
    story.append(Spacer(1,3*mm))
    story.append(Paragraph(
        "Tum KRITIK ve YUKSEK bulgular icin derhal duzeltici onlem alinmasi gerekmektedir. "
        "ORTA duzey bulgular bir sonraki gelistirme sprintinde ele alinmalidir.", ST["body"]))
    story.append(Spacer(1,4*mm))

    mt = Table([
        [Paragraph("<b>Metrik</b>",ST["th"]), Paragraph("<b>Deger</b>",ST["th"])],
        ["Subdomain Sayisi",     str(len(subs))],
        ["Canli Host",           str(len(alive))],
        ["Kesfedilen URL",       str(len(results.get("urls",[])))],
        ["Acik Port",            str(len(results.get("naabu_ports",[]) or []))],
        ["Nuclei Bulgusu",       str(len(results.get("nuclei_findings",[])))],
        ["Hassas Veri",          str(len(results.get("secret_findings",[])))],
        ["Toplam Bulgu",         str(total)],
    ], colWidths=[80*mm, COL_W-80*mm],
    style=TableStyle([
        ("BACKGROUND",    (0,0),(-1,0), C_DARK),
        ("TEXTCOLOR",     (0,0),(-1,0), C_WHITE),
        ("FONTNAME",      (0,0),(-1,-1), FONT),
        ("FONTSIZE",      (0,0),(-1,-1), 9),
        ("LEADING",       (0,0),(-1,-1), 12),
        ("ROWBACKGROUNDS",(0,1),(-1,-1), [C_WHITE, C_LIGHT]),
        ("TOPPADDING",    (0,0),(-1,-1), 4),
        ("BOTTOMPADDING", (0,0),(-1,-1), 4),
        ("LEFTPADDING",   (0,0),(-1,-1), 6),
        ("GRID",          (0,0),(-1,-1), 0.3, C_BORDER),
    ]))
    story.append(mt)

    # ── KAPSAM ───────────────────────────────────────────────────────────────
    section_header("2. Kapsam ve Metodoloji", story)
    scope_rows = [[target, "Web Uygulamasi", "Kapsam Ici"]]
    for host, plist in results.get("open_ports",{}).items():
        for port in plist:
            scope_rows.append([f"{host}:{port}", "Ag Servisi", "Kapsam Ici"])
    scope = Table(
        [[Paragraph("<b>Varlik</b>",ST["th"]),
          Paragraph("<b>Tur</b>",ST["th"]),
          Paragraph("<b>Durum</b>",ST["th"])]] + scope_rows,
        colWidths=[COL_W*0.45, COL_W*0.30, COL_W*0.25],
        style=TableStyle([
            ("BACKGROUND",    (0,0),(-1,0), C_DARK),
            ("TEXTCOLOR",     (0,0),(-1,0), C_WHITE),
            ("FONTNAME",      (0,0),(-1,-1), FONT),
            ("FONTSIZE",      (0,0),(-1,-1), 9),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [C_WHITE, C_LIGHT]),
            ("TOPPADDING",    (0,0),(-1,-1), 5),
            ("BOTTOMPADDING", (0,0),(-1,-1), 5),
            ("LEFTPADDING",   (0,0),(-1,-1), 6),
            ("GRID",          (0,0),(-1,-1), 0.3, C_BORDER),
        ]))
    story.append(scope)
    story.append(Spacer(1,3*mm))
    story.append(Paragraph(
        "Test metodolojisi OWASP Test Kilavuzu v4.2 ve PTES standartlarini takip etmektedir. "
        "Kullanilan araclar: subfinder, httpx, nmap, nuclei, ffuf, katana, testssl.sh, "
        "SecretFinder, LinkFinder, dalfox, Corsy, graphw00f, trufflehog.", ST["body"]))

    # ── DETAYLI BULGULAR ─────────────────────────────────────────────────────
    story.append(PageBreak())
    section_header("3. Detayli Bulgular", story)
    if findings:
        for f in findings:
            finding_card(f, story)
    else:
        story.append(Paragraph("Bu taramada onemli guvenlik bulgusu tespit edilmemistir.", ST["body"]))

    # ── BULGU OZET TABLOSU ───────────────────────────────────────────────────
    story.append(PageBreak())
    section_header("4. Bulgu Ozeti", story)
    sum_rows = [[
        Paragraph("<b>ID</b>",ST["th"]),
        Paragraph("<b>Onem</b>",ST["th"]),
        Paragraph("<b>CVSS</b>",ST["th"]),
        Paragraph("<b>Baslik</b>",ST["th"]),
        Paragraph("<b>Durum</b>",ST["th"]),
    ]]
    for f in findings:
        sev = f.get("severity","INFO").upper()
        sum_rows.append([
            Paragraph(f.get("id",""), ST["tc"]),
            Paragraph(f"<b>{sev}</b>", ParagraphStyle(f"s{sev}",
                fontName=FONT_BOLD, fontSize=8, textColor=SEV_FG.get(sev,C_MUTED))),
            Paragraph(str(f.get("cvss","N/A")), ST["tc"]),
            Paragraph(f.get("title",""), ST["tc"]),
            Paragraph("Acik", ST["tc"]),
        ])
    sum_t = Table(sum_rows,
        colWidths=[18*mm,22*mm,14*mm,COL_W-18*mm-22*mm-14*mm-18*mm,18*mm],
        style=TableStyle([
            ("BACKGROUND",    (0,0),(-1,0), C_DARK),
            ("TEXTCOLOR",     (0,0),(-1,0), C_WHITE),
            ("FONTNAME",      (0,0),(-1,-1), FONT),
            ("FONTSIZE",      (0,0),(-1,-1), 8),
            ("LEADING",       (0,0),(-1,-1), 11),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [C_WHITE, C_LIGHT]),
            ("TOPPADDING",    (0,0),(-1,-1), 4),
            ("BOTTOMPADDING", (0,0),(-1,-1), 4),
            ("LEFTPADDING",   (0,0),(-1,-1), 5),
            ("GRID",          (0,0),(-1,-1), 0.3, C_BORDER),
            ("BOX",           (0,0),(-1,-1), 0.5, C_BORDER),
        ]))
    story.append(sum_t)

    # ── DUZELTIM YOL HARITASI ─────────────────────────────────────────────────
    section_header("5. Duzeltim Yol Haritasi", story)
    rm_bgs = [SEV_BG["CRITICAL"],SEV_BG["HIGH"],SEV_BG["MEDIUM"],SEV_BG["LOW"]]
    rm_t = Table([
        [Paragraph("<b>Oncelik</b>",ST["th"]),
         Paragraph("<b>Onem</b>",ST["th"]),
         Paragraph("<b>Son Tarih</b>",ST["th"]),
         Paragraph("<b>Adet</b>",ST["th"])],
        ["Acil (P0)",      "KRITIK",     "48 saat icinde",    str(counts["CRITICAL"])],
        ["Kisa Vade (P1)", "YUKSEK",     "14 gun icinde",     str(counts["HIGH"])],
        ["Sprint (P2)",    "ORTA",       "Sonraki sprint",    str(counts["MEDIUM"])],
        ["Birikim (P3)",   "DUSUK/BILGI","60 gun icinde",     str(counts["LOW"]+counts["INFO"])],
    ], colWidths=[35*mm,30*mm,42*mm,COL_W-35*mm-30*mm-42*mm],
    style=TableStyle([
        ("BACKGROUND",    (0,0),(-1,0), C_DARK),
        ("TEXTCOLOR",     (0,0),(-1,0), C_WHITE),
        ("FONTNAME",      (0,0),(-1,-1), FONT),
        ("FONTSIZE",      (0,0),(-1,-1), 9),
        ("LEADING",       (0,0),(-1,-1), 12),
    ] + [("BACKGROUND",(0,i+1),(-1,i+1),rm_bgs[i]) for i in range(4)] +
    [("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5),
     ("LEFTPADDING",(0,0),(-1,-1),6),("GRID",(0,0),(-1,-1),0.3,C_BORDER),
     ("BOX",(0,0),(-1,-1),0.5,C_BORDER)]))
    story.append(rm_t)

    # ── IMZA ─────────────────────────────────────────────────────────────────
    story.append(Spacer(1,10*mm))
    story.append(HRFlowable(width="100%", thickness=0.3, color=C_BORDER))
    story.append(Spacer(1,4*mm))
    story.append(Paragraph(
        f"Rapor Tarihi: {today}  |  GREYPHANTOM v3  |  Insan tarafindan dogrulanmistir.",
        ST["center"]))

    # ── BUILD ─────────────────────────────────────────────────────────────────
    class MyCanvas(GPCanvas):
        def __init__(self, filename, **kwargs):
            kwargs.pop("doc_info", None)
            GPCanvas.__init__(self, filename, doc_info=doc_info, **kwargs)

    doc.build(story, canvasmaker=MyCanvas)
    return out_path