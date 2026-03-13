# penbot 🔴

Automated Pentest Framework — by Orkun

## Kurulum

```bash
# WSL Ubuntu'da
git clone https://github.com/kullanicin/penbot.git
cd penbot
pip install -r requirements.txt --break-system-packages
```

## Kullanım

```bash
# Full tarama (agresif mi sorar)
python penbot.py --target hedef.com

# Mod seç
python penbot.py --target hedef.com --mode full
python penbot.py --target hedef.com --mode recon
python penbot.py --target hedef.com --mode vuln
python penbot.py --target hedef.com --mode quick

# Modu zorla
python penbot.py --target hedef.com --aggressive
python penbot.py --target hedef.com --passive

# Son taramayı Claude'a yapıştırmak için
python penbot.py --report
```

## Modlar

| Mod | Fazlar | Süre |
|---|---|---|
| `full` | recon + crawl + vuln | ~15-30 dk |
| `quick` | recon + vuln | ~10-15 dk |
| `recon` | sadece recon | ~5 dk |
| `crawl` | sadece crawl | ~10 dk |
| `vuln` | sadece vuln | ~10 dk |

## Gerekli araçlar (WSL)

```
subfinder, assetfinder, httpx, nmap, gau, waybackurls,
ffuf, nuclei, arjun, gf, jwt_tool
```

## Raporlar

`reports/` klasöründe JSON olarak kaydedilir.
`python penbot.py --report` ile son taramayı Claude formatında görebilirsin.