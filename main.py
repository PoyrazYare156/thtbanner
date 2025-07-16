from fastapi import FastAPI, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import cloudscraper
from modules.sql_injection import test_sql_injection
from modules.xss import test_xss
from modules.waf_detect import detect_waf
from modules.open_redirect import test_open_redirect
app = FastAPI()

# CORS çözümü
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static ve templates klasörleri bağlanıyor
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Header puanları
SECURITY_HEADERS = {
    "content-security-policy": 20,
    "strict-transport-security": 15,
    "x-frame-options": 10,
    "x-content-type-options": 10,
    "referrer-policy": 10,
    "permissions-policy": 10
}

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})
    
@app.get("/güvenlik", response_class=HTMLResponse)
async def güvenlik_page(request: Request):
    return templates.TemplateResponse("güvenlik.html", {"request": request})

@app.get("/api/vulnscan")
async def vuln_scan(url: str = Query(...)):
    results = {
        "sql_injection": test_sql_injection(url),
        "xss": test_xss(url),
        "waf": detect_waf(url),
        "open_redirect": test_open_redirect(url)
    }
    return results

@app.get("/api/scan")
async def scan(url: str = Query(...)):
    try:
        scraper = cloudscraper.create_scraper(browser={'custom': 'ScannerBot/1.0'})
        response = scraper.get(url, timeout=10)
        headers = dict(response.headers)

        results = {}
        for header, score in SECURITY_HEADERS.items():
            if header in headers:
                results[header] = {"value": headers[header], "score": score}
            else:
                results[header] = {"value": None, "score": 0}

        return results
    except Exception as e:
        return {"error": str(e)}
