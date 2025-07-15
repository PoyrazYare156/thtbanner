from fastapi import FastAPI, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import cloudscraper

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

templates = Jinja2Templates(directory="templates")

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

@app.get("/api/scan")
async def scan(url: str = Query(...)):
    try:
        scraper = cloudscraper.create_scraper(
            browser={'custom': 'ScraperBot/1.0'}
        )
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
