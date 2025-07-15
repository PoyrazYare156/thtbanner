from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
import httpx

app = FastAPI()

origins = ["*"]  # Geliştirme aşaması için herkese açık (isteğe bağlı kısıtlanabilir)
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECURITY_HEADERS = {
    "content-security-policy": 20,
    "strict-transport-security": 15,
    "x-frame-options": 10,
    "x-content-type-options": 10,
    "referrer-policy": 10,
    "permissions-policy": 10
}

@app.get("/api/scan")
async def scan_headers(url: str = Query(..., description="Target URL to scan")):
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=10) as client:
            response = await client.head(url)

        headers = {k.lower(): v for k, v in response.headers.items()}
        report = {}
        score = 100
        recommendations = []

        for header, points in SECURITY_HEADERS.items():
            val = headers.get(header)
            if not val:
                score -= points
                report[header] = None
                recommendations.append(f"{header} is missing.")
            else:
                report[header] = val
                if header == "content-security-policy":
                    if any(x in val for x in ["*", "unsafe-inline", "unsafe-eval"]):
                        score -= 10
                        recommendations.append("CSP is weak (uses * or unsafe-*).")
                    elif "nonce" not in val and "strict-dynamic" not in val:
                        score -= 5
                        recommendations.append("CSP lacks nonce or strict-dynamic.")

        risk = "Low"
        if score < 80:
            risk = "Medium"
        if score < 50:
            risk = "High"

        return {
            "url": url,
            "score": score,
            "risk": risk,
            "headers": report,
            "recommendations": recommendations
        }

    except Exception as e:
        return {
            "url": url,
            "error": str(e),
            "score": 0,
            "risk": "Error",
            "headers": {},
            "recommendations": ["Scan failed due to error."]
        }