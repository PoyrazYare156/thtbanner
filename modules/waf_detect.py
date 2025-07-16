import requests

def detect_waf(url):
    try:
        r = requests.get(url, timeout=5)
        server = r.headers.get("Server", "").lower()
        if any(waf in server for waf in ["cloudflare", "sucuri", "incapsula"]):
            return True
    except:
        pass
    return False
