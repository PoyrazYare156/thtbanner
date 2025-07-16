import requests

def test_open_redirect(url):
    try:
        r = requests.get(url + "?next=http://evil.com", allow_redirects=False, timeout=5)
        if "evil.com" in r.headers.get("Location", ""):
            return True
    except:
        pass
    return False
