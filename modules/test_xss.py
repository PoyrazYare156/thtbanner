import requests

def test_xss(url):
    test_payload = "<script>alert(1)</script>"
    try:
        r = requests.get(url, params={"q": test_payload}, timeout=5)
        if test_payload in r.text:
            return True
    except:
        pass
    return False
