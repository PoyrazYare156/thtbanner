import requests

def test_sql_injection(url):
    test_payload = "' OR '1'='1"
    try:
        r = requests.get(url, params={"id": test_payload}, timeout=5)
        if "sql" in r.text.lower() or "syntax" in r.text.lower():
            return True
    except:
        pass
    return False
