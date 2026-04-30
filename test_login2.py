import requests
import logging

logging.basicConfig(level=logging.DEBUG)
import urllib3
urllib3.disable_warnings()
session = requests.Session()
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Accept-Language': 'en-US,en;q=0.9',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'same-origin',
    'Sec-Fetch-User': '?1',
    'Upgrade-Insecure-Requests': '1',
}

r1 = session.get('https://vtop.vitap.ac.in/vtop/open/page', headers=HEADERS, verify=False)
import re
csrf = re.search(r'name="_csrf"\s+value="([^"]+)"', r1.text).group(1)

r2 = session.post('https://vtop.vitap.ac.in/vtop/prelogin/setup', data={'_csrf': csrf, 'flag': 'VTOP'}, headers={**HEADERS, 'Content-Type': 'application/x-www-form-urlencoded', 'Referer': 'https://vtop.vitap.ac.in/vtop/open/page'}, verify=False)
login_csrf = re.search(r'name="_csrf"\s+value="([^"]+)"', r2.text).group(1)

payload = {
    "_csrf": login_csrf,
    "username": "KAMRANQURESHI",
    "password": "wrongpassword123",
    "captchaStr": "123456",
}

r3 = session.post(
    "https://vtop.vitap.ac.in/vtop/login",
    data=payload,
    headers={
        **HEADERS,
        "Content-Type": "application/x-www-form-urlencoded",
        "Referer": "https://vtop.vitap.ac.in/vtop/login",
        "Origin": "https://vtop.vitap.ac.in",
    },
    verify=False,
    allow_redirects=False,
)

print("LOGIN POST STATUS:", r3.status_code)
print("LOGIN POST URL:", r3.url)
print("HEADERS:", r3.headers)
