import requests
from bs4 import BeautifulSoup
import urllib3

urllib3.disable_warnings()
session = requests.Session()
HEADERS = {'User-Agent': 'Mozilla/5.0'}

r1 = session.get('https://vtop.vitap.ac.in/vtop/open/page', headers=HEADERS, verify=False)
soup1 = BeautifulSoup(r1.text, 'html.parser')
csrf = soup1.find('input', {'name': '_csrf'}).get('value')

r2 = session.post('https://vtop.vitap.ac.in/vtop/prelogin/setup', data={'_csrf': csrf, 'flag': 'VTOP'}, headers=HEADERS, verify=False)
soup2 = BeautifulSoup(r2.text, 'html.parser')
login_csrf = soup2.find('input', {'name': '_csrf'}).get('value')

print("PRELOGIN CSRF:", csrf)
print("LOGIN CSRF:", login_csrf)

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
        "Referer": "https://vtop.vitap.ac.in/vtop/login", # this is probably the actual referer now
        "Origin": "https://vtop.vitap.ac.in",
    },
    verify=False,
    allow_redirects=True,
)

print("LOGIN POST STATUS:", r3.status_code)
print("LOGIN POST URL:", r3.url)
print(r3.text[:500])
