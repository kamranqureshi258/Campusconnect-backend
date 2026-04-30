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
with open('vtop_login.html', 'w', encoding='utf-8') as f:
    f.write(r2.text)
