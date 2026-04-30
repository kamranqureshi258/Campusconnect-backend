"""
Test script to fetch and save the actual processViewTimeTable response
so we can inspect its HTML structure.
"""
import requests
import urllib3
urllib3.disable_warnings()

# Load cookies/session from main app's session
# We'll make a fresh login here

VTOP_BASE = "https://vtop.vitap.ac.in/vtop"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0",
}

session = requests.Session()

# Step 1: Load initial page
r = session.get(f"{VTOP_BASE}/open/page", headers=HEADERS, verify=False)
from bs4 import BeautifulSoup
soup = BeautifulSoup(r.text, "html.parser")
csrf = soup.find("input", {"name": "_csrf"})
csrf_val = csrf.get("value", "") if csrf else ""
print(f"CSRF: {csrf_val[:30]}...")

# Step 2: prelogin setup
r2 = session.post(
    f"{VTOP_BASE}/prelogin/setup",
    data={"_csrf": csrf_val, "flag": "VTOP"},
    headers={**HEADERS, "Content-Type": "application/x-www-form-urlencoded", "Referer": f"{VTOP_BASE}/open/page"},
    verify=False, allow_redirects=True,
)
soup2 = BeautifulSoup(r2.text, "html.parser")
csrf_input = soup2.find("input", {"name": "_csrf"})
if csrf_input:
    csrf_val = csrf_input.get("value", "")
    print(f"NEW CSRF: {csrf_val[:30]}...")

# --- NOW YOU NEED TO MANUALLY SET THESE AFTER LOGIN ---
# Copy these from your running main.py session (print session._csrf and session.authorizedID)
CSRF = input("Paste your _csrf token: ").strip()
AUTH_ID = input("Paste your authorizedID: ").strip()
SEM_ID = input("Paste semester ID (e.g. AP2025265): ").strip()
JSESSIONID = input("Paste JSESSIONID cookie: ").strip()

session.cookies.set("JSESSIONID", JSESSIONID, domain="vtop.vitap.ac.in")

r3 = session.post(
    f"{VTOP_BASE}/processViewTimeTable",
    data={"_csrf": CSRF, "semesterSubId": SEM_ID, "authorizedID": AUTH_ID},
    headers={**HEADERS, "Content-Type": "application/x-www-form-urlencoded"},
    verify=False,
)
print(f"STATUS: {r3.status_code}, LEN: {len(r3.text)}")
print(f"URL: {r3.url}")

with open("timetable_response.html", "w", encoding="utf-8") as f:
    f.write(r3.text)
print("Saved to timetable_response.html")
print("First 2000 chars:")
print(r3.text[:2000])
