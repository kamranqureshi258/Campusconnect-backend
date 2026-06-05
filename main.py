# ============================
# CampusConnect Backend
# ============================

import os
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel
from typing import Optional
from test_captcha import solve_captcha
from bs4 import BeautifulSoup
import requests
import urllib3
import base64
import time
import re
from datetime import datetime, timezone
from fastapi.staticfiles import StaticFiles

urllib3.disable_warnings()

app = FastAPI(title="CampusConnect API")

# Optional: serve local assets if provided (useful in dev; cloud deploy won't have this path)
_assets_dir = os.getenv("ASSETS_DIR", "").strip()
if _assets_dir:
    p = Path(_assets_dir)
    if p.exists() and p.is_dir():
        app.mount("/assets", StaticFiles(directory=str(p)), name="assets")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Monkeypatch requests.Session.request to default timeout to 10 seconds
original_request = requests.Session.request

def new_request(self, method, url, *args, **kwargs):
    kwargs.setdefault("timeout", 10)
    return original_request(self, method, url, *args, **kwargs)

requests.Session.request = new_request

session = requests.Session()

VTOP_BASE = "https://vtop.vitap.ac.in/vtop"

# Headers — keep it simple; Sec-Fetch-* caused 404 on login POST
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0",
}

# Current semester IDs (from vitap_student_app constants — most recent first)
SEMESTER_IDS = [
    "AP2024258",  # Summer Semester2 2024-25
    "AP2024257",  # Summer Semester1 2024-25
    "AP2024256",  # Long Semester 2024-25
    "AP2024255",  # Winter Semester 2024-25 Freshers
    "AP2024254",  # Winter Semester 2024-25
    "AP2024253",  # FALL SEM 2024-25 FRESHERS
    "AP2024252",  # FALL SEM 2024-25
]

# ============================
# MODELS
# ============================
class LoginRequest(BaseModel):
    registration_number: str
    password: str
    captcha: Optional[str] = None


class OtpRequest(BaseModel):
    otp: str

class OutingApplyRequest(BaseModel):
    placeOfVisit: str
    purposeOfVisit: str
    outDate: str  # Format: DD-Mon-YYYY (e.g., 25-Oct-2026)
    inDate: str
    outTimeHr: str # 06 to 22
    outTimeMin: str # 00, 30
    inTimeHr: str
    inTimeMin: str


# ============================
# ROOT
# ============================
@app.get("/")
def root():
    return {"message": "CampusConnect Backend Running"}


# ============================
# CAPTCHA
# ============================
@app.get("/captcha")
def get_captcha():
    global session

    try:
        login_page = session.get(f"{VTOP_BASE}/open/page", headers=HEADERS, verify=False)

        soup = BeautifulSoup(login_page.text, "html.parser")
        csrf_input = soup.find("input", {"name": "_csrf"})
        csrf_val = csrf_input.get("value", "") if csrf_input else ""
        session._csrf = csrf_val

        # Important: Initialize student login context
        setup_r = session.post(
            f"{VTOP_BASE}/prelogin/setup",
            data={"_csrf": csrf_val, "flag": "VTOP"},
            headers={
                **HEADERS,
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": f"{VTOP_BASE}/open/page",
            },
            verify=False,
            allow_redirects=True,
        )

        print(f"PRELOGIN STATUS: {setup_r.status_code}, URL: {setup_r.url}")
        print(f"PRELOGIN COOKIES: {dict(session.cookies)}")
        
        # Update CSRF token from the actual login page just in case it changed
        soup_login = BeautifulSoup(setup_r.text, "html.parser")
        csrf_login = soup_login.find("input", {"name": "_csrf"})
        if csrf_login:
            session._csrf = csrf_login.get("value", "")
            print(f"NEW CSRF FROM SETUP: {session._csrf}")

        r = session.get(f"{VTOP_BASE}/get/new/captcha", headers=HEADERS, verify=False)
        print(f"CAPTCHA STATUS: {r.status_code}")

        soup2 = BeautifulSoup(r.text, "html.parser")
        img = soup2.find("img")

        if img and img.get("src"):
            src = img["src"]

            if src.startswith("data:image"):
                header, data = src.split(",", 1)
                mime = header.split(";")[0].split(":")[1]
                return Response(base64.b64decode(data), media_type=mime)

            img_url = src if src.startswith("http") else f"{VTOP_BASE}/{src.lstrip('/')}"
            img_r = session.get(img_url, verify=False)

            return Response(
                content=img_r.content,
                media_type=img_r.headers.get("Content-Type", "image/png"),
            )

        raise HTTPException(status_code=500, detail="Captcha not found")

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================
# LOGIN
# ============================
def _setup_vtop_session():
    """Initializes the VTOP session and gets the CSRF token"""
    global session
    login_page = session.get(f"{VTOP_BASE}/open/page", headers=HEADERS, verify=False)
    soup = BeautifulSoup(login_page.text, "html.parser")
    csrf_input = soup.find("input", {"name": "_csrf"})
    csrf_val = csrf_input.get("value", "") if csrf_input else ""
    session._csrf = csrf_val

    setup_r = session.post(
        f"{VTOP_BASE}/prelogin/setup",
        data={"_csrf": csrf_val, "flag": "VTOP"},
        headers={
            **HEADERS,
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": f"{VTOP_BASE}/open/page",
        },
        verify=False,
        allow_redirects=True,
    )
    
    soup_login = BeautifulSoup(setup_r.text, "html.parser")
    csrf_login = soup_login.find("input", {"name": "_csrf"})
    if csrf_login:
        session._csrf = csrf_login.get("value", "")

@app.post("/login")
def login(data: LoginRequest):
    global session

    try:
        # If frontend didn't pass captcha, we need to setup the session ourselves
        if not hasattr(session, "_csrf") or not data.captcha:
            _setup_vtop_session()
            
        captcha_ans = data.captcha.strip() if data.captcha else ""
        
        # Auto-solve captcha if not provided
        if not captcha_ans:
            r_cap = session.get(f"{VTOP_BASE}/get/new/captcha", headers=HEADERS, verify=False)
            try:
                soup2 = BeautifulSoup(r_cap.text, "html.parser")
                img = soup2.find("img")
                if img and img.get("src"):
                    src = img["src"]
                    if src.startswith("data:image"):
                        # Extract the base64 part
                        b64_str = src.split(",", 1)[1]
                        captcha_ans = solve_captcha(b64_str)
                        print(f"Auto-solved captcha: {captcha_ans}")
                    else:
                        print(f"Captcha src is not data URL: {src}")
            except Exception as e:
                print(f"Captcha auto-solve failed: {e}")

        payload = {
            "_csrf": getattr(session, "_csrf", ""),
            "username": data.registration_number.strip(),
            "password": data.password.strip(),
            "vtopLogin": "true",
            "captchaStr": captcha_ans,
        }

        # Store the registration number for later use as authorizedID
        session._username = data.registration_number.strip()

        print(f"LOGIN PAYLOAD: csrf={payload['_csrf'][:20]}..., user={payload['username']}, captcha={payload['captchaStr']}")
        print(f"LOGIN COOKIES: {dict(session.cookies)}")

        # First POST without following redirects to see raw response
        r_raw = session.post(
            f"{VTOP_BASE}/login",
            data=payload,
            headers={
                **HEADERS,
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": f"{VTOP_BASE}/prelogin/setup",
                "Origin": "https://vtop.vitap.ac.in",
            },
            verify=False,
            allow_redirects=False,
        )

        print(f"RAW LOGIN STATUS: {r_raw.status_code}")
        print(f"RAW LOCATION: {r_raw.headers.get('Location', 'NONE')}")
        print(f"RAW RESPONSE LEN: {len(r_raw.text)}")

        # Now follow redirects manually
        if r_raw.status_code in (301, 302, 303, 307, 308):
            redirect_url = r_raw.headers.get("Location", "")
            if redirect_url:
                if not redirect_url.startswith("http"):
                    redirect_url = f"https://vtop.vitap.ac.in{redirect_url}"
                print(f"FOLLOWING REDIRECT TO: {redirect_url}")
                r = session.get(redirect_url, headers=HEADERS, verify=False)
            else:
                r = r_raw
        else:
            r = r_raw

        html = r.text.lower()
        final_url = r.url.lower()

        print(f"LOGIN RESPONSE STATUS: {r.status_code}")
        print("FINAL URL:", r.url)
        print("HTML SNIPPET:", r.text[:500])

        # SUCCESS
        if "init/page" in final_url or "processcourse" in final_url or "content" in final_url:
            _extract_session_tokens(r.text)
            return {"success": True}

        # OTP DETECTION
        if (
            "otp has been sent" in html or
            "enter otp" in html or
            "verify otp" in html or
            "otpverification" in final_url
        ):
            return {
                "success": False,
                "otp_required": True,
                "message": "OTP required"
            }

        # ERROR HANDLING
        if "login/error" in final_url:
            return {"success": False, "message": "Invalid credentials or captcha"}

        # CAPTCHA
        if "captcha" in html:
            return {"success": False, "message": "Wrong captcha"}

        return {"success": False, "message": "Login failed"}

    except Exception as e:
        return {"success": False, "message": str(e)}


def _extract_session_tokens(html_text: str):
    """Extract authorizedID and CSRF from the dashboard HTML after login."""
    global session

    # Save dashboard for debugging
    try:
        with open("dashboard_debug.html", "w", encoding="utf-8") as f:
            f.write(html_text)
    except Exception:
        pass

    # Extract authorizedID — VTOP uses various JS variable patterns
    patterns = [
        r'var\s+id\s*=\s*["\']([^"\']+)["\']',
        r'authorizedID\s*[=:]\s*["\']([^"\']+)["\']',
        r'id="authorizedIDX"\s+value="([^"]+)"',
        r'name="authorizedID"\s+value="([^"]+)"',
    ]
    for pat in patterns:
        m = re.search(pat, html_text)
        if m:
            session.authorizedID = m.group(1)
            print(f"EXTRACTED authorizedID: {session.authorizedID}")
            break
    else:
        # Fallback: use the registration number
        if hasattr(session, "_username"):
            session.authorizedID = session._username
            print(f"FALLBACK authorizedID: {session.authorizedID}")

    # Extract fresh CSRF token from dashboard
    soup = BeautifulSoup(html_text, "html.parser")
    csrf_input = soup.find("input", {"name": "_csrf"})
    if csrf_input and csrf_input.get("value"):
        session._csrf = csrf_input["value"]
        print(f"UPDATED CSRF: {session._csrf}")


# ============================
# OTP VERIFY
# ============================
@app.post("/submit-otp")
def submit_otp(data: OtpRequest):
    global session

    try:
        r_otp = session.post(
            f"{VTOP_BASE}/validateSecurityOtp",
            data={"otpCode": data.otp.strip(), "_csrf": getattr(session, "_csrf", "")},
            headers={
                **HEADERS,
                "Content-Type": "application/x-www-form-urlencoded",
            },
            verify=False,
        )

        # validateSecurityOtp returns JSON like {"status": "SUCCESS", "redirectUrl": "..."}
        try:
            resp_json = r_otp.json()
            if resp_json.get("status") == "SUCCESS":
                # Follow redirect to dashboard to extract tokens
                redirect_url = resp_json.get("redirectUrl", "")
                if redirect_url:
                    dash_r = session.get(
                        f"https://vtop.vitap.ac.in{redirect_url}",
                        headers=HEADERS,
                        verify=False,
                    )
                    _extract_session_tokens(dash_r.text)
                return {"success": True}
            else:
                return {"success": False, "message": resp_json.get("message", "OTP verification failed")}
        except ValueError:
            pass

        r = session.get(f"{VTOP_BASE}/init/page", headers=HEADERS, verify=False)

        if "init/page" in r.url.lower():
            _extract_session_tokens(r.text)
            return {"success": True}

        return {"success": False, "message": "OTP verification failed"}

    except Exception as e:
        return {"success": False, "message": str(e)}


# ============================
# ATTENDANCE
# ============================
@app.get("/attendance")
def attendance():
    global session

    try:
        csrf = getattr(session, "_csrf", "")
        auth_id = getattr(session, "authorizedID", getattr(session, "_username", ""))

        if not csrf or not auth_id:
            raise HTTPException(status_code=401, detail="Not logged in. Please login first.")

        print(f"ATTENDANCE REQUEST: authorizedID={auth_id}, csrf={csrf[:20]}...")

        # Step 1: Dynamically fetch available semester IDs from StudentTimeTable
        init_payload = {
            "verifyMenu": "true",
            "authorizedID": auth_id,
            "_csrf": csrf,
            "nocache": str(int(time.time() * 1000)),
        }

        r_init = session.post(
            f"{VTOP_BASE}/academics/common/StudentTimeTable",
            data=init_payload,
            headers={
                **HEADERS,
                "Content-Type": "application/x-www-form-urlencoded",
            },
            verify=False,
        )

        print(f"TIMETABLE INIT: status={r_init.status_code}, len={len(r_init.text)}")

        # Skip if we got redirected to login (session expired)
        if "login" in r_init.url.lower():
            raise HTTPException(status_code=401, detail="Session expired. Please login again.")

        # Extract semester IDs from the dropdown
        soup_init = BeautifulSoup(r_init.text, "html.parser")
        sem_select = soup_init.find("select", {"name": "semesterSubId"})

        semester_ids = []
        if sem_select:
            for opt in sem_select.find_all("option"):
                val = opt.get("value", "").strip()
                if val:
                    semester_ids.append(val)
                    print(f"  FOUND SEMESTER: {val} — {opt.text.strip()}")

        if not semester_ids:
            # Fallback to hardcoded IDs
            print("No semesters found dynamically, using hardcoded fallback")
            semester_ids = SEMESTER_IDS
        
        # Save the init response for debugging
        try:
            with open("timetable_init_debug.html", "w", encoding="utf-8") as f:
                f.write(r_init.text)
        except Exception:
            pass

        # Step 2: Try each semester ID via processViewStudentAttendance
        for sem_id in semester_ids:
            fetch_payload = {
                "_csrf": csrf,
                "semesterSubId": sem_id,
                "authorizedID": auth_id,
            }

            r = session.post(
                f"{VTOP_BASE}/processViewStudentAttendance",
                data=fetch_payload,
                headers={
                    **HEADERS,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                verify=False,
            )

            print(f"SEM {sem_id}: status={r.status_code}, len={len(r.text)}, url={r.url}")

            # Skip if we got redirected to login (session expired)
            if "login" in r.url.lower():
                raise HTTPException(status_code=401, detail="Session expired. Please login again.")

            # Skip 404 or empty/error responses
            if r.status_code == 404:
                continue

            soup = BeautifulSoup(r.text, "html.parser")
            rows = soup.find_all("tr")

            # Need at least a header + 1 data row
            if len(rows) < 2:
                print(f"SEM {sem_id}: Only {len(rows)} rows, trying next...")
                continue

            theory, lab = [], []

            for row in rows:
                cols = row.find_all("td")
                if len(cols) < 8:
                    continue

                course_name = cols[2].text.strip()
                course_type = cols[3].text.strip() if len(cols) > 3 else ""

                # attendance_percentage is at index 7 per vitap_student_app's parser
                percent = cols[7].text.strip().replace("%", "") if len(cols) > 7 else ""
                
                # Fallback: try last column
                if not percent or not percent.replace('.', '', 1).isdigit():
                    percent = cols[-1].text.strip().replace("%", "")
                if not percent.replace('.', '', 1).isdigit():
                    continue

                attended = cols[5].text.strip() if len(cols) > 5 else ""
                total = cols[6].text.strip() if len(cols) > 6 else ""

                item = {
                    "course": course_name,
                    "percent": percent,
                    "attended": attended,
                    "total": total,
                    "type": course_type,
                }

                if "lab" in course_type.lower() or "lab" in course_name.lower():
                    lab.append(item)
                else:
                    theory.append(item)

            if theory or lab:
                print(f"SUCCESS with SEM {sem_id}: {len(theory)} theory, {len(lab)} lab")
                return {"theory": theory, "lab": lab}
            else:
                print(f"SEM {sem_id}: Parsed 0 courses, trying next...")

        # If we exhausted all semester IDs, return empty
        print("No attendance data found for any semester ID")
        return {"theory": [], "lab": []}

    except HTTPException:
        raise
    except Exception as e:
        print("ATTENDANCE ERROR:", str(e))
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


# ============================
# LOGOUT
# ============================
@app.post("/logout")
def logout():
    global session
    session = requests.Session()
    return {"success": True}


# ============================
# HELPER: get session tokens
# ============================
def _get_auth():
    csrf = getattr(session, "_csrf", "")
    auth_id = getattr(session, "authorizedID", getattr(session, "_username", ""))
    if not csrf or not auth_id:
        raise HTTPException(status_code=401, detail="Not logged in.")
    return csrf, auth_id


def _get_semesters():
    """Fetch available semester IDs dynamically from VTOP."""
    csrf, auth_id = _get_auth()
    r = session.post(
        f"{VTOP_BASE}/academics/common/StudentTimeTable",
        data={"verifyMenu": "true", "authorizedID": auth_id, "_csrf": csrf, "nocache": str(int(time.time() * 1000))},
        headers={**HEADERS, "Content-Type": "application/x-www-form-urlencoded"},
        verify=False,
    )
    if "login" in r.url.lower():
        raise HTTPException(status_code=401, detail="Session expired.")
    soup = BeautifulSoup(r.text, "html.parser")
    sel = soup.find("select", {"name": "semesterSubId"})
    ids = []
    if sel:
        for opt in sel.find_all("option"):
            v = opt.get("value", "").strip()
            if v:
                ids.append({"id": v, "name": opt.text.strip()})
    if not ids:
        ids = [{"id": sid, "name": sid} for sid in SEMESTER_IDS]
    return ids


# ============================
# SEMESTERS
# ============================
@app.get("/semesters")
def get_semesters():
    try:
        return {"semesters": _get_semesters()}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================
# TIMETABLE
# ============================
@app.get("/timetable")
def timetable(sem_id: str = ""):
    try:
        csrf, auth_id = _get_auth()
        if not sem_id:
            sems = _get_semesters()
            sem_id = sems[0]["id"] if sems else ""
        if not sem_id:
            raise HTTPException(status_code=400, detail="No semester ID available.")

        r = session.post(
            f"{VTOP_BASE}/processViewTimeTable",
            data={"_csrf": csrf, "semesterSubId": sem_id, "authorizedID": auth_id},
            headers={**HEADERS, "Content-Type": "application/x-www-form-urlencoded"},
            verify=False,
        )
        if "login" in r.url.lower():
            raise HTTPException(status_code=401, detail="Session expired.")

        # Save raw response for debugging
        with open("timetable_response.html", "w", encoding="utf-8") as f:
            f.write(r.text)
        print(f"TIMETABLE: status={r.status_code}, len={len(r.text)}")

        soup = BeautifulSoup(r.text, "html.parser")
        
        # ── Find the Course List Table and the Timetable Grid ───────────────────
        tables = soup.find_all("table")
        print(f"TIMETABLE TABLES: {len(tables)}")
        
        course_table = None
        grid_table = None
        
        for table in tables:
            first_row = table.find("tr")
            if not first_row:
                continue
            text = first_row.get_text(" ", strip=True).upper()
            if "SL.NO" in text and "CLASS GROUP" in text:
                course_table = table
            elif "THEORY" in text and "START" in text:
                grid_table = table

        # ── Pass 1: Course list table ─────────────────────────────
        # Maps course_code -> {name, faculty, slot, venue, class_nbr}
        # Maps class_nbr  -> faculty
        # Maps course_key (code_type) -> (slot, venue)
        classname_code = {}   # code -> name
        faculty_code   = {}   # class_nbr -> faculty
        course_to_class_nbr = {}   # code_type -> class_nbr
        course_to_slot_venue = {}  # code_type -> (slot, venue)

        if course_table:
            for row in course_table.find_all("tr"):
                cols = row.find_all("td")
                if len(cols) < 9:
                    continue

                # col[6] = Class Nbr
                class_nbr = cols[6].get_text(strip=True).replace("\t","").replace("\n","")

                # col[2] = "CODE - Name ( Course Type )"
                raw_name = cols[2].get_text(" ", strip=True).replace("\t","").replace("\n","")
                name_parts = [p.strip() for p in raw_name.split(" - ") if p.strip()]
                if len(name_parts) < 2:
                    continue

                code = name_parts[0]
                # name is everything after code, stripped of "(type)" suffix
                name_full = " - ".join(name_parts[1:])
                name = name_full.split("(")[0].strip()

                if code not in classname_code:
                    classname_code[code] = name

                # Determine course_type from the description string
                if "( Embedded Theory )" in raw_name or "(Embedded Theory)" in raw_name:
                    ctype = "ETH"
                elif "( Embedded Lab )" in raw_name or "(Embedded Lab)" in raw_name:
                    ctype = "ELA"
                elif "( Theory Only )" in raw_name or "(Theory Only)" in raw_name:
                    ctype = "TH"
                elif "( Lab Only )" in raw_name or "(Lab Only)" in raw_name:
                    ctype = "LO"
                elif "( Project )" in raw_name or "(Project)" in raw_name:
                    ctype = "PJT"
                else:
                    ctype = "UNK"

                if class_nbr:
                    course_key = f"{code}_{ctype}"
                    course_to_class_nbr[course_key] = class_nbr

                    # col[7] = slot/venue in <p> tags
                    paras = cols[7].find_all("p")
                    if len(paras) >= 2:
                        slot_txt = paras[0].get_text(strip=True).replace(" - ", "").replace(" -", "")
                        venue_txt = paras[1].get_text(strip=True)
                        if slot_txt and venue_txt:
                            course_to_slot_venue[course_key] = (slot_txt, venue_txt)

                # col[8] = faculty
                faculty_raw = cols[8].get_text(" ", strip=True)
                faculty_name = faculty_raw.split(" - ")[0].strip()
                if faculty_name and faculty_name != "Project" and class_nbr:
                    faculty_code[class_nbr] = faculty_name

        print(f"COURSES FOUND: {len(classname_code)}, FACULTY: {len(faculty_code)}")

        # ── Pass 2: Day-grid table ───────────────────────────────
        DAYS = ["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"]
        timetable_data = {d: [] for d in DAYS}
        timings = []  # [{start, end}]
        raw_slots = []  # list of dicts

        if grid_table:
            rows = grid_table.find_all("tr")
            count = 0
            current_day = ""

            for row in rows:
                cols = row.find_all("td")
                if not cols:
                    continue

                if count < 2:
                    # First two rows = start times and end times
                    if count == 0:
                        for col in cols:
                            timings.append({
                                "start": col.get_text(strip=True).replace("\t","").replace("\n",""),
                                "end": ""
                            })
                    elif count == 1:
                        for i, col in enumerate(cols):
                            if i < len(timings):
                                timings[i]["end"] = col.get_text(strip=True).replace("\t","").replace("\n","")
                    count += 1
                    continue

                if count in (2, 3):
                    # Skip rows 2,3 (header rows in grid)
                    count += 1
                    continue

                # Day data rows — alternating: even=has day label, odd=continuation
                if count % 2 == 0:
                    # Even row (after first 4): day label is first col
                    first_txt = cols[0].get_text(strip=True).replace("\t","").replace("\n","")
                    if first_txt in DAYS:
                        current_day = first_txt
                        data_cols = cols[1:]
                    else:
                        data_cols = cols
                else:
                    data_cols = cols

                # Parse each slot cell
                for idx, col in enumerate(data_cols):
                    cell = col.get_text(strip=True).replace("\t","").replace("\n","")
                    if len(cell) < 6 or "-" not in cell:
                        continue
                    # Format: "SLOT-CODE-TYPE-ROOM-BLOCK" or "SLOT-CODE-TYPE-ROOM-BLOCK-EXTRA"
                    parts = cell.split("-")
                    if len(parts) < 3:
                        continue
                    slot_name   = parts[0].strip()
                    course_code = parts[1].strip()
                    course_type = parts[2].strip()
                    room_no     = parts[3].strip() if len(parts) > 3 else ""
                    block       = " ".join(p.strip() for p in parts[4:6]) if len(parts) > 4 else ""

                    # Look up name
                    course_name = classname_code.get(course_code, "")
                    if not course_name:
                        # Try all codes for partial match
                        for k, v in classname_code.items():
                            if k == course_code:
                                course_name = v
                                break

                    # Look up class_nbr for faculty lookup
                    course_key = f"{course_code}_{course_type}"
                    class_nbr = course_to_class_nbr.get(course_key, "")
                    timing = timings[idx] if idx < len(timings) else {}

                    raw_slots.append({
                        "idx": idx,
                        "day": current_day,
                        "slot": slot_name,
                        "course_code": course_code,
                        "course_type": course_type,
                        "room_no": room_no,
                        "block": block,
                        "start_time": timing.get("start", ""),
                        "end_time": timing.get("end", ""),
                        "course_name": course_name,
                        "class_nbr": class_nbr,
                    })
                count += 1

        print(f"RAW SLOTS: {len(raw_slots)}")

        # ── Group consecutive slots of same course per day ──────────────────────
        from itertools import groupby

        # Group by (day, course_code, course_type)
        grouped = {}
        for s in raw_slots:
            key = (s["day"], s["course_code"], s["course_type"])
            grouped.setdefault(key, []).append(s)

        for (day, code, ctype), slots in grouped.items():
            if not slots or day not in timetable_data:
                continue
            slots_sorted = sorted(slots, key=lambda x: x["start_time"])

            # Build consecutive groups
            groups = []
            cur = [slots_sorted[0]]
            for s in slots_sorted[1:]:
                last = cur[-1]
                if last["end_time"] == s["start_time"] or last["start_time"] == s["start_time"]:
                    cur.append(s)
                else:
                    groups.append(cur)
                    cur = [s]
            groups.append(cur)

            for grp in groups:
                first = grp[0]
                last  = grp[-1]
                slot_combined = "+".join(s["slot"] for s in grp)
                course_key    = f"{code}_{ctype}"

                # Prefer slot/venue from first tbody lookup
                sv = course_to_slot_venue.get(course_key)
                final_slot  = sv[0] if sv else slot_combined
                final_venue = sv[1] if sv else f"{first['room_no']}-{first['block']}".strip("-")
                faculty     = faculty_code.get(first["class_nbr"], "")

                timetable_data[day].append({
                    "slot": final_slot,
                    "course_code": code,
                    "course_name": first["course_name"] or code,
                    "course_type": ctype,
                    "venue": final_venue,
                    "faculty": faculty,
                    "start_time": first["start_time"],
                    "end_time": last["end_time"],
                })

        # Sort each day by start_time
        for day in DAYS:
            timetable_data[day].sort(key=lambda x: x["start_time"])

        # Count total classes
        total = sum(len(v) for v in timetable_data.values())
        print(f"TIMETABLE CLASSES: {total}")

        return {
            "semester_id": sem_id,
            "timetable": timetable_data,
            "courses": [
                {"code": k, "name": v} for k, v in classname_code.items()
            ],
        }

    except HTTPException:
        raise
    except Exception as e:
        import traceback; traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))



# ============================
# MARKS

# ============================
@app.get("/marks")
def marks(sem_id: str = ""):
    try:
        csrf, auth_id = _get_auth()
        if not sem_id:
            sems = _get_semesters()
            sem_id = sems[0]["id"] if sems else ""

        r = session.post(
            f"{VTOP_BASE}/examinations/doStudentMarkView",
            data={"_csrf": csrf, "semesterSubId": sem_id, "authorizedID": auth_id},
            headers={**HEADERS, "Content-Type": "application/x-www-form-urlencoded"},
            verify=False,
        )
        if "login" in r.url.lower():
            raise HTTPException(status_code=401, detail="Session expired.")

        # Save debug
        with open("marks_debug.html", "w", encoding="utf-8") as f:
            f.write(r.text)

        soup = BeautifulSoup(r.text, "html.parser")
        
        if "This menu is not available" in r.text or "not available at present" in r.text:
            return {"semester_id": sem_id, "courses": [], "message": "VTOP has temporarily disabled the Marks menu.\nPlease check back later."}

        courses = []
        toggle = False

        for row in soup.select("tr.tableContent"):
            cols = row.find_all("td")
            if not toggle:
                if len(cols) >= 8:
                    course = {
                        "serial": cols[0].get_text(strip=True),
                        "course_code": cols[2].get_text(strip=True),
                        "course_title": cols[3].get_text(strip=True),
                        "course_type": cols[4].get_text(strip=True),
                        "faculty": cols[6].get_text(strip=True) if len(cols) > 6 else "",
                        "slot": cols[7].get_text(strip=True) if len(cols) > 7 else "",
                        "details": [],
                    }
            else:
                details = []
                for sub in cols[0].select("tr.tableContent-level1") if cols else []:
                    td = sub.find_all("td")
                    if len(td) >= 7:
                        details.append({
                            "title": td[1].get_text(strip=True),
                            "max": td[2].get_text(strip=True),
                            "weightage": td[3].get_text(strip=True),
                            "status": td[4].get_text(strip=True),
                            "scored": td[5].get_text(strip=True),
                            "weightage_mark": td[6].get_text(strip=True),
                        })
                course["details"] = details
                courses.append(course)
            toggle = not toggle

        return {"semester_id": sem_id, "courses": courses}

    except HTTPException:
        raise
    except Exception as e:
        import traceback; traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


# ============================
# GRADE HISTORY
# ============================
@app.get("/grade-history")
def grade_history():
    try:
        csrf, auth_id = _get_auth()

        r = session.post(
            f"{VTOP_BASE}/examinations/examGradeView/StudentGradeHistory",
            data={"_csrf": csrf, "authorizedID": auth_id, "verifyMenu": "true",
                  "nocache": str(int(time.time() * 1000))},
            headers={**HEADERS, "Content-Type": "application/x-www-form-urlencoded"},
            verify=False,
        )
        if "login" in r.url.lower():
            raise HTTPException(status_code=401, detail="Session expired.")

        with open("grade_history_debug.html", "w", encoding="utf-8") as f:
            f.write(r.text)

        soup = BeautifulSoup(r.text, "html.parser")
        semesters = []
        cgpa = ""

        # Try to find CGPA using column matching first
        for td in soup.find_all(["td", "th"]):
            txt = td.get_text(strip=True)
            if txt.upper() == "CGPA":
                table = td.find_parent("table")
                if table:
                    rows = table.find_all("tr")
                    try:
                        for r_idx, row in enumerate(rows):
                            headers = row.find_all(["td", "th"])
                            if td in headers:
                                idx = headers.index(td)
                                if r_idx + 1 < len(rows):
                                    next_row = rows[r_idx + 1]
                                    vals = next_row.find_all(["td", "th"])
                                    if idx < len(vals):
                                        val = vals[idx].get_text(strip=True)
                                        float(val)  # Verify it's a valid float
                                        cgpa = val
                                        break
                        if cgpa:
                            break
                    except Exception:
                        pass

        # Fallback to general label search if not found
        if not cgpa:
            for td in soup.find_all("td"):
                txt = td.get_text(strip=True)
                if "CGPA" in txt or "cgpa" in txt.lower():
                    nxt = td.find_next_sibling("td")
                    if nxt:
                        val = nxt.get_text(strip=True)
                        try:
                            float(val)
                            cgpa = val
                            break
                        except ValueError:
                            import re
                            match = re.search(r"\d+\.\d+", val)
                            if match:
                                cgpa = match.group(0)
                                break

        # Parse semester tables
        current_sem = None
        for row in soup.find_all("tr"):
            cols = row.find_all("td")
            if not cols:
                th = row.find_all("th")
                if th:
                    header = th[0].get_text(strip=True)
                    if any(kw in header.upper() for kw in ["SEMESTER", "SEM", "FALL", "WINTER", "SUMMER", "EFFECTIVE GRADES", "GRADE HISTORY"]):
                        current_sem = {"name": header, "sgpa": "", "credits": "", "courses": []}
                        semesters.append(current_sem)
                continue
            if len(cols) >= 6:
                sl_no = cols[0].get_text(strip=True)
                c_code = cols[1].get_text(strip=True)
                c_name = cols[2].get_text(strip=True)
                c_credits = cols[4].get_text(strip=True)
                c_grade = cols[5].get_text(strip=True)
                
                # Check if it's a valid course row
                if sl_no.isdigit() and c_code and any(char.isalpha() for char in c_code):
                    if current_sem is None:
                        current_sem = {"name": "Effective Grades", "sgpa": "", "credits": "", "courses": []}
                        semesters.append(current_sem)
                    
                    current_sem["courses"].append({
                        "code": c_code,
                        "name": c_name,
                        "credits": c_credits,
                        "grade": c_grade,
                    })

        return {"cgpa": cgpa, "semesters": semesters}

    except HTTPException:
        raise
    except Exception as e:
        import traceback; traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


# ============================
# EXAM SCHEDULE
# ============================
@app.get("/exam-schedule")
def exam_schedule(sem_id: str = ""):
    try:
        csrf, auth_id = _get_auth()
        if not sem_id:
            sems = _get_semesters()
            sem_id = sems[0]["id"] if sems else ""

        # Step 1: Initialize menu context
        session.post(
            f"{VTOP_BASE}/examinations/doSearchExamScheduleForStudent",
            data={
                "verifyMenu": "true",
                "authorizedID": auth_id,
                "_csrf": csrf,
                "nocache": str(int(time.time() * 1000))
            },
            headers={**HEADERS, "Content-Type": "application/x-www-form-urlencoded"},
            verify=False,
        )

        # Step 2: Fetch the actual exam schedule results
        r = session.post(
            f"{VTOP_BASE}/examinations/doSearchExamScheduleForStudent",
            data={
                "_csrf": csrf,
                "semesterSubId": sem_id,
                "authorizedID": auth_id
            },
            headers={**HEADERS, "Content-Type": "application/x-www-form-urlencoded"},
            verify=False,
        )
        # Save raw HTML response for debugging
        try:
            with open("exam_schedule_debug.html", "w", encoding="utf-8") as f:
                f.write(r.text)
        except Exception:
            pass

        if "login" in r.url.lower():
            raise HTTPException(status_code=401, detail="Session expired.")

        if "not available at present" in r.text or "This menu is not available" in r.text:
            return {"semester_id": sem_id, "exams": [], "message": "VTOP has temporarily disabled the Exam Schedule menu.\nPlease check back closer to exam time."}

        soup = BeautifulSoup(r.text, "html.parser")
        exam_groups = []
        current_group = {"type": "Exams", "subjects": []}
        
        for row in soup.find_all("tr"):
            cols = row.find_all("td")
            if len(cols) > 0 and len(cols) < 3:
                # It's an exam type header (e.g. CAT-1, FAT)
                if current_group["subjects"]:
                    exam_groups.append(current_group)
                current_group = {"type": cols[0].get_text(strip=True), "subjects": []}
            elif len(cols) >= 5:
                serial = cols[0].get_text(strip=True) if len(cols) > 0 else ""
                code = cols[1].get_text(strip=True) if len(cols) > 1 else ""
                name = cols[2].get_text(strip=True) if len(cols) > 2 else ""
                date = cols[6].get_text(strip=True) if len(cols) > 6 else "Not Announced"
                time_val = cols[9].get_text(strip=True) if len(cols) > 9 else (cols[8].get_text(strip=True) if len(cols) > 8 else "Not Announced")
                venue = cols[10].get_text(strip=True) if len(cols) > 10 else "Not Announced"
                seat = cols[12].get_text(strip=True) if len(cols) > 12 else ""

                current_group["subjects"].append({
                    "serial": serial,
                    "course_code": code,
                    "course_name": name,
                    "date": date,
                    "time": time_val,
                    "venue": venue,
                    "seat": seat,
                })

        if current_group["subjects"]:
            exam_groups.append(current_group)

        return {"semester_id": sem_id, "exam_groups": exam_groups, "message": None}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================
# ACADEMIC CALENDAR
# ============================
@app.get("/academic-calendar")
def academic_calendar(month_str: str = "", sem_id: str = ""):
    try:
        csrf, auth_id = _get_auth()
        if not sem_id:
            sems = _get_semesters()
            sem_id = sems[0]["id"] if sems else ""

        if not month_str:
            import datetime
            month_str = datetime.datetime.now().strftime("01-%b-%Y").upper()

        r = session.post(
            f"{VTOP_BASE}/processViewCalendar",
            data={
                "_csrf": csrf,
                "calDate": month_str,
                "semSubId": sem_id,
                "classGroupId": "COMB",
                "authorizedID": auth_id,
                "x": str(int(time.time() * 1000))
            },
            headers={**HEADERS, "Content-Type": "application/x-www-form-urlencoded"},
            verify=False,
        )
        if "login" in r.url.lower():
            raise HTTPException(status_code=401, detail="Session expired.")

        soup = BeautifulSoup(r.text, 'html.parser')
        month_header = soup.find('h4').text.strip() if soup.find('h4') else month_str
        events = []

        for td in soup.find_all('td'):
            spans = td.find_all('span')
            if not spans: continue
            day_num = spans[0].text.strip()
            if not day_num.isdigit(): continue
            
            event_text = ' '.join(s.text.strip() for s in spans[1:] if s.text.strip())
            if not event_text: continue

            etype = "Academic"
            title = event_text
            
            if "Holiday" in event_text:
                etype = "Holiday"
                title = event_text.replace("Holiday - General (Semester)", "").strip().strip("()")
                if not title: title = "Holiday"
            elif "Exam" in event_text:
                etype = "Exam"
            elif "Instructional Day" in event_text:
                title = "Instructional Day"
                
            # Filter out generic instructional days if desired, or keep them. Let's keep them so the calendar is populated!
            
            month_short = month_header[:3].title()
            year = month_header[-4:] if month_header[-4:].isdigit() else datetime.datetime.now().year
            
            events.append({
                'date': f'{month_short} {int(day_num):02d}, {year}',
                'title': title,
                'type': etype
            })

        return {"semester_id": sem_id, "month": month_header, "events": events}

    except HTTPException:
        raise
    except Exception as e:
        import traceback; traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

# ============================
# PROFILE
# ============================
@app.get("/profile")
def profile():
    try:
        csrf, auth_id = _get_auth()

        r = session.post(
            f"{VTOP_BASE}/studentsRecord/StudentProfileAllView",
            data={"_csrf": csrf, "authorizedID": auth_id,
                  "nocache": str(int(time.time() * 1000))},
            headers={**HEADERS, "Content-Type": "application/x-www-form-urlencoded"},
            verify=False,
        )
        if "login" in r.url.lower():
            raise HTTPException(status_code=401, detail="Session expired.")

        with open("profile_debug.html", "w", encoding="utf-8") as f:
            f.write(r.text)

        soup = BeautifulSoup(r.text, "html.parser")
        data = {}

        # Extract key-value pairs from profile table
        for row in soup.find_all("tr"):
            cols = row.find_all("td")
            if len(cols) >= 2:
                key = cols[0].get_text(strip=True).rstrip(":")
                val = cols[1].get_text(strip=True)
                if key and val:
                    data[key] = val

        # Extract photo URL if present
        img = soup.find("img", {"class": re.compile(r"profile|student|photo", re.I)})
        if img and img.get("src"):
            data["photo_url"] = img["src"]

        return {"profile": data}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================
# APPLY OUTINGS
# ============================
@app.post("/apply-general-outing")
def apply_general_outing(data: OutingApplyRequest):
    try:
        csrf, auth_id = _get_auth()
        # VTOP requires datetime in some requests, usually UTC string
        now_str = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")

        payload = {
            "_csrf": csrf,
            "x": now_str,
            "placeOfVisit": data.placeOfVisit,
            "purposeOfVisit": data.purposeOfVisit,
            "outDate": data.outDate,
            "inDate": data.inDate,
            "outTimeHr": data.outTimeHr,
            "outTimeMin": data.outTimeMin,
            "inTimeHr": data.inTimeHr,
            "inTimeMin": data.inTimeMin,
        }

        r = session.post(
            f"{VTOP_BASE}/hostel/saveGeneralOutingForm",
            data=payload,
            headers={**HEADERS, "Content-Type": "application/x-www-form-urlencoded"},
            verify=False,
        )
        if "login" in r.url.lower():
            raise HTTPException(status_code=401, detail="Session expired.")

        # If successful, it usually returns a new HTML or simple success string
        # Let's check for standard errors
        if "error" in r.text.lower() and "success" not in r.text.lower():
            return {"success": False, "message": "Failed to apply outing. Check constraints (e.g., 24h gap)."}

        return {"success": True, "message": "General Outing Applied Successfully"}

    except HTTPException:
        raise
    except Exception as e:
        import traceback; traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/apply-weekend-outing")
def apply_weekend_outing(data: OutingApplyRequest):
    try:
        csrf, auth_id = _get_auth()
        now_str = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")

        payload = {
            "_csrf": csrf,
            "x": now_str,
            "placeOfVisit": data.placeOfVisit,
            "purposeOfVisit": data.purposeOfVisit,
            "outDate": data.outDate,
            "inDate": data.inDate,
            "outTimeHr": data.outTimeHr,
            "outTimeMin": data.outTimeMin,
            "inTimeHr": data.inTimeHr,
            "inTimeMin": data.inTimeMin,
        }

        r = session.post(
            f"{VTOP_BASE}/hostel/saveWeekendOutingForm",
            data=payload,
            headers={**HEADERS, "Content-Type": "application/x-www-form-urlencoded"},
            verify=False,
        )
        if "login" in r.url.lower():
            raise HTTPException(status_code=401, detail="Session expired.")

        if "error" in r.text.lower() and "success" not in r.text.lower():
            return {"success": False, "message": "Failed to apply weekend outing. Check constraints."}

        return {"success": True, "message": "Weekend Outing Applied Successfully"}

    except HTTPException:
        raise
    except Exception as e:
        import traceback; traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

# ============================
# GENERAL OUTING
# ============================
@app.get("/general-outing")
def general_outing():
    csrf, auth_id = _get_auth()
    try:
        r = session.post(
            f"{VTOP_BASE}/hostel/StudentGeneralOuting",
            data={"_csrf": csrf, "authorizedID": auth_id, "verifyMenu": "true"},
            headers={**HEADERS, "Content-Type": "application/x-www-form-urlencoded"},
            verify=False,
        )
        
        if "This menu is not available" in r.text or "not available at present" in r.text:
            return {"outings": [], "message": "VTOP has temporarily disabled the Outing menu.\nPlease check back later."}

        with open("outing_debug.html", "w", encoding="utf-8") as f:
            f.write(r.text)
            
        # Parse actual outings
        soup = BeautifulSoup(r.text, "html.parser")
        outings = []
        table = soup.find("table", id="BookingRequests")
        if table:
            tbody = table.find("tbody")
            if tbody:
                for row in tbody.find_all("tr"):
                    cols = row.find_all("td")
                    if len(cols) >= 10:
                        place = cols[2].get_text(strip=True)
                        purpose = cols[3].get_text(strip=True)
                        from_date = cols[4].get_text(strip=True).split(' ')[0]
                        from_time = cols[5].get_text(strip=True)
                        to_date = cols[6].get_text(strip=True).split(' ')[0]
                        to_time = cols[7].get_text(strip=True)
                        status = cols[9].get_text(strip=True)
                        
                        leave_id = ""
                        if len(cols) > 10:
                            a_tag = cols[10].find("a")
                            if a_tag and a_tag.has_attr("data-url"):
                                leave_id = a_tag["data-url"].split("/")[-1]
                        
                        outings.append({
                            "date": f"{from_date}",
                            "destination": place,
                            "purpose": purpose,
                            "status": status,
                            "time": f"{from_time} - {to_time}",
                            "leave_id": leave_id
                        })

        return {"outings": outings, "message": None}
    except Exception as e:
        return {"outings": [], "message": str(e)}

@app.get("/download-outing")
def download_outing(leave_id: str, type: str = "general"):
    csrf, auth_id = _get_auth()
    try:
        if type == "weekend":
            url = f"{VTOP_BASE}/hostel/downloadOutingForm/{leave_id}?authorizedID={auth_id}&_csrf={csrf}"
        else:
            url = f"{VTOP_BASE}/hostel/downloadLeavePass/{leave_id}?authorizedID={auth_id}&_csrf={csrf}"
        r = session.get(url, verify=False)
        return Response(content=r.content, media_type="application/pdf", headers={
            "Content-Disposition": f"attachment; filename=outing_pass_{leave_id}.pdf"
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ============================
# WEEKEND OUTING
# ============================
@app.get("/weekend-outing")
def weekend_outing():
    csrf, auth_id = _get_auth()
    try:
        r = session.post(
            f"{VTOP_BASE}/hostel/StudentWeekendOuting",
            data={"_csrf": csrf, "authorizedID": auth_id, "verifyMenu": "true"},
            headers={**HEADERS, "Content-Type": "application/x-www-form-urlencoded"},
            verify=False,
        )
        
        if "This menu is not available" in r.text or "not available at present" in r.text:
            return {"outings": [], "message": "VTOP has temporarily disabled the Weekend Outing menu.\nPlease check back later."}

        soup = BeautifulSoup(r.text, "html.parser")
        outings = []
        table = soup.find("table", id="BookingRequests")
        if table:
            tbody = table.find("tbody")
            if tbody:
                for row in tbody.find_all("tr"):
                    cols = row.find_all("td")
                    # Support both 11-col and 14-col formats (weekday vs weekend)
                    if len(cols) >= 11:
                        is_weekend = len(cols) >= 14
                        place = cols[4].get_text(strip=True)
                        purpose = cols[5].get_text(strip=True)
                        time_str = cols[6].get_text(strip=True)
                        
                        date_idx = 9 if is_weekend else 7
                        status_idx = 12 if is_weekend else 9
                        download_idx = 13 if is_weekend else 10
                        
                        date_str = cols[date_idx].get_text(strip=True).split(' ')[0]
                        status = cols[status_idx].get_text(strip=True)
                        
                        leave_id = ""
                        if len(cols) > download_idx:
                            a_tag = cols[download_idx].find("a", {"data-leave-url": True})
                            if not a_tag:
                                a_tag = cols[download_idx].find("a", {"data-url": True})
                            
                            if a_tag:
                                url_attr = a_tag.get("data-leave-url") or a_tag.get("data-url")
                                if url_attr:
                                    leave_id = url_attr.split("/")[-1]
                        
                        outings.append({
                            "date": date_str,
                            "destination": place,
                            "purpose": purpose,
                            "status": status,
                            "time": time_str,
                            "leave_id": leave_id
                        })

        return {"outings": outings, "message": None}
    except Exception as e:
        return {"outings": [], "message": str(e)}


# ============================
# COURSE MATERIALS
# ============================

@app.get("/course-page/classes")
def course_classes(sem_id: str = ""):
    try:
        csrf, auth_id = _get_auth()
        if not sem_id:
            sems = _get_semesters()
            sem_id = sems[0]["id"] if sems else ""

        r = session.post(
            f"{VTOP_BASE}/academics/common/StudentCoursePage",
            data={
                "verifyMenu": "true",
                "authorizedID": auth_id,
                "_csrf": csrf,
                "nocache": str(int(time.time() * 1000))
            },
            headers={**HEADERS, "Content-Type": "application/x-www-form-urlencoded"},
            verify=False,
        )
        if "login" in r.url.lower():
            raise HTTPException(status_code=401, detail="Session expired.")

        # Save HTML response for debugging
        try:
            with open("course_page_debug.html", "w", encoding="utf-8") as f:
                f.write(r.text)
        except Exception:
            pass

        soup = BeautifulSoup(r.text, "html.parser")
        classes = []
        
        # Scrape registered courses table at the bottom of the page
        for row in soup.find_all("tr"):
            cols = row.find_all("td")
            if len(cols) >= 5:
                code = cols[1].get_text(strip=True)
                title = cols[2].get_text(strip=True)
                ctype = cols[3].get_text(strip=True)
                class_id = cols[4].get_text(strip=True)
                
                # Check if it has a class_id that starts with semSubId or matches length
                if class_id and len(class_id) > 5 and class_id.isalnum():
                    slot = cols[5].get_text(strip=True) if len(cols) > 5 else ""
                    faculty = cols[6].get_text(strip=True) if len(cols) > 6 else ""
                    
                    # Try to extract erpId from Javascript calls in View/Download button in this row
                    erp_id = ""
                    btn = row.find("a") or row.find("button")
                    if btn:
                        onclick = btn.get("onclick", "") or btn.get("href", "")
                        ids = re.findall(r"['\"]([^'\"]+)['\"]", onclick)
                        for arg in ids:
                            if arg.isdigit() and len(arg) >= 4:
                                erp_id = arg
                                break
                    
                    classes.append({
                        "course_code": code,
                        "course_name": title,
                        "course_type": ctype,
                        "class_id": class_id,
                        "slot": slot,
                        "faculty_name": faculty,
                        "erp_id": erp_id or "70792"
                    })

        return {"classes": classes}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/course-page/semesters")
def course_semesters():
    try:
        csrf, auth_id = _get_auth()
        r = session.post(
            f"{VTOP_BASE}/academics/common/StudentCoursePage",
            data={
                "verifyMenu": "true",
                "authorizedID": auth_id,
                "_csrf": csrf,
                "nocache": str(int(time.time() * 1000))
            },
            headers={**HEADERS, "Content-Type": "application/x-www-form-urlencoded"},
            verify=False,
        )
        if "login" in r.url.lower():
            raise HTTPException(status_code=401, detail="Session expired.")
        
        soup = BeautifulSoup(r.text, "html.parser")
        sel = soup.find("select", {"name": "semesterSubId"})
        sems = []
        if sel:
            for opt in sel.find_all("option"):
                v = opt.get("value", "").strip()
                if v:
                    sems.append({"id": v, "name": opt.text.strip()})
        return {"semesters": sems}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/course-page/courses")
def course_list(sem_id: str):
    try:
        csrf, auth_id = _get_auth()
        r = session.post(
            f"{VTOP_BASE}/getCourseForCoursePage",
            data={
                "_csrf": csrf,
                "paramReturnId": "getCourseForCoursePage",
                "semSubId": sem_id,
                "authorizedID": auth_id,
                "x": str(int(time.time() * 1000))
            },
            headers={
                **HEADERS,
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": f"{VTOP_BASE}/academics/common/StudentCoursePage"
            },
            verify=False,
        )
        try:
            with open("courses_debug.html", "w", encoding="utf-8") as f:
                f.write(r.text)
        except Exception:
            pass
        if "login" in r.url.lower():
            raise HTTPException(status_code=401, detail="Session expired.")
        
        soup = BeautifulSoup(r.text, "html.parser")
        sel = soup.find("select", {"id": "courseCode"}) or soup.find("select", {"name": "courseCode"}) or soup
        courses = []
        for opt in sel.find_all("option"):
            v = opt.get("value", "").strip()
            if v:
                courses.append({"id": v, "name": opt.text.strip()})
        return {"courses": courses}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/course-page/slots")
def course_slots(sem_id: str, class_id: str):
    try:
        csrf, auth_id = _get_auth()
        r = session.post(
            f"{VTOP_BASE}/getSlotIdForCoursePage",
            data={
                "_csrf": csrf,
                "classId": class_id,
                "praType": "source",
                "paramReturnId": "getSlotIdForCoursePage",
                "semSubId": sem_id,
                "authorizedID": auth_id,
                "x": str(int(time.time() * 1000))
            },
            headers={
                **HEADERS,
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": f"{VTOP_BASE}/academics/common/StudentCoursePage"
            },
            verify=False,
        )
        try:
            with open("slots_debug.html", "w", encoding="utf-8") as f:
                f.write(r.text)
        except Exception:
            pass
        if "login" in r.url.lower():
            raise HTTPException(status_code=401, detail="Session expired.")
        
        soup = BeautifulSoup(r.text, "html.parser")
        sel = soup.find("select", {"id": "slotId"}) or soup.find("select", {"name": "slotId"}) or soup
        slots = []
        for opt in sel.find_all("option"):
            v = opt.get("value", "").strip()
            if v:
                slots.append({"id": v, "name": opt.text.strip()})
        return {"slots": slots}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/course-page/faculties")
def course_faculties(sem_id: str, class_id: str, slot_id: str):
    try:
        csrf, auth_id = _get_auth()
        r = session.post(
            f"{VTOP_BASE}/getFacultyForCoursePage",
            data={
                "_csrf": csrf,
                "classId": class_id,
                "slotId": slot_id,
                "praType": "source",
                "paramReturnId": "getFacultyForCoursePage",
                "semSubId": sem_id,
                "authorizedID": auth_id,
                "x": str(int(time.time() * 1000))
            },
            headers={
                **HEADERS,
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": f"{VTOP_BASE}/academics/common/StudentCoursePage"
            },
            verify=False,
        )
        try:
            with open("faculties_debug.html", "w", encoding="utf-8") as f:
                f.write(r.text)
        except Exception:
            pass
        if "login" in r.url.lower():
            raise HTTPException(status_code=401, detail="Session expired.")
        
        soup = BeautifulSoup(r.text, "html.parser")
        sel = soup.find("select", {"id": "faculty"}) or soup.find("select", {"name": "faculty"}) or soup
        faculties = []
        for opt in sel.find_all("option"):
            v = opt.get("value", "").strip()
            if v:
                faculties.append({"id": v, "name": opt.text.strip()})
        return {"faculties": faculties}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/course-page/materials")
def course_materials(class_id: str, erp_id: str, sem_id: str = ""):
    try:
        csrf, auth_id = _get_auth()
        if not sem_id:
            sems = _get_semesters()
            sem_id = sems[0]["id"] if sems else ""

        # Resolve the actual class ID from the slot ID list (which lists all faculties and class IDs for this course)
        actual_class_id = class_id
        try:
            r_slots = session.post(
                f"{VTOP_BASE}/getSlotIdForCoursePage",
                data={
                    "_csrf": csrf,
                    "classId": class_id,
                    "praType": "source",
                    "paramReturnId": "getSlotIdForCoursePage",
                    "semSubId": sem_id,
                    "authorizedID": auth_id,
                    "x": str(int(time.time() * 1000))
                },
                headers={
                    **HEADERS,
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Referer": f"{VTOP_BASE}/academics/common/StudentCoursePage"
                },
                verify=False,
            )
            if r_slots.status_code == 200:
                soup_slots = BeautifulSoup(r_slots.text, "html.parser")
                for row in soup_slots.find_all("tr"):
                    btn = row.find("button", {"onclick": re.compile("processViewStudentCourseDetail")}) or \
                          row.find("a", {"onclick": re.compile("processViewStudentCourseDetail")})
                    if btn:
                        onclick = btn.get("onclick", "")
                        args = re.findall(r"['\"]([^'\"]+)['\"]", onclick)
                        if len(args) >= 3:
                            row_sem, row_erp, row_cid = args[0], args[1], args[2]
                            if row_erp == erp_id:
                                actual_class_id = row_cid
                                break
        except Exception:
            pass

        payload = {
            "_csrf": csrf,
            "semSubId": sem_id,
            "classId": actual_class_id,
            "erpId": erp_id,
            "authorizedID": auth_id,
            "x": str(int(time.time() * 1000))
        }

        r = session.post(
            f"{VTOP_BASE}/processViewStudentCourseDetail",
            data=payload,
            headers={
                **HEADERS,
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": f"{VTOP_BASE}/academics/common/StudentCoursePage"
            },
            verify=False,
        )
        if "login" in r.url.lower():
            raise HTTPException(status_code=401, detail="Session expired.")

        # Save HTML response for debugging
        try:
            with open("course_detail_debug.html", "w", encoding="utf-8") as f:
                f.write(r.text)
        except Exception:
            pass

        soup = BeautifulSoup(r.text, "html.parser")
        materials = []
        syllabus_id = ""

        # Check for syllabus download button
        syllabus_btn = soup.find("button", {"onclick": re.compile(r"courseSyllabusDownload|Syllabus", re.I)}) or \
                       soup.find("a", {"href": re.compile(r"courseSyllabusDownload|Syllabus", re.I)}) or \
                       soup.find("a", {"onclick": re.compile(r"courseSyllabusDownload|Syllabus", re.I)})
        if syllabus_btn:
            onclick = syllabus_btn.get("onclick", "") or syllabus_btn.get("href", "")
            args = re.findall(r"['\"]([^'\"]+)['\"]", onclick)
            if args:
                syllabus_id = args[0]

        # Parse materials tables
        for table in soup.find_all("table"):
            rows = table.find_all("tr")
            if not rows:
                continue
            
            # Find the header row if it exists
            header_row = rows[0]
            header_cols = header_row.find_all(["td", "th"])
            
            topic_idx = -1
            material_idx = -1
            
            for idx, col in enumerate(header_cols):
                text = col.get_text(strip=True).lower()
                if "topic" in text:
                    topic_idx = idx
                elif "material" in text or "download" in text:
                    material_idx = idx
            
            has_headers = (topic_idx != -1 and material_idx != -1)
            
            for row in rows:
                if has_headers and row == header_row:
                    continue
                
                cols = row.find_all("td")
                if not cols:
                    continue
                
                # Skip the table header if we didn't match has_headers but it contains headers
                first_col_text = cols[0].get_text(strip=True).lower()
                if "sl.no" in first_col_text or "class group" in first_col_text:
                    continue
                
                if has_headers:
                    if topic_idx < len(cols) and material_idx < len(cols):
                        topic = cols[topic_idx].get_text(strip=True)
                        links = cols[material_idx].find_all(["a", "button"])
                    else:
                        continue
                elif len(cols) == 2:
                    topic = cols[0].get_text(strip=True)
                    links = cols[1].find_all(["a", "button"])
                elif len(cols) >= 5:
                    topic = cols[-2].get_text(strip=True)
                    links = cols[-1].find_all(["a", "button"])
                else:
                    continue
                
                for link in links:
                    name = link.get_text(strip=True) or "Download Reference Material"
                    onclick = link.get("onclick", "") or link.get("href", "")
                    
                    args = re.findall(r"['\"]([^'\"]+)['\"]", onclick)
                    if args:
                        file_id = args[0]
                        if "allCourseMeterialDownload" in file_id:
                            continue
                        materials.append({
                            "topic": topic,
                            "name": name,
                            "file_id": file_id
                        })

        return {
            "syllabus_id": syllabus_id,
            "materials": materials
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/course-page/download")
def download_material(file_id: str):
    try:
        csrf, auth_id = _get_auth()
        params = {
            "authorizedID": auth_id,
            "_csrf": csrf,
            "x": str(int(time.time() * 1000))
        }

        # Make the authenticated request directly to that file URL on VTOP
        r = session.get(
            f"{VTOP_BASE}/{file_id}",
            params=params,
            headers=HEADERS,
            verify=False,
            stream=True
        )
        if "login" in r.url.lower():
            raise HTTPException(status_code=401, detail="Session expired.")

        content_type = r.headers.get("Content-Type", "application/octet-stream")
        content_disposition = r.headers.get("Content-Disposition", "")
        content_length = r.headers.get("Content-Length")
        
        headers = {
            "Content-Disposition": content_disposition,
        }
        if content_length:
            headers["Content-Length"] = content_length

        return StreamingResponse(
            r.iter_content(chunk_size=1024*8),
            media_type=content_type,
            headers=headers
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "8000"))
    reload = os.getenv("RELOAD", "1") == "1"
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=reload)
