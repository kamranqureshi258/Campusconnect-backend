# CampusConnect Backend — Deploy (24/7)

This folder is a FastAPI backend. To make the mobile app work **anywhere, anytime** (even if your PC is off), deploy this backend to a cloud host and use the provided **HTTPS** URL in the app’s settings.

## Render (free / easy)

1. Push this `campusconnect-backend/` folder to a GitHub repository.
2. In Render: create **New → Web Service** and select the repo.
3. Settings:
   - **Runtime**: Python
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`
4. Deploy. Render will give you a URL like `https://your-app.onrender.com`

## Railway (also easy)

1. Push to GitHub, then create a new Railway project from the repo.
2. Set start command to:
   - `uvicorn main:app --host 0.0.0.0 --port $PORT`
3. Railway will provide a public URL (HTTPS).

## Use the URL in the phone app

Open the app → tap the **gear icon** → set **Server URL** to your cloud URL, e.g.:

`https://your-app.onrender.com`

## Local dev (optional)

```bash
python main.py
```

If you want to serve assets in local dev, set:

```bash
set ASSETS_DIR=C:\Users\qures\campusconnect\assets
python main.py
```

