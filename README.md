# HookD — Social-Engineering / Phishing Web Detection

A Flask web app that detects phishing & social-engineering content in **text,
URLs, and images** (via OCR) using a machine-learning engine.

## Local-first database (no internet required)

This project uses a **local SQLite database** (`hookd.db`), so it runs fully
offline — ideal for presentations where internet may be unreliable. The
database file is created automatically the first time you run the app, and is
seeded with a demo account and sample scan history.

> Previously the app used Supabase (a cloud service). That has been replaced
> entirely; no API keys or internet connection are needed.

The **front-end is also fully offline**: Bootstrap, the Lucide icons, and the
fonts (Space Grotesk, JetBrains Mono, Inter) are vendored into `static/vendor`
and `static/fonts`, so the UI renders correctly with no internet during a
presentation. Shared design tokens, fonts, and motion live in
`static/css/theme.css`.

### Demo login (auto-created)

| Email            | Password  |
| ---------------- | --------- |
| `demo@hookd.com` | `demo123` |

You can also create your own account from the **Sign Up** page — accounts are
stored locally with PBKDF2-hashed passwords.

## Get the code (Git LFS required!)

The trained model (`OLD BACKEND/Phish_Model_Advanced.pkl`) is stored with
**Git LFS**. Install it first, or you'll only get a placeholder file and the
model won't load.

```bash
git lfs install            # one-time, from https://git-lfs.com
git clone https://github.com/rehbyte/HookD-Social-Engineering-Web-Detection
cd HookD-Social-Engineering-Web-Detection
git lfs pull               # pulls the real model .pkl
```

## Setup

1. (Recommended) create a virtual environment:
   ```bash
   python -m venv venv
   venv\Scripts\activate        # Windows
   # source venv/bin/activate   # macOS/Linux
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Install the **Tesseract OCR** engine (needed for image scanning):
   - Windows: https://github.com/UB-Mannheim/tesseract/wiki
4. Run the app:
   ```bash
   python app.py
   ```
   Then open http://127.0.0.1:5000 in your browser.

## Account & history management

- **Edit profile** — change your first/last name from the Profile page.
- **Change password** — set a new password (requires your current one) from
  the Profile page.
- **Clear history** — wipe all of your scans at once via the "Clear All
  History" button on the History page.

## Configuration (optional, via `.env`)

Copy `.env.example` to `.env`. All values have sensible defaults.

| Variable | Purpose | Default |
| --- | --- | --- |
| `SECRET_KEY` | Flask session signing key | insecure dev key |
| `DEV_MODE` | `1` = skip login (instant guest demo); `0` = local accounts | `0` |
| `FLASK_DEBUG` | `1` = debug mode (local only) | `0` |
| `PORT` | port the server listens on | `5000` |
| `DATABASE_PATH` | SQLite file location | `./hookd.db` |
| `TESSERACT_CMD` | explicit Tesseract path | auto-detect |

## Model performance (Metrics page)

The **Results** page (`/metrics`) shows the model's accuracy, precision, recall,
F1, confusion matrix, and baseline comparison, read from `results.json`.
To regenerate it against the current engine:

```bash
python test_agent.py ground_truth_200.csv
```

## Exhibit / booth mode

- Set `DEV_MODE=1` in `.env` for an instant no-login guest demo.
- Generate a QR code that links to the running app (e.g. for phones on the same
  network):
  ```bash
  python make_qr.py http://<your-laptop-ip>:5000
  ```

## Resetting the data

To start from a clean slate (e.g. before a demo), just delete `hookd.db` and
restart the app — it will recreate the tables and re-seed the demo data.

## Project structure

```
app.py            Flask routes (auth, scanning, history, profile)
database.py       Local SQLite layer + local authentication
ml_engine/        Phishing detection model & feature engineering
utils/            OCR, email parsing, DNS checks, security filters
templates/        HTML pages
static/           CSS, JS, uploaded images
whitelist.json    Trusted senders/domains used by the scanner
```
