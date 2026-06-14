# HookD — Social Engineering & Phishing Detection

A Flask web app that detects phishing / social-engineering in **text, URLs, and images**
(via OCR) using an ML model plus a rule-based forensics engine.

Runs **fully offline** — accounts and scan history are stored in a local **SQLite** file
(`hookd.db`). No internet or external services required, which makes it ideal for an exhibit.

---

## Get the code (Git LFS required!)

The trained model is stored with **Git LFS**, so you must have it installed or you'll
only get a placeholder file and the app will fail to load the model.

```bash
git lfs install            # one-time, from https://git-lfs.com
git clone https://github.com/rehbyte/HookD-Social-Engineering-Web-Detection
cd HookD-Social-Engineering-Web-Detection
git checkout offline-exhibit
git lfs pull               # pulls the real model .pkl
```

## Run it

```bash
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000. Sign up for a local account, log in, and scan.
Data is stored locally in `hookd.db` (created automatically on first run).

Image scanning needs the **Tesseract OCR** binary (pip can't install this):
- **Windows:** install Tesseract; auto-detected at `C:\Program Files\Tesseract-OCR\tesseract.exe`
- **Linux:** `sudo apt install tesseract-ocr`

(Text and URL scanning work without Tesseract.)

## Configuration (optional, via `.env`)

Copy `.env.example` to `.env`. All values have sensible defaults.

| Variable | Purpose | Default |
|---|---|---|
| `SECRET_KEY` | Flask session signing key | insecure dev key |
| `DEV_MODE` | `1` = skip login (instant guest demo); `0` = local accounts | `0` |
| `FLASK_DEBUG` | `1` = debug (local only) | `0` |
| `DATABASE_PATH` | SQLite file location | `./hookd.db` |
| `TESSERACT_CMD` | explicit Tesseract path | auto-detect |

---

## Exhibit setup — let phones use it with NO internet

Run the app on the laptop and have the laptop broadcast its own Wi-Fi hotspot.
Phones join that hotspot and reach the laptop directly — fully offline.

### 1. Turn on the laptop's hotspot
Windows: **Settings → Network & Internet → Mobile hotspot → On.**
The laptop's address is normally a **fixed** `192.168.137.1`, so the QR stays valid.

### 2. Allow the app through the firewall (first time only)
Windows may prompt when you start the app — click **Allow** on Private networks.
(Port 5000 inbound must be allowed for phones to connect.)

### 3. Start the app
```bash
python app.py
```
It listens on `0.0.0.0:5000`, so it's reachable at `http://192.168.137.1:5000`.

### 4. Make the QR code
```bash
pip install "qrcode[pil]"
python make_qr.py http://192.168.137.1:5000
```
Produces `hookd_qr.png` — print it and place it at the booth. Visitors connect their
phone to the laptop's hotspot, scan the QR, and use HookD.

> Tip: confirm your hotspot IP with `ipconfig` (look for the "Mobile hotspot" adapter)
> in case your machine uses a different address.

---

## Project structure
- `app.py` — Flask routes + local auth
- `database.py` — SQLite storage (users, scan history) with hashed passwords
- `ml_engine/` — model + feature engine + forensics scanner
- `utils/` — OCR, email parsing, DNS verification, preprocessing
- `templates/` + `static/` — frontend
- `make_qr.py` — generate the booth QR code
