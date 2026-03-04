# FileCipher

FileCipher is a simple way to send files between devices using a short access code.

Instead of sharing a direct file link, you upload a file, set a code, and share only that code with the receiver. It is built for quick, private transfers with a lightweight Flask stack.

## What it does

- Upload any file type
- Share files using a custom code
- Download files from another device using that code
- Basic brute-force protection on code attempts
- Admin stats page for upload/download activity

## Project structure

```txt
FileCipher/
├── app/                 # Flask app package (routes, templates, static, services)
├── run.py               # Local development entrypoint
├── wsgi.py              # Production WSGI entrypoint
├── requirements.txt
└── database.db          # SQLite database (generated/used at runtime)
```

## Prerequisites

- Python 3.10+
- `pip`

## Quick start (local)

1. Clone and enter the project:
   ```bash
   cd /path/to/FileCipher
   ```
2. Create a virtual environment:
   ```bash
   python3 -m venv venv
   ```
3. Activate it:
   ```bash
   source venv/bin/activate
   ```
4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
5. Start the app:
   ```bash
   python run.py
   ```
6. Open in browser:
   - http://127.0.0.1:5000

## Notes

- Uploaded image files are stored in `app/media/`.
- The app uses SQLite by default (`database.db`).
