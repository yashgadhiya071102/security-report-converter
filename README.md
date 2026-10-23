# Security Report → PDF Converter

Converts security scanner reports into an executive PDF. Works as a **web app** and a **CLI**.

**Inputs:** Prowler JSON (legacy, v4/v5 OCSF, NDJSON), Prowler HTML, Trivy JSON, Checkov JSON, generic JSON/HTML finding tables.

## Run locally

```bash
pip install -r requirements.txt
python app.py                 # web UI at http://127.0.0.1:5000
```
Windows: double-click `run.bat`.

## CLI

```bash
python convert.py report.json -o report.pdf
python convert.py report.html -o report.pdf
python convert.py scan.json --failed-only --severity-threshold high --title "Q3 AWS Audit" --company "Acme" -o out.pdf
```

## Deploy (DevOps)

| Item | Value |
|---|---|
| Python | 3.10+ (image uses 3.12) |
| Install | `pip install -r requirements.txt` (pure Python, no system packages needed) |
| Start | `python app.py --no-browser` |
| Port | `PORT` env var (default `5000`) |
| Bind address | `HOST` env var (default `127.0.0.1`; **set `0.0.0.0` on a server**) |
| Upload limit | `MAX_UPLOAD_MB` env var (default `50`) |
| Health check | `GET /api/health` → `{"status":"ok"}` |
| Secrets / DB / storage | None. Stateless; PDFs are generated in memory/temp and deleted |

### Docker
```bash
docker build -t security-report-converter .
docker run -p 5000:5000 security-report-converter
```

### Notes
- The server is Python's built-in `http.server`. For internal use behind a reverse proxy (nginx / ALB) it's fine; put TLS and authentication on the proxy. There is **no built-in login**.
- The web UI loads **Chart.js and Google Fonts from CDNs** (`index.html`). If the host has no internet access, the dashboard charts/fonts won't load (PDF generation is unaffected, it's server-side). Vendor these files into `web/` for air-gapped hosting.

## Layout
```
app.py              web server + REST API (/api/parse, /api/generate-pdf, /api/sample, /api/health)
convert.py          CLI
scanner_parser.py   parsers/normalizers (Prowler, Trivy, Checkov, HTML tables)
pdf_generator.py    PDF builder (reportlab)
web/                dashboard UI
samples/            example inputs
```
