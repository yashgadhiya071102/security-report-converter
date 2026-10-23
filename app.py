"""
app.py
Lightweight, zero-dependency local web server & REST API for the
Universal Security Scanner Report to PDF Converter.

Endpoints:
- GET /                    -> Serves web dashboard UI (web/index.html)
- GET /styles.css          -> Serves styling
- GET /app.js              -> Serves frontend application logic
- GET /api/sample          -> Returns sample scanner reports (AWS, Azure, HTML)
- POST /api/parse          -> Parses raw JSON or HTML content and returns normalized findings & metrics
- POST /api/generate-pdf   -> Converts report to downloadable executive PDF binary
"""

import os
import sys
import json
import urllib.parse
import tempfile
import webbrowser
import mimetypes
import re
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

from scanner_parser import parse_json_content, parse_html_content, ScanReport, decode_bytes
from pdf_generator import generate_security_pdf

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(BASE_DIR, "web")
SAMPLES_DIR = os.path.join(BASE_DIR, "samples")
MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_MB", "50")) * 1024 * 1024


def _safe_filename(name, default="security_assessment_report.pdf"):
    """Strip anything that could break / inject into the Content-Disposition header."""
    name = re.sub(r"[^A-Za-z0-9._ -]", "_", str(name or "")).strip(" .")
    if not name:
        name = default
    if not name.lower().endswith(".pdf"):
        name += ".pdf"
    return name


class ConverterServerHandler(BaseHTTPRequestHandler):
    def _send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        self.wfile.write(body)

    def _send_error_json(self, message, status=400):
        self._send_json({"error": True, "message": str(message)}, status=status)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        query = urllib.parse.parse_qs(parsed_url.query)

        # Health check
        if path == "/api/health":
            return self._send_json({"status": "ok", "app": "Security Report to PDF Converter"})

        # Sample data loader
        if path == "/api/sample":
            sample_type = query.get("type", ["aws"])[0].lower()
            file_map = {
                "aws": "prowler_aws_sample.json",
                "azure": "prowler_azure_sample.json",
                "html": "prowler_sample_report.html"
            }
            target_name = file_map.get(sample_type, "prowler_aws_sample.json")
            sample_path = os.path.join(SAMPLES_DIR, target_name)
            if not os.path.exists(sample_path):
                return self._send_error_json(f"Sample {sample_type} not found", 404)

            try:
                with open(sample_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                if target_name.endswith(".html"):
                    report = parse_html_content(content)
                else:
                    report = parse_json_content(content)

                return self._send_json({
                    "success": True,
                    "sample_type": sample_type,
                    "raw_content": content,
                    "report": report.to_dict()
                })
            except Exception as e:
                return self._send_error_json(str(e), 500)

        # Static Web Files
        rel_path = path.lstrip("/")
        if not rel_path or rel_path == "":
            rel_path = "index.html"

        file_path = os.path.realpath(os.path.join(WEB_DIR, urllib.parse.unquote(rel_path)))
        web_root = os.path.realpath(WEB_DIR)
        if file_path != web_root and not file_path.startswith(web_root + os.sep):
            self.send_response(403)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"403 Forbidden")
            return
        if os.path.exists(file_path) and os.path.isfile(file_path):
            mime_type, _ = mimetypes.guess_type(file_path)
            if not mime_type:
                mime_type = "application/octet-stream"
            if mime_type.startswith("text/") or mime_type in ["application/javascript", "application/json"]:
                mime_type += "; charset=utf-8"

            try:
                with open(file_path, "rb") as f:
                    body = f.read()
                self.send_response(200)
                self.send_header("Content-Type", mime_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                self.wfile.write(body)
                return
            except Exception as e:
                return self._send_error_json(f"Failed to read file: {e}", 500)

        self.send_response(404)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"404 Not Found")

    def do_POST(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            return self._send_error_json("Invalid Content-Length")
        if content_length <= 0:
            return self._send_error_json("Empty request payload")
        if content_length > MAX_UPLOAD_BYTES:
            return self._send_error_json(
                f"File too large (limit {MAX_UPLOAD_BYTES // (1024 * 1024)} MB)", 413)

        raw_data = self.rfile.read(content_length)

        # Endpoint 1: Parse content
        if path == "/api/parse":
            try:
                try:
                    payload = json.loads(raw_data.decode("utf-8"))
                    content_str = payload.get("content", "")
                    filename = payload.get("filename", "")
                except Exception:
                    content_str = decode_bytes(raw_data)
                    filename = ""

                if filename.lower().endswith(".html") or filename.lower().endswith(".htm") or "<html" in content_str[:200].lower():
                    report = parse_html_content(content_str)
                else:
                    report = parse_json_content(content_str)

                return self._send_json({
                    "success": True,
                    "report": report.to_dict()
                })
            except Exception as e:
                return self._send_error_json(f"Parse error: {e}", 400)

        # Endpoint 2: Generate PDF
        if path == "/api/generate-pdf":
            try:
                payload = json.loads(raw_data.decode("utf-8"))
                report_dict = payload.get("report")
                raw_content = payload.get("content")
                config = payload.get("config", {})

                if report_dict and "findings" in report_dict:
                    report = ScanReport(report_dict.get("findings", []), report_dict.get("metadata", {}))
                elif raw_content:
                    if "<html" in raw_content[:200].lower():
                        report = parse_html_content(raw_content)
                    else:
                        report = parse_json_content(raw_content)
                else:
                    return self._send_error_json("No report data provided")

                # Generate to temporary PDF file (always cleaned up)
                with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp_file:
                    tmp_pdf_path = tmp_file.name
                try:
                    generate_security_pdf(report, tmp_pdf_path, config)
                    with open(tmp_pdf_path, "rb") as f:
                        pdf_bytes = f.read()
                finally:
                    try:
                        os.remove(tmp_pdf_path)
                    except OSError:
                        pass

                self.send_response(200)
                self.send_header("Content-Type", "application/pdf")
                self.send_header("Content-Length", str(len(pdf_bytes)))
                filename = _safe_filename(config.get("filename"))
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(pdf_bytes)
                return
            except Exception as e:
                import traceback
                traceback.print_exc()
                return self._send_error_json(f"PDF generation error: {e}", 500)

        return self._send_error_json("Endpoint not found", 404)


def run_server(port=5000, host="127.0.0.1", open_browser=False):
    server_address = (host, port)
    try:
        httpd = ThreadingHTTPServer(server_address, ConverterServerHandler)
    except OSError:
        if os.environ.get("PORT"):
            raise  # hosted deployment: never silently move to a different port
        # Local use: fall back to an alternate port if the default is occupied
        port = 8080
        server_address = (host, port)
        httpd = ThreadingHTTPServer(server_address, ConverterServerHandler)

    url = f"http://{host}:{port}"
    print(f"\n=======================================================")
    print(f"  Security Scanner Report to PDF Converter Web Server")
    print(f"=======================================================")
    print(f"[*] Server running at: {url}")
    print(f"[*] Web UI Dashboard:   {url}")
    print(f"[*] API Parse Endpoint: {url}/api/parse")
    print(f"[*] API PDF Generator:  {url}/api/generate-pdf")
    print(f"=======================================================\n")

    if open_browser:
        webbrowser.open(url)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        httpd.server_close()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Start Security Report to PDF Web Application")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", 5000)),
                        help="Port to listen on (default: $PORT or 5000)")
    parser.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"),
                        help="Host address (default: $HOST or 127.0.0.1; use 0.0.0.0 on a server)")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically open browser")
    args = parser.parse_args()

    run_server(port=args.port, host=args.host, open_browser=not args.no_browser)
