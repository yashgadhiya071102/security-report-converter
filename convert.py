#!/usr/bin/env python3
"""
convert.py
Command-Line Interface (CLI) for Universal Security Scanner to PDF Converter.

Usage:
  python convert.py input_report.json -o output.pdf
  python convert.py input_report.html -o output.pdf
  python convert.py scan.json --failed-only --severity-threshold high -o executive.pdf
  python convert.py scan.json --title "Q3 AWS Security Audit" --company "Acme Corp" -o report.pdf
"""

import sys
import os
import argparse
from scanner_parser import parse_report_file
from pdf_generator import generate_security_pdf


def main():
    parser = argparse.ArgumentParser(
        description="Convert security scan reports (Prowler JSON/HTML, Trivy, Checkov, etc.) into executive PDF reports."
    )
    parser.add_argument("input", help="Path to input report file (.json, .html, .txt)")
    parser.add_argument("-o", "--output", help="Path to output PDF file (default: <input_basename>.pdf)")
    parser.add_argument("--title", default="Cloud Security Assessment Report", help="Custom report title")
    parser.add_argument("--company", default="Enterprise Cloud Security Audit", help="Organization / Client name")
    parser.add_argument("--assessor", default="Security Automation Team", help="Assessor or Team name")
    parser.add_argument("--all", dest="failed_only", action="store_false", default=True,
                        help="Include all findings (default is failed findings only)")
    parser.add_argument("--severity-threshold", default="all",
                        choices=["all", "low", "medium", "high", "critical"],
                        help="Minimum severity threshold to include")
    parser.add_argument("--max-findings", type=int, default=None,
                        help="Maximum detailed findings to include in report")
    parser.add_argument("--summary-only", action="store_true",
                        help="Only generate executive summary without detailed findings")

    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"Error: Input file '{args.input}' not found.", file=sys.stderr)
        sys.exit(1)

    output_path = args.output
    if not output_path:
        base, _ = os.path.splitext(args.input)
        output_path = f"{base}_report.pdf"

    print(f"\n========================================================")
    print(f"  Universal Security Report to PDF Converter")
    print(f"========================================================")
    print(f"[*] Reading input file: {args.input}")

    try:
        scan_report = parse_report_file(args.input)
    except Exception as e:
        print(f"[!] Error parsing report: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"[+] Total Checks Evaluated: {scan_report.total_checks}")
    print(f"[+] Passed: {scan_report.passed_checks} | Failed: {scan_report.failed_checks}")
    print(f"[+] Security Score: {scan_report.security_score}% ({scan_report.security_grade} - {scan_report.posture_text})")
    print(f"[+] Failed Severity: Critical: {scan_report.severity_counts['critical']}, "
          f"High: {scan_report.severity_counts['high']}, "
          f"Medium: {scan_report.severity_counts['medium']}, "
          f"Low: {scan_report.severity_counts['low']}")

    if scan_report.top_failed_services:
        top_srv_str = ", ".join([f"{s['service'].upper()} ({s['fail_count']})" for s in scan_report.top_failed_services[:4]])
        print(f"[+] Top Failing Services: {top_srv_str}")

    config = {
        "report_title": args.title,
        "company_name": args.company,
        "assessor_name": args.assessor,
        "failed_only": args.failed_only,
        "severity_threshold": args.severity_threshold,
        "max_findings": 0 if args.summary_only else args.max_findings
    }

    print(f"[*] Generating PDF report with vector charts...")
    try:
        generate_security_pdf(scan_report, output_path, config)
        print(f"[SUCCESS] PDF Report successfully generated at:")
        print(f"          -> {os.path.abspath(output_path)}")
        file_size_kb = round(os.path.getsize(output_path) / 1024, 1)
        print(f"          Size: {file_size_kb} KB\n")
    except Exception as e:
        print(f"[!] Error building PDF: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
