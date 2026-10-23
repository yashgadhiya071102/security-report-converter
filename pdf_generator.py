"""
pdf_generator.py
State-of-the-art PDF report generator for security scanner reports.
Generates an executive-ready, highly styled PDF with:
- Professional cover page with Security Posture Score & key metrics
- Executive Summary & visual analytics (Severity pie/donut chart, Services bar chart)
- Compliance Framework Alignment Matrix (CIS, NIST, ISO 27001, etc.)
- Actionable priority remediation quick-wins
- Detailed findings breakdown with code remediation snippets
- Running headers, footers, page numbering ("Page X of Y"), and confidentiality notices.
"""

import os
import html
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas
from reportlab.graphics.shapes import Drawing, Rect, String, Group, Circle, Line
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import HorizontalBarChart
from reportlab.graphics.charts.legends import Legend


# ==========================================
# Color Palette
# ==========================================
PRIMARY = colors.HexColor('#0F172A')       # Slate 900
PRIMARY_LIGHT = colors.HexColor('#1E293B') # Slate 800
ACCENT = colors.HexColor('#2563EB')        # Blue 600
ACCENT_LIGHT = colors.HexColor('#EFF6FF')  # Blue 50
TEXT_MAIN = colors.HexColor('#1E293B')     # Slate 800
TEXT_MUTED = colors.HexColor('#64748B')    # Slate 500
BORDER_COLOR = colors.HexColor('#E2E8F0')  # Slate 200
BG_LIGHT = colors.HexColor('#F8FAFC')      # Slate 50

# Severity Colors
COLOR_CRITICAL = colors.HexColor('#DC2626') # Red 600
BG_CRITICAL = colors.HexColor('#FEE2E2')
COLOR_HIGH = colors.HexColor('#EA580C')     # Orange 600
BG_HIGH = colors.HexColor('#FFEDD5')
COLOR_MEDIUM = colors.HexColor('#D97706')   # Amber 600
BG_MEDIUM = colors.HexColor('#FEF3C7')
COLOR_LOW = colors.HexColor('#2563EB')      # Blue 600
BG_LOW = colors.HexColor('#DBEAFE')
COLOR_INFO = colors.HexColor('#475569')     # Slate 600
BG_INFO = colors.HexColor('#F1F5F9')

# Status Colors
COLOR_FAIL = colors.HexColor('#DC2626')
BG_FAIL = colors.HexColor('#FEE2E2')
COLOR_PASS = colors.HexColor('#16A34A')
BG_PASS = colors.HexColor('#DCFCE7')
COLOR_MUTED = colors.HexColor('#D97706')
BG_MUTED = colors.HexColor('#FEF3C7')


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas to dynamically compute and print total page count ('Page X of Y')."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        # Cover page (page 1) decoration
        if self._pageNumber == 1:
            # Decorative top bar
            self.setFillColor(ACCENT)
            self.rect(0, 835, 595.27, 7, fill=1, stroke=0)
            self.restoreState()
            return

        # Running Header (pages >= 2)
        self.setFont('Helvetica-Bold', 8)
        self.setFillColor(TEXT_MUTED)
        self.drawString(36, 815, "CLOUD SECURITY ASSESSMENT REPORT")
        self.setFont('Helvetica', 8)
        self.drawRightString(559, 815, "CONFIDENTIAL")
        self.setStrokeColor(BORDER_COLOR)
        self.setLineWidth(0.6)
        self.line(36, 808, 559, 808)

        # Running Footer
        self.line(36, 45, 559, 45)
        self.setFont('Helvetica', 8)
        self.setFillColor(TEXT_MUTED)
        self.drawString(36, 32, "Security Assessment Report • Generated via Universal Scanner Converter")
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(559, 32, page_str)
        self.restoreState()


def _esc(text):
    """Escapes HTML entities safely for ReportLab Paragraphs."""
    if not text:
        return ""
    return html.escape(str(text), quote=False)


def _wrap_safe(text):
    """Escapes HTML entities safely for ReportLab Paragraphs.

    NOTE: long tokens (ARNs, check IDs) are wrapped by ReportLab itself
    (ParagraphStyle.splitLongWords). Do NOT insert zero-width spaces here: the
    built-in PDF fonts have no glyph for U+200B, so they render as black boxes.
    """
    if not text:
        return ""
    return html.escape(str(text), quote=False)


def generate_security_pdf(scan_report, output_pdf_path, config=None):
    """
    Builds the complete multi-page PDF from a ScanReport object.
    config: dict with optional keys:
      - report_title: str
      - company_name: str
      - assessor_name: str
      - failed_only: bool (default True)
      - severity_threshold: str ('all', 'low', 'medium', 'high', 'critical')
      - max_findings: int (limit detailed findings count, None = all)
    """
    if config is None:
        config = {}

    report_title = config.get("report_title", "Cloud Security Assessment Report")
    company_name = config.get("company_name", "Enterprise Security Audit")
    assessor_name = config.get("assessor_name", "Security Automation Team")
    failed_only = config.get("failed_only", True)
    severity_threshold = config.get("severity_threshold", "all").lower()
    max_findings = config.get("max_findings", None)

    # ==========================================
    # VALIDATION
    # ==========================================
    v_total = scan_report.passed_checks + scan_report.failed_checks + getattr(scan_report, 'manual_checks', 0) + scan_report.muted_checks + scan_report.info_checks
    if scan_report.total_checks != v_total:
        raise ValueError(f"Validation failed: total_checks ({scan_report.total_checks}) != sum of statuses ({v_total})")
    
    v_sev_fails = sum(scan_report.severity_counts.values())
    if scan_report.failed_checks != v_sev_fails:
        raise ValueError(f"Validation failed: failed_checks ({scan_report.failed_checks}) != sum of severity_counts ({v_sev_fails})")

    # Document setup
    doc = SimpleDocTemplate(
        output_pdf_path,
        pagesize=A4,
        leftMargin=36,
        rightMargin=36,
        topMargin=42,
        bottomMargin=48
    )

    content = []
    base_styles = getSampleStyleSheet()

    # Custom Typography Styles
    title_style = ParagraphStyle(
        'CoverTitle',
        parent=base_styles['Title'],
        fontName='Helvetica-Bold',
        fontSize=26,
        leading=32,
        textColor=PRIMARY,
        alignment=0,
        spaceAfter=6
    )

    subtitle_style = ParagraphStyle(
        'CoverSubtitle',
        parent=base_styles['Normal'],
        fontName='Helvetica',
        fontSize=13,
        leading=17,
        textColor=ACCENT,
        spaceAfter=18
    )

    h1_style = ParagraphStyle(
        'SectionH1',
        parent=base_styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=16,
        leading=20,
        textColor=PRIMARY,
        spaceBefore=14,
        spaceAfter=10,
        keepWithNext=True
    )

    h2_style = ParagraphStyle(
        'SectionH2',
        parent=base_styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=PRIMARY_LIGHT,
        spaceBefore=10,
        spaceAfter=6,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        'ReportBody',
        parent=base_styles['BodyText'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=14,
        textColor=TEXT_MAIN,
        spaceAfter=6
    )

    meta_label = ParagraphStyle(
        'MetaLabel',
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=11,
        textColor=TEXT_MUTED
    )

    meta_val = ParagraphStyle(
        'MetaValue',
        fontName='Helvetica',
        fontSize=9.5,
        leading=13,
        textColor=PRIMARY
    )

    code_style = ParagraphStyle(
        'CodeSnippet',
        fontName='Courier',
        fontSize=7.8,
        leading=11,
        textColor=colors.HexColor('#0F172A'),
        backColor=colors.HexColor('#F1F5F9'),
        borderColor=colors.HexColor('#CBD5E1'),
        borderWidth=0.6,
        borderPadding=6,
        spaceBefore=4,
        spaceAfter=4,
        borderRadius=3
    )

    badge_style = ParagraphStyle(
        'BadgeText',
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10,
        alignment=1
    )

    # ==========================================
    # PAGE 1: COVER & EXECUTIVE SUMMARY
    # ==========================================
    content.append(Spacer(1, 10))
    content.append(Paragraph(_esc(company_name.upper()), ParagraphStyle(
        'OrgHeader', fontName='Helvetica-Bold', fontSize=10, leading=12, textColor=ACCENT, spaceAfter=8
    )))
    content.append(Paragraph(_esc(report_title), title_style))
    content.append(Paragraph("Technical Security Assessment, Compliance Audit & Actionable Remediations", subtitle_style))
    content.append(HRFlowable(width="100%", thickness=1.5, color=ACCENT, spaceBefore=0, spaceAfter=18))

    # Meta Overview Box
    prov = scan_report.metadata.get("provider", "Cloud Infrastructure")
    acc = scan_report.metadata.get("account_id", "Default Scope")
    scanner = scan_report.metadata.get("scanner", "Prowler Security Scanner")
    time_str = scan_report.metadata.get("timestamp", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))

    meta_data = [
        [
            Paragraph("TARGET SCOPE / ACCOUNT:", meta_label), Paragraph(_esc(acc), meta_val),
            Paragraph("AUDIT DATE:", meta_label), Paragraph(_esc(time_str), meta_val)
        ],
        [
            Paragraph("CLOUD PROVIDER:", meta_label), Paragraph(_esc(prov), meta_val),
            Paragraph("AUDITING TOOL:", meta_label), Paragraph(_esc(scanner), meta_val)
        ],
        [
            Paragraph("LEAD ASSESSOR:", meta_label), Paragraph(_esc(assessor_name), meta_val),
            Paragraph("OVERALL POSTURE:", meta_label), Paragraph(f"<b>{scan_report.posture_text}</b> ({scan_report.security_grade})", meta_val)
        ]
    ]
    meta_table = Table(meta_data, colWidths=[120, 140, 110, 153])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), BG_LIGHT),
        ('BOX', (0,0), (-1,-1), 1, BORDER_COLOR),
        ('INNERGRID', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('LEFTPADDING', (0,0), (-1,-1), 8),
        ('RIGHTPADDING', (0,0), (-1,-1), 8),
    ]))
    content.append(meta_table)
    content.append(Spacer(1, 14))

    # Security Score Callout Card
    score_color = COLOR_PASS if scan_report.security_score >= 80 else (COLOR_MEDIUM if scan_report.security_score >= 60 else COLOR_FAIL)
    score_bg = BG_PASS if scan_report.security_score >= 80 else (BG_MEDIUM if scan_report.security_score >= 60 else BG_CRITICAL)

    score_card_data = [
        [
            Paragraph(f"<font size=28 color='{score_color.hexval()}'><b>{scan_report.security_score}%</b></font><br/><font size=9 color='#64748B'>SECURITY SCORE</font>", ParagraphStyle('ScoreCard', alignment=1)),
            Paragraph(
                f"<font size=12 color='{PRIMARY.hexval()}'><b>Security Posture Rating: {scan_report.posture_text} (Grade {scan_report.security_grade})</b></font><br/>"
                f"<font size=9 color='#475569'>Evaluation completed across <b>{scan_report.total_checks}</b> automated security checks. "
                f"Identified <b>{scan_report.failed_checks} failed checks</b> and <b>{scan_report.passed_checks} compliant checks</b>. "
                f"Remediation prioritization should address critical and high findings first to minimize attack surface.</font>",
                ParagraphStyle('ScoreNarrative', fontName='Helvetica', fontSize=9, leading=13)
            )
        ]
    ]
    score_table = Table(score_card_data, colWidths=[120, 403])
    score_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,0), score_bg),
        ('BACKGROUND', (1,0), (1,0), BG_LIGHT),
        ('BOX', (0,0), (-1,-1), 1.2, score_color),
        ('LINEBEFORE', (1,0), (1,0), 1, BORDER_COLOR),
        ('ALIGN', (0,0), (0,0), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('TOPPADDING', (0,0), (-1,-1), 10),
        ('BOTTOMPADDING', (0,0), (-1,-1), 10),
        ('LEFTPADDING', (0,0), (-1,-1), 10),
        ('RIGHTPADDING', (0,0), (-1,-1), 10),
    ]))
    content.append(score_table)
    content.append(Spacer(1, 14))

    # 6 Quick Metric Summary Cards
    def make_metric_card(label, count, val_color, bg_color):
        return [
            Paragraph(f"<font size=18 color='{val_color.hexval()}'><b>{count}</b></font>", ParagraphStyle('MCVal', alignment=1)),
            Paragraph(f"<font size=8 color='{TEXT_MUTED.hexval()}'><b>{label.upper()}</b></font>", ParagraphStyle('MCLbl', alignment=1))
        ]

    m1 = make_metric_card("Total Checks", scan_report.total_checks, PRIMARY, BG_LIGHT)
    m2 = make_metric_card("Passed Checks", scan_report.passed_checks, COLOR_PASS, BG_PASS)
    m3 = make_metric_card("Failed Checks", scan_report.failed_checks, COLOR_FAIL, BG_FAIL)
    m4 = make_metric_card("Manual Ver.", getattr(scan_report, 'manual_checks', 0), COLOR_INFO, BG_INFO)
    m5 = make_metric_card("Muted / Skipped", scan_report.muted_checks, COLOR_MUTED, BG_MUTED)
    m6 = make_metric_card("Total Resources", getattr(scan_report, 'total_resources', 0), PRIMARY, BG_LIGHT)

    metric_table_data = [
        [m1[0], m2[0], m3[0]],
        [m1[1], m2[1], m3[1]],
        [m4[0], m5[0], m6[0]],
        [m4[1], m5[1], m6[1]]
    ]
    metrics_table = Table(metric_table_data, colWidths=[174, 174, 175])
    metrics_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (0,3), BG_LIGHT),
        ('BACKGROUND', (1,0), (1,1), BG_PASS),
        ('BACKGROUND', (2,0), (2,1), BG_FAIL),
        ('BACKGROUND', (1,2), (1,3), BG_MUTED),
        ('BACKGROUND', (2,2), (2,3), BG_LIGHT),
        ('BACKGROUND', (0,2), (0,3), BG_INFO),
        ('BOX', (0,0), (0,1), 1, BORDER_COLOR),
        ('BOX', (1,0), (1,1), 1, colors.HexColor('#86EFAC')),
        ('BOX', (2,0), (2,1), 1, colors.HexColor('#FCA5A5')),
        ('BOX', (0,2), (0,3), 1, BORDER_COLOR),
        ('BOX', (1,2), (1,3), 1, colors.HexColor('#FCD34D')),
        ('BOX', (2,2), (2,3), 1, BORDER_COLOR),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
    ]))
    content.append(metrics_table)
    content.append(Spacer(1, 16))

    # Severity Breakdown Ribbon
    sev_data = [
        [
            Paragraph("<b>FAILED SEVERITY SPREAD</b>", ParagraphStyle('SevLbl', fontName='Helvetica-Bold', fontSize=8, textColor=TEXT_MUTED)),
            Paragraph(f"<font color='{COLOR_CRITICAL.hexval()}'><b>Critical: {scan_report.severity_counts['critical']}</b></font>", badge_style),
            Paragraph(f"<font color='{COLOR_HIGH.hexval()}'><b>High: {scan_report.severity_counts['high']}</b></font>", badge_style),
            Paragraph(f"<font color='{COLOR_MEDIUM.hexval()}'><b>Medium: {scan_report.severity_counts['medium']}</b></font>", badge_style),
            Paragraph(f"<font color='{COLOR_LOW.hexval()}'><b>Low: {scan_report.severity_counts['low']}</b></font>", badge_style),
        ]
    ]
    sev_table = Table(sev_data, colWidths=[140, 95, 95, 95, 98])
    sev_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), BG_LIGHT),
        ('BOX', (0,0), (-1,-1), 0.8, BORDER_COLOR),
        ('INNERGRID', (0,0), (-1,-1), 0.5, BORDER_COLOR),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('ALIGN', (1,0), (-1,-1), 'CENTER'),
    ]))
    content.append(sev_table)

    # Page Break after Cover / Executive Overview
    content.append(PageBreak())

    # ==========================================
    # PAGE 2: VISUAL ANALYTICS & CHARTS
    # ==========================================
    content.append(Paragraph("1. Security Visual Analytics & Breakdown", h1_style))
    content.append(Paragraph(
        "The charts below visualize the risk distribution across severity levels, overall status compliance ratios, "
        "and cloud services with the highest number of non-compliant configurations.",
        body_style
    ))
    content.append(Spacer(1, 10))

    # Render Vector Charts
    # Chart A: Severity Breakdown Donut/Pie Chart
    # Chart B: Top Failing Services Horizontal Bar Chart
    chart_row_data = []

    # Drawing 1: Pie Chart
    pie_drawing = Drawing(250, 160)
    pie = Pie()
    pie.x = 15
    pie.y = 15
    pie.width = 120
    pie.height = 120
    
    sev_vals = [
        scan_report.severity_counts["critical"],
        scan_report.severity_counts["high"],
        scan_report.severity_counts["medium"],
        scan_report.severity_counts["low"],
        scan_report.severity_counts["informational"]
    ]
    if sum(sev_vals) == 0:
        sev_vals = [1]
        pie.data = [1]
        pie.slices[0].fillColor = COLOR_PASS
        pie_labels = ['No Failed Checks']
    else:
        pie.data = sev_vals
        pie.slices[0].fillColor = COLOR_CRITICAL
        pie.slices[1].fillColor = COLOR_HIGH
        pie.slices[2].fillColor = COLOR_MEDIUM
        pie.slices[3].fillColor = COLOR_LOW
        pie.slices[4].fillColor = COLOR_INFO

    pie_drawing.add(pie)
    
    # Donut hole
    hole = Circle(75, 75, 35) # center is x+width/2 (15+120/2=75)
    hole.fillColor = colors.white
    hole.strokeColor = colors.white
    pie_drawing.add(hole)
    # Add text in hole
    pie_drawing.add(String(75, 78, str(scan_report.failed_checks), fontSize=14, fontName='Helvetica-Bold', textAnchor='middle', fillColor=COLOR_FAIL))
    pie_drawing.add(String(75, 65, "Failed", fontSize=10, fontName='Helvetica', textAnchor='middle', fillColor=TEXT_MUTED))

    # Legend for Pie
    pie_legend = Legend()
    pie_legend.x = 145
    pie_legend.y = 130
    pie_legend.dx = 8
    pie_legend.dy = 8
    pie_legend.fontName = 'Helvetica'
    pie_legend.fontSize = 8.5
    pie_legend.boxAnchor = 'nw'
    pie_legend.colorNamePairs = [
        (COLOR_CRITICAL, f"Critical  {scan_report.severity_counts['critical']}"),
        (COLOR_HIGH, f"High      {scan_report.severity_counts['high']}"),
        (COLOR_MEDIUM, f"Medium    {scan_report.severity_counts['medium']}"),
        (COLOR_LOW, f"Low       {scan_report.severity_counts['low']}"),
        (COLOR_INFO, f"Info      {scan_report.severity_counts['informational']}")
    ]
    pie_drawing.add(pie_legend)

    # Drawing 2: Top Failing Services Bar Chart
    bar_drawing = Drawing(260, 160)
    top_srvs = scan_report.top_failed_services[:5]
    if top_srvs:
        bc = HorizontalBarChart()
        bc.x = 65
        bc.y = 15
        bc.height = 130
        bc.width = 180
        bc.data = [[s["fail_count"] for s in reversed(top_srvs)]]
        bc.categoryAxis.categoryNames = [s["service"][:10].upper() for s in reversed(top_srvs)]
        bc.categoryAxis.labels.fontSize = 8
        bc.categoryAxis.labels.fontName = 'Helvetica-Bold'
        bc.categoryAxis.labels.fillColor = PRIMARY_LIGHT
        bc.valueAxis.valueMin = 0
        max_fails = max(s["fail_count"] for s in top_srvs)
        bc.valueAxis.valueMax = max(max_fails + 1, 3)
        bc.valueAxis.valueStep = 1 if max_fails <= 5 else 2
        bc.valueAxis.labels.fontSize = 7.5
        bc.bars[0].fillColor = COLOR_CRITICAL
        bar_drawing.add(bc)
    else:
        # Placeholder drawing when no fails
        bar_drawing.add(String(40, 80, "No Failed Services Found (100% Compliant)", fontName='Helvetica-Bold', fontSize=10, fillColor=COLOR_PASS))

    # Put charts in a 2-column container
    charts_table = Table([
        [
            Paragraph("<b>Failure Severity Distribution</b>", ParagraphStyle('C1T', alignment=1, fontName='Helvetica-Bold', fontSize=10, textColor=PRIMARY)),
            Paragraph("<b>Top Failing Services (Failure Count)</b>", ParagraphStyle('C2T', alignment=1, fontName='Helvetica-Bold', fontSize=10, textColor=PRIMARY))
        ],
        [pie_drawing, bar_drawing]
    ], colWidths=[260, 263])
    charts_table.setStyle(TableStyle([
        ('BOX', (0,0), (0,1), 1, BORDER_COLOR),
        ('BOX', (1,0), (1,1), 1, BORDER_COLOR),
        ('BACKGROUND', (0,0), (-1,0), BG_LIGHT),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('ALIGN', (0,1), (-1,1), 'CENTER'),
        ('VALIGN', (0,1), (-1,1), 'MIDDLE'),
    ]))
    content.append(charts_table)
    content.append(Spacer(1, 14))

    # Compliance Framework Alignment Matrix
    content.append(Paragraph("2. Compliance Framework Alignment", h2_style))
    if scan_report.compliance_summary:
        comp_rows = [
            [
                Paragraph("<b>Framework Standard</b>", ParagraphStyle('CFH', fontName='Helvetica-Bold', fontSize=8.5, textColor=PRIMARY)),
                Paragraph("<b>Total Checks</b>", ParagraphStyle('CFH', fontName='Helvetica-Bold', fontSize=8.5, textColor=PRIMARY, alignment=1)),
                Paragraph("<b>Passed</b>", ParagraphStyle('CFH', fontName='Helvetica-Bold', fontSize=8.5, textColor=COLOR_PASS, alignment=1)),
                Paragraph("<b>Failed</b>", ParagraphStyle('CFH', fontName='Helvetica-Bold', fontSize=8.5, textColor=COLOR_FAIL, alignment=1)),
                Paragraph("<b>Compliance %</b>", ParagraphStyle('CFH', fontName='Helvetica-Bold', fontSize=8.5, textColor=PRIMARY, alignment=1)),
                Paragraph("<b>Status Assessment</b>", ParagraphStyle('CFH', fontName='Helvetica-Bold', fontSize=8.5, textColor=PRIMARY))
            ]
        ]
        for fw, stat in sorted(scan_report.compliance_summary.items(), key=lambda x: x[1]["compliance_pct"]):
            pct = stat["compliance_pct"]
            status_text = "Compliant" if pct >= 90 else ("Partially Compliant" if pct >= 60 else "Non-Compliant")
            color_badge = COLOR_PASS if pct >= 90 else (COLOR_MEDIUM if pct >= 60 else COLOR_FAIL)
            comp_rows.append([
                Paragraph(f"<b>{_esc(fw)}</b>", meta_val),
                Paragraph(str(stat["total"]), ParagraphStyle('CNum', alignment=1, fontSize=9)),
                Paragraph(f"<font color='{COLOR_PASS.hexval()}'><b>{stat['pass']}</b></font>", ParagraphStyle('CNum', alignment=1, fontSize=9)),
                Paragraph(f"<font color='{COLOR_FAIL.hexval()}'><b>{stat['fail']}</b></font>", ParagraphStyle('CNum', alignment=1, fontSize=9)),
                Paragraph(f"<b>{pct}%</b>", ParagraphStyle('CNum', alignment=1, fontSize=9, textColor=color_badge)),
                Paragraph(f"<font color='{color_badge.hexval()}'><b>{status_text}</b></font>", meta_val)
            ])
        comp_table = Table(comp_rows, colWidths=[150, 70, 60, 60, 85, 98])
        comp_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), BG_LIGHT),
            ('BOX', (0,0), (-1,-1), 1, BORDER_COLOR),
            ('INNERGRID', (0,0), (-1,-1), 0.5, BORDER_COLOR),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        content.append(comp_table)
    else:
        content.append(Paragraph("<i>No standard compliance frameworks mapped in this scan dataset.</i>", body_style))

    content.append(Spacer(1, 14))

    # Priority Action Items / Top Quick Wins
    content.append(Paragraph("3. Executive Priority Remediation Guide", h2_style))
    urgent_fails = [f for f in scan_report.findings if f.status == "FAIL" and f.severity in ["critical", "high"]]
    if urgent_fails:
        prio_rows = [
            [
                Paragraph("<b>Severity</b>", ParagraphStyle('PH', fontName='Helvetica-Bold', fontSize=8, textColor=PRIMARY)),
                Paragraph("<b>Service</b>", ParagraphStyle('PH', fontName='Helvetica-Bold', fontSize=8, textColor=PRIMARY)),
                Paragraph("<b>Check & Finding Title</b>", ParagraphStyle('PH', fontName='Helvetica-Bold', fontSize=8, textColor=PRIMARY)),
                Paragraph("<b>Urgent Remediation Action</b>", ParagraphStyle('PH', fontName='Helvetica-Bold', fontSize=8, textColor=PRIMARY))
            ]
        ]
        for f in urgent_fails[:5]:
            sev_color = COLOR_CRITICAL if f.severity == "critical" else COLOR_HIGH
            sev_bg = BG_CRITICAL if f.severity == "critical" else BG_HIGH
            prio_rows.append([
                Paragraph(f"<font color='{sev_color.hexval()}'><b>{f.severity.upper()}</b></font>", ParagraphStyle('PS', fontName='Helvetica-Bold', fontSize=8)),
                Paragraph(_esc(f.service.upper()), meta_val),
                Paragraph(f"<b>{_esc(f.title)}</b><br/><font size=7.5 color='#64748B'>{_esc(f.resource_id or f.resource_arn)}</font>", meta_val),
                Paragraph(_esc(f.remediation_text or f.status_extended[:120]), ParagraphStyle('PRem', fontSize=8.5, leading=11, textColor=TEXT_MAIN))
            ])
        prio_table = Table(prio_rows, colWidths=[65, 65, 170, 223])
        prio_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), BG_LIGHT),
            ('BOX', (0,0), (-1,-1), 1, BORDER_COLOR),
            ('INNERGRID', (0,0), (-1,-1), 0.5, BORDER_COLOR),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ]))
        content.append(prio_table)
    else:
        content.append(Paragraph("<i>No critical or high severity failed findings identified in this audit.</i>", body_style))

    # Page Break for Detailed Technical Findings
    content.append(PageBreak())

    # ==========================================
    # PAGE 3+: DETAILED TECHNICAL FINDINGS
    # ==========================================
    content.append(Paragraph("4. Security Findings Explorer", h1_style))
    
    # Filter findings based on configuration
    filtered_findings = scan_report.findings
    if failed_only:
        filtered_findings = [f for f in filtered_findings if f.status == "FAIL"]

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    if severity_threshold in sev_order:
        thresh_val = sev_order[severity_threshold]
        filtered_findings = [f for f in filtered_findings if sev_order.get(f.severity.lower(), 4) <= thresh_val]

    # Sort: Failures first, then Critical -> High -> Medium -> Low
    filtered_findings.sort(key=lambda f: (0 if f.status == "FAIL" else 1, sev_order.get(f.severity.lower(), 4), f.service, f.check_id))

    # Validate Severity Priority Order
    prev_sev_val = -1
    for f in filtered_findings:
        if f.status == "FAIL":
            curr_sev_val = sev_order.get(f.severity.lower(), 4)
            if curr_sev_val < prev_sev_val:
                raise ValueError(f"Validation failed: Finding of severity '{f.severity}' appeared after a lower priority severity finding. Order constraint violated.")
            prev_sev_val = curr_sev_val

    if max_findings and len(filtered_findings) > max_findings:
        content.append(Paragraph(
            f"<b>{max_findings} Failed Findings</b> <i>(Limited by max_findings configuration)</i>",
            body_style
        ))
        filtered_findings = filtered_findings[:max_findings]
    else:
        content.append(Paragraph(
            f"<b>{len(filtered_findings)} Failed Findings</b>",
            body_style
        ))

    content.append(Spacer(1, 10))

    if not filtered_findings:
        content.append(Paragraph("<b>No findings matched the selected criteria.</b>", body_style))

    # Render each finding as a card
    for idx, f in enumerate(filtered_findings, start=1):
        finding_elements = []

        is_fail = (f.status == "FAIL")
        st_color = COLOR_FAIL if is_fail else (COLOR_PASS if f.status == "PASS" else COLOR_MUTED)
        st_bg = BG_FAIL if is_fail else (BG_PASS if f.status == "PASS" else BG_MUTED)

        sev_colors = {
            "critical": (COLOR_CRITICAL, BG_CRITICAL),
            "high": (COLOR_HIGH, BG_HIGH),
            "medium": (COLOR_MEDIUM, BG_MEDIUM),
            "low": (COLOR_LOW, BG_LOW),
            "informational": (COLOR_INFO, BG_INFO)
        }
        sev_fg, sev_bg = sev_colors.get(f.severity, (COLOR_INFO, BG_INFO))

        # Finding Header Row Table
        header_table_data = [
            [
                Paragraph(f"<font color='{st_color.hexval()}'><b>[{f.status}]</b></font>", badge_style),
                Paragraph(f"<font color='{sev_fg.hexval()}'><b>[{f.severity.upper()}]</b></font>", badge_style),
                Paragraph(f"<b>#{idx}. {_esc(f.title)}</b>", ParagraphStyle('FTitle', fontName='Helvetica-Bold', fontSize=9.5, leading=12, textColor=PRIMARY)),
                Paragraph(f"<font color='#64748B'>{_esc(f.check_id)}</font>", ParagraphStyle('FId', fontName='Courier', fontSize=7, alignment=2))
            ]
        ]
        hdr_table = Table(header_table_data, colWidths=[45, 65, 253, 160])
        hdr_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,0), st_bg),
            ('BACKGROUND', (1,0), (1,0), sev_bg),
            ('BACKGROUND', (2,0), (-1,-1), BG_LIGHT),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('ALIGN', (0,0), (1,0), 'CENTER'),
        ]))
        finding_elements.append(hdr_table)

        # Body table
        res_str = getattr(f, 'resolved_resource', f.resource_arn or f.resource_id or 'Not explicitly identified by scanner')
        
        body_rows = [
            [
                Paragraph("<b>AFFECTED RESOURCE / SCOPE:</b>", meta_label),
                Paragraph(f"<font face='Courier' size=8>{_wrap_safe(res_str)}</font>", meta_val),
                Paragraph("<b>Service / Region:</b>", meta_label),
                Paragraph(f"{_esc(f.service.upper())} / {_esc(f.region)}", meta_val)
            ]
        ]

        if getattr(f, 'resource_tags', None):
            body_rows.append([
                Paragraph("<b>Resource Tags:</b>", meta_label),
                Paragraph(f"<font color='#64748B'>{_wrap_safe(f.resource_tags)}</font>", ParagraphStyle('FTags', fontSize=8.5, leading=11)),
                Paragraph("", meta_label), Paragraph("", meta_val)
            ])

        if f.status_extended:
            body_rows.append([
                Paragraph("<b>Observation / Status Details:</b>", meta_label),
                Paragraph(_wrap_safe(f.status_extended), ParagraphStyle('FDetail', fontSize=8.5, leading=11, textColor=TEXT_MAIN)),
                Paragraph("", meta_label), Paragraph("", meta_val)
            ])

        if f.risk:
            body_rows.append([
                Paragraph("<b>Risk Impact:</b>", meta_label),
                Paragraph(f"<font color='{COLOR_CRITICAL.hexval()}'>{_wrap_safe(f.risk)}</font>", ParagraphStyle('FRisk', fontSize=8.5, leading=11)),
                Paragraph("", meta_label), Paragraph("", meta_val)
            ])

        if f.remediation_text:
            body_rows.append([
                Paragraph("<b>Remediation:</b>", meta_label),
                Paragraph(_wrap_safe(f.remediation_text), ParagraphStyle('FRem', fontSize=8.5, leading=11, textColor=TEXT_MAIN)),
                Paragraph("", meta_label), Paragraph("", meta_val)
            ])
            
        if f.compliance:
            comp_str = "<br/>".join([f"{_esc(k)}: {_esc(', '.join(v))}" for k, v in f.compliance.items()])
            body_rows.append([
                Paragraph("<b>Compliance Mapping:</b>", meta_label),
                Paragraph(comp_str, ParagraphStyle('FComp', fontSize=8, leading=10, textColor=TEXT_MUTED)),
                Paragraph("", meta_label), Paragraph("", meta_val)
            ])

        # Merge cells for wide rows
        t_style = [
            ('BACKGROUND', (0,0), (-1,-1), colors.white),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ]
        
        row_idx = 1
        if getattr(f, 'resource_tags', None):
            t_style.append(('SPAN', (1, row_idx), (3, row_idx)))
            row_idx += 1
        if f.status_extended:
            t_style.append(('SPAN', (1, row_idx), (3, row_idx)))
            row_idx += 1
        if f.risk:
            t_style.append(('SPAN', (1, row_idx), (3, row_idx)))
            row_idx += 1
        if f.remediation_text:
            t_style.append(('SPAN', (1, row_idx), (3, row_idx)))
            row_idx += 1
        if f.compliance:
            t_style.append(('SPAN', (1, row_idx), (3, row_idx)))
            row_idx += 1

        b_table = Table(body_rows, colWidths=[90, 220, 95, 118])
        b_table.setStyle(TableStyle(t_style))
        finding_elements.append(b_table)

        # Code command snippet if present
        if f.remediation_code:
            code_str = _esc(f.remediation_code).replace("\n", "<br/>")
            finding_elements.append(Paragraph(f"<b>Fix Command:</b><br/>{code_str}", code_style))

        # Doc link if present
        if f.remediation_url:
            finding_elements.append(Paragraph(
                f"<font size=7.5 color='{ACCENT.hexval()}'>Ref Doc: {_esc(f.remediation_url)}</font>",
                ParagraphStyle('FUrl', fontName='Helvetica-Oblique', spaceAfter=3)
            ))

        # Card wrapper box
        card_table = Table([[finding_elements]], colWidths=[523])
        card_table.setStyle(TableStyle([
            ('BOX', (0,0), (-1,-1), 1, BORDER_COLOR),
            ('TOPPADDING', (0,0), (-1,-1), 0),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('LEFTPADDING', (0,0), (-1,-1), 0),
            ('RIGHTPADDING', (0,0), (-1,-1), 0),
        ]))

        # KeepTogether keeps each individual finding card unified on one page if possible
        content.append(KeepTogether(card_table))
        content.append(Spacer(1, 8))

    # Manual Findings Section
    manual_findings = [f for f in scan_report.findings if f.status == "MANUAL"]
    if manual_findings:
        content.append(PageBreak())
        content.append(Paragraph("5. Manual Verification Required", h1_style))
        content.append(Paragraph(
            "The following checks require manual verification and cannot be fully evaluated in an automated manner.",
            body_style
        ))
        content.append(Spacer(1, 10))
        for f in manual_findings:
            res_str = f.resource_arn or f.resource_id or 'N/A'
            m_rows = [
                [Paragraph("<b>Check:</b>", meta_label), Paragraph(f"<b>{_wrap_safe(f.title)}</b>", meta_val)],
                [Paragraph("<b>Service / Region:</b>", meta_label), Paragraph(f"{_esc(f.service.upper())} / {_esc(f.region)}", meta_val)],
                [Paragraph("<b>Resource:</b>", meta_label), Paragraph(f"<font face='Courier' size=8>{_wrap_safe(res_str)}</font>", meta_val)],
                [Paragraph("<b>Details:</b>", meta_label), Paragraph(_wrap_safe(f.status_extended), ParagraphStyle('FDetail', fontSize=8.5, leading=11, textColor=TEXT_MAIN))]
            ]
            if f.compliance:
                comp_str = "<br/>".join([f"{_esc(k)}: {_esc(', '.join(v))}" for k, v in f.compliance.items()])
                m_rows.append([Paragraph("<b>Compliance:</b>", meta_label), Paragraph(comp_str, ParagraphStyle('FComp', fontSize=8, leading=10, textColor=TEXT_MUTED))])
            
            m_table = Table(m_rows, colWidths=[90, 433])
            m_table.setStyle(TableStyle([
                ('BOX', (0,0), (-1,-1), 1, BORDER_COLOR),
                ('INNERGRID', (0,0), (-1,-1), 0.5, BORDER_COLOR),
                ('BACKGROUND', (0,0), (0,-1), BG_INFO),
                ('TOPPADDING', (0,0), (-1,-1), 5),
                ('BOTTOMPADDING', (0,0), (-1,-1), 5),
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ]))
            content.append(KeepTogether(m_table))
            content.append(Spacer(1, 8))

    # Passed Controls Section
    passed_findings = [f for f in scan_report.findings if f.status == "PASS"]
    if passed_findings:
        content.append(PageBreak())
        content.append(Paragraph("6. Passed Security Controls", h1_style))
        content.append(Paragraph(
            "The following security controls were successfully validated as compliant during the assessment.",
            body_style
        ))
        content.append(Spacer(1, 10))
        
        p_rows = [
            [
                Paragraph("<b>Service</b>", ParagraphStyle('PH', fontName='Helvetica-Bold', fontSize=8, textColor=PRIMARY)),
                Paragraph("<b>Check Title</b>", ParagraphStyle('PH', fontName='Helvetica-Bold', fontSize=8, textColor=PRIMARY)),
                Paragraph("<b>Check ID</b>", ParagraphStyle('PH', fontName='Helvetica-Bold', fontSize=8, textColor=PRIMARY)),
                Paragraph("<b>Region</b>", ParagraphStyle('PH', fontName='Helvetica-Bold', fontSize=8, textColor=PRIMARY)),
                Paragraph("<b>Resource</b>", ParagraphStyle('PH', fontName='Helvetica-Bold', fontSize=8, textColor=PRIMARY))
            ]
        ]
        
        for f in passed_findings:
            p_rows.append([
                Paragraph(_esc(f.service.upper()), ParagraphStyle('PC', fontSize=7.5)),
                Paragraph(_wrap_safe(f.title), ParagraphStyle('PC', fontSize=7.5)),
                Paragraph(_wrap_safe(f.check_id), ParagraphStyle('PC', fontSize=7.5, fontName='Courier')),
                Paragraph(_esc(f.region), ParagraphStyle('PC', fontSize=7.5)),
                Paragraph(_wrap_safe(f.resource_id or 'N/A'), ParagraphStyle('PC', fontSize=7.5, fontName='Courier'))
            ])
            
        p_table = Table(p_rows, colWidths=[60, 160, 100, 60, 143])
        p_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), BG_LIGHT),
            ('BOX', (0,0), (-1,-1), 1, BORDER_COLOR),
            ('INNERGRID', (0,0), (-1,-1), 0.5, BORDER_COLOR),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ]))
        content.append(p_table)

    # Build the PDF using NumberedCanvas
    doc.build(content, canvasmaker=NumberedCanvas)
    return output_pdf_path
