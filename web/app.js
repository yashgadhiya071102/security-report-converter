/**
 * app.js - Frontend application controller for Security Scanner to PDF Converter
 */

// Application State
let currentReport = null;
let rawFileContent = null;
let currentFileName = "security_report";
let severityChartInstance = null;
let servicesChartInstance = null;

let pdfConfig = {
  report_title: "Cloud Security Assessment Report",
  company_name: "Enterprise Cloud Security Audit",
  assessor_name: "Security Automation & Compliance Team",
  failed_only: true,
  severity_threshold: "all"
};

// DOM Elements
const dropzone = document.getElementById("dropzone");
const fileInput = document.getElementById("fileInput");
const togglePasteBtn = document.getElementById("togglePasteBtn");
const pasteAreaContainer = document.getElementById("pasteAreaContainer");
const rawTextInput = document.getElementById("rawTextInput");
const submitPasteBtn = document.getElementById("submitPasteBtn");
const cancelPasteBtn = document.getElementById("cancelPasteBtn");

const loadingOverlay = document.getElementById("loadingOverlay");
const loadingMessage = document.getElementById("loadingMessage");
const dashboardSection = document.getElementById("dashboardSection");

const themeToggleBtn = document.getElementById("themeToggleBtn");
const exportPdfBtn = document.getElementById("exportPdfBtn");

const openConfigModalBtn = document.getElementById("openConfigModalBtn");
const closeConfigModalBtn = document.getElementById("closeConfigModalBtn");
const configModal = document.getElementById("configModal");
const saveConfigBtn = document.getElementById("saveConfigBtn");
const modalExportPdfBtn = document.getElementById("modalExportPdfBtn");

const findingSearch = document.getElementById("findingSearch");
const statusFilter = document.getElementById("statusFilter");
const severityFilter = document.getElementById("severityFilter");
const findingsList = document.getElementById("findingsList");
const noFindingsMsg = document.getElementById("noFindingsMsg");
const cloudProviderInput = document.getElementById("cloudProviderInput");
const clientNameInput = document.getElementById("clientNameInput");

// Initialization
document.addEventListener("DOMContentLoaded", () => {
  setupTheme();
  setupEventListeners();
  setupSampleButtons();
  
  // Auto-load AWS sample by default so the user sees a rich, active dashboard immediately!
  loadSampleReport("aws");
});

function setupTheme() {
  const savedTheme = localStorage.getItem("sec_converter_theme") || "dark-theme";
  document.body.className = savedTheme;

  themeToggleBtn.addEventListener("click", () => {
    if (document.body.classList.contains("dark-theme")) {
      document.body.classList.remove("dark-theme");
      document.body.classList.add("light-theme");
      localStorage.setItem("sec_converter_theme", "light-theme");
    } else {
      document.body.classList.remove("light-theme");
      document.body.classList.add("dark-theme");
      localStorage.setItem("sec_converter_theme", "dark-theme");
    }
    if (currentReport) {
      renderCharts(currentReport);
    }
  });
}

function setupEventListeners() {
  // Dropzone drag-and-drop
  ['dragenter', 'dragover'].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropzone.classList.add('drag-over');
    }, false);
  });

  ['dragleave', 'drop'].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropzone.classList.remove('drag-over');
    }, false);
  });

  dropzone.addEventListener('drop', (e) => {
    const dt = e.dataTransfer;
    const files = dt.files;
    if (files.length > 0) {
      handleFile(files[0]);
    }
  });

  // File input change
  fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
      handleFile(e.target.files[0]);
    }
  });

  // Paste area toggle
  togglePasteBtn.addEventListener('click', () => {
    pasteAreaContainer.style.display = pasteAreaContainer.style.display === 'none' ? 'block' : 'none';
  });

  cancelPasteBtn.addEventListener('click', () => {
    pasteAreaContainer.style.display = 'none';
  });

  submitPasteBtn.addEventListener('click', () => {
    const text = rawTextInput.value.trim();
    if (!text) {
      alert("Please paste JSON or HTML content first.");
      return;
    }
    rawFileContent = text;
    currentFileName = "pasted_report";
    processContent(text, "pasted_report.json");
    pasteAreaContainer.style.display = 'none';
  });

  // Filtering
  findingSearch.addEventListener('input', filterAndRenderFindings);
  statusFilter.addEventListener('change', filterAndRenderFindings);
  severityFilter.addEventListener('change', filterAndRenderFindings);

  // Manual report header values. These are never auto-filled from the scan.
  cloudProviderInput.addEventListener('input', updateManualReportFields);
  clientNameInput.addEventListener('input', updateManualReportFields);

  // PDF Export
  exportPdfBtn.addEventListener('click', () => downloadPdf(pdfConfig));

  // Config Modal
  openConfigModalBtn.addEventListener('click', () => {
    document.getElementById('cfgTitle').value = pdfConfig.report_title;
    document.getElementById('cfgCompany').value = pdfConfig.company_name;
    document.getElementById('cfgAssessor').value = pdfConfig.assessor_name;
    document.getElementById('cfgFilter').value = pdfConfig.failed_only ? 'failed' : 'all';
    document.getElementById('cfgSeverity').value = pdfConfig.severity_threshold;
    configModal.style.display = 'flex';
  });

  closeConfigModalBtn.addEventListener('click', () => {
    configModal.style.display = 'none';
  });

  saveConfigBtn.addEventListener('click', () => {
    saveModalConfig();
    configModal.style.display = 'none';
  });

  modalExportPdfBtn.addEventListener('click', () => {
    saveModalConfig();
    configModal.style.display = 'none';
    downloadPdf(pdfConfig);
  });
}

function saveModalConfig() {
  pdfConfig.report_title = document.getElementById('cfgTitle').value.trim() || "Cloud Security Assessment Report";
  pdfConfig.company_name = document.getElementById('cfgCompany').value.trim() || "Enterprise Cloud Security Audit";
  pdfConfig.assessor_name = document.getElementById('cfgAssessor').value.trim() || "Security Automation Team";
  pdfConfig.failed_only = (document.getElementById('cfgFilter').value === 'failed');
  pdfConfig.severity_threshold = document.getElementById('cfgSeverity').value;
}

function updateManualReportFields() {
  const providerEl = document.getElementById('metaProvider');
  const clientEl = document.getElementById('metaClient');

  if (providerEl) providerEl.textContent = cloudProviderInput.value.trim();
  if (clientEl) clientEl.textContent = clientNameInput.value.trim();
}

function setupSampleButtons() {
  document.querySelectorAll('.sample-tag-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const sampleType = btn.getAttribute('data-sample');
      loadSampleReport(sampleType);
    });
  });
}

function handleFile(file) {
  currentFileName = file.name;
  showLoading(`Reading ${file.name}...`);
  const reader = new FileReader();
  reader.onload = (e) => {
    // Decode manually so UTF-16 / BOM files (e.g. PowerShell redirects) work too
    const bytes = new Uint8Array(e.target.result);
    let encoding = "utf-8";
    if (bytes[0] === 0xFF && bytes[1] === 0xFE) encoding = "utf-16le";
    else if (bytes[0] === 0xFE && bytes[1] === 0xFF) encoding = "utf-16be";
    rawFileContent = new TextDecoder(encoding).decode(bytes).replace(/^\uFEFF/, "");
    processContent(rawFileContent, file.name);
  };
  reader.onerror = () => {
    hideLoading();
    alert("Error reading file.");
  };
  reader.readAsArrayBuffer(file);
}

async function processContent(contentStr, filename) {
  showLoading("Parsing scan findings, compliance frameworks & metrics...");
  try {
    const response = await fetch('/api/parse', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content: contentStr, filename: filename })
    });

    if (!response.ok) {
      let msg = await response.text();
      try { msg = JSON.parse(msg).message || msg; } catch (_) {}
      throw new Error(msg);
    }

    const data = await response.json();
    if (data.report) {
      currentReport = data.report;
      renderReport(currentReport);
      exportPdfBtn.disabled = false;
    } else {
      throw new Error("No report data returned");
    }
  } catch (err) {
    console.error("Parse error:", err);
    alert("Error parsing report: " + err.message);
  } finally {
    hideLoading();
  }
}

async function loadSampleReport(sampleType) {
  showLoading(`Loading sample ${sampleType.toUpperCase()} report...`);
  try {
    const res = await fetch(`/api/sample?type=${sampleType}`);
    const data = await res.json();
    if (data.report) {
      currentReport = data.report;
      rawFileContent = data.raw_content;
      currentFileName = `sample_${sampleType}_report`;
      renderReport(currentReport);
      exportPdfBtn.disabled = false;
    }
  } catch (err) {
    console.warn("Could not fetch sample from server, using local fallback if available:", err);
  } finally {
    hideLoading();
  }
}

function showLoading(msg) {
  loadingMessage.textContent = msg;
  loadingOverlay.style.display = 'block';
}

function hideLoading() {
  loadingOverlay.style.display = 'none';
}

// Render the Entire Dashboard
function renderReport(report) {
  dashboardSection.style.display = 'block';

  // 1. Meta strip
  const meta = report.metadata || {};
  document.getElementById('metaAccount').textContent = meta.account_id || "Production Account";
  updateManualReportFields();
  document.getElementById('metaTimestamp').textContent = meta.timestamp || new Date().toISOString();

  // 2. Security Score & Grade
  const sum = report.summary || {};
  const score = sum.security_score || 0;
  document.getElementById('scoreDisplay').textContent = `${score}%`;
  
  const gradeBadge = document.getElementById('gradeBadge');
  gradeBadge.textContent = `Grade ${sum.security_grade || 'B'}`;
  gradeBadge.className = `grade-badge grade-${(sum.security_grade || 'b').charAt(0).toLowerCase()}`;

  document.getElementById('postureHeading').textContent = `Posture: ${sum.posture_text || 'Good'}`;
  document.getElementById('postureSummary').textContent = 
    `Evaluated across ${sum.total_checks} automated checks. ${sum.failed_checks} failed configurations requiring remediation.`;

  // Animate SVG Gauge (circumference = 2 * PI * 50 = 314.159)
  const gaugeProgress = document.getElementById('gaugeProgress');
  const circumference = 314.159;
  const offset = circumference - (score / 100) * circumference;
  gaugeProgress.style.strokeDashoffset = offset;
  gaugeProgress.style.stroke = score >= 80 ? 'var(--color-pass)' : (score >= 60 ? 'var(--color-medium)' : 'var(--color-critical)');

  // 3. Metric highlight tiles
  document.getElementById('mTotal').textContent = sum.total_checks || 0;
  document.getElementById('mPassed').textContent = sum.passed_checks || 0;
  document.getElementById('mFailed').textContent = sum.failed_checks || 0;
  
  // 4. Findings by severity summary cards
  const severityCounts = sum.severity_counts || {};
  const severityTotal = Object.values(severityCounts).reduce((total, value) => total + (Number(value) || 0), 0);
  const failedTotal = Number(sum.failed_checks || severityTotal || 0);

  const severityCardData = [
    ['critical', 'severityCriticalCount', 'severityCriticalPct'],
    ['high', 'severityHighCount', 'severityHighPct'],
    ['medium', 'severityMediumCount', 'severityMediumPct'],
    ['low', 'severityLowCount', 'severityLowPct']
  ];

  severityCardData.forEach(([key, countId, pctId]) => {
    const count = Number(severityCounts[key] || 0);
    const pct = failedTotal > 0 ? ((count / failedTotal) * 100).toFixed(1) : '0.0';
    const countElement = document.getElementById(countId);
    const pctElement = document.getElementById(pctId);
    if (countElement) countElement.textContent = count.toLocaleString();
    if (pctElement) pctElement.textContent = `${pct}% of total findings`;
  });

  // 5. Render Charts
  renderCharts(report);

  // 6. Compliance Table
  renderCompliance(report.summary.compliance_summary);

  // 7. Findings Explorer
  filterAndRenderFindings();

  // Scroll to dashboard smoothly
  dashboardSection.scrollIntoView({ behavior: 'smooth' });
}

function renderCharts(report, forceLight = false) {
  if (typeof Chart === 'undefined') return;

  const isDark = !forceLight && document.body.classList.contains('dark-theme');
  const textColor = isDark ? '#9CA3AF' : '#64748B';
  const gridColor = isDark ? 'rgba(255, 255, 255, 0.08)' : 'rgba(0, 0, 0, 0.08)';

  // Chart 1: Failure Severity Donut
  const sevCtx = document.getElementById('severityChart');
  if (sevCtx) {
    if (severityChartInstance) {
      severityChartInstance.destroy();
    }
    const sevs = report.summary.severity_counts || {};
    const severityDataRaw = [
      { name: "Critical", value: sevs.critical || 0, color: '#DC2626' },
      { name: "High", value: sevs.high || 0, color: '#EA580C' },
      { name: "Medium", value: sevs.medium || 0, color: '#D97706' },
      { name: "Low", value: sevs.low || 0, color: '#2563EB' },
      { name: "Informational", value: sevs.informational || 0, color: '#475569' }
    ];
    const severityData = severityDataRaw.filter(item => item.value > 0);

    const severityTotal = severityData.reduce((acc, item) => acc + item.value, 0);
    const displayedFailedChecks = report.summary.failed_checks || 0;
    const actualFailedFindings = (report.findings || []).filter(f => f.status === 'FAIL').length;

    if (severityTotal !== actualFailedFindings) {
      console.error(`Validation Error: severityTotal (${severityTotal}) does not match actual failed findings (${actualFailedFindings})`);
    }
    if (severityTotal !== displayedFailedChecks) {
      console.error(`Validation Error: severityTotal (${severityTotal}) does not match displayed failed checks (${displayedFailedChecks})`);
    }

    const centerEl = document.getElementById('donutTotal');
    if (centerEl) centerEl.textContent = displayedFailedChecks;

    const legendEl = document.getElementById('severityLegend');
    if (legendEl) {
      legendEl.innerHTML = '';
      severityData.forEach(item => {
        const pct = displayedFailedChecks > 0 ? ((item.value / displayedFailedChecks) * 100).toFixed(1) : '0.0';
        const row = document.createElement('div');
        row.style.display = 'flex';
        row.style.alignItems = 'center';
        row.innerHTML = `
          <span style="color: ${item.color}; margin-right: 8px; font-size: 16px;">●</span>
          <span style="width: 100px; font-weight: 500;">${item.name}</span>
          <span style="width: 30px; text-align: right; font-weight: 600;">${item.value}</span>
          <span style="width: 70px; text-align: right; color: var(--text-muted);">(${pct}%)</span>
        `;
        legendEl.appendChild(row);
      });
    }

    severityChartInstance = new Chart(sevCtx, {
      type: 'doughnut',
      data: {
        labels: severityData.map(d => d.name),
        datasets: [{
          data: severityData.map(d => d.value),
          backgroundColor: severityData.map(d => d.color),
          borderColor: isDark ? '#111827' : '#FFFFFF',
          borderWidth: 2,
          hoverOffset: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: false,
        cutout: '65%',
        plugins: {
          legend: {
            display: false
          },
          tooltip: {
            callbacks: {
              label: function(context) {
                const val = context.parsed;
                const pct = displayedFailedChecks > 0 ? ((val / displayedFailedChecks) * 100).toFixed(1) : 0;
                return ` ${context.label}: ${val} (${pct}%)`;
              }
            }
          }
        }
      }
    });
  }

  // Chart 2: Top Failing Services Bar Chart
  const srvCtx = document.getElementById('servicesChart');
  if (srvCtx) {
    if (servicesChartInstance) {
      servicesChartInstance.destroy();
    }
    const topSrv = (report.summary.top_failed_services || []).slice(0, 6);
    const labels = topSrv.map(s => (s.service || 'unknown').toUpperCase());
    const dataVals = topSrv.map(s => s.fail_count);

    servicesChartInstance = new Chart(srvCtx, {
      type: 'bar',
      data: {
        labels: labels.length > 0 ? labels : ['None'],
        datasets: [{
          label: 'Failed Checks',
          data: dataVals.length > 0 ? dataVals : [0],
          backgroundColor: '#EF4444',
          borderRadius: 6,
          maxBarThickness: 32
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: false,
        scales: {
          x: {
            grid: { display: false },
            ticks: { color: textColor, font: { family: 'Inter', size: 11, weight: 600 } }
          },
          y: {
            beginAtZero: true,
            grid: { color: gridColor },
            ticks: { color: textColor, stepSize: 1, precision: 0 }
          }
        },
        plugins: {
          legend: { display: false }
        }
      }
    });
  }
}

function renderCompliance(compSummary) {
  const tbody = document.getElementById('complianceTableBody');
  tbody.innerHTML = '';

  if (!compSummary || Object.keys(compSummary).length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">No compliance frameworks mapped in this scan.</td></tr>';
    return;
  }

  for (const [fw, stat] of Object.entries(compSummary)) {
    const tr = document.createElement('tr');
    const pct = stat.compliance_pct || 0;
    const isPassing = pct >= 80;
    const pctColor = isPassing ? 'var(--color-pass)' : (pct >= 60 ? 'var(--color-medium)' : 'var(--color-fail)');

    tr.innerHTML = `
      <td><strong>${escapeHtml(fw)}</strong></td>
      <td>${stat.total}</td>
      <td style="color: var(--color-pass); font-weight: 600;">${stat.pass}</td>
      <td style="color: var(--color-fail); font-weight: 600;">${stat.fail}</td>
      <td style="color: ${pctColor}; font-weight: 700;">${pct}%</td>
      <td style="width: 180px;">
        <div class="progress-bar-bg">
          <div class="progress-bar-fill" style="width: ${pct}%; background: ${pctColor};"></div>
        </div>
      </td>
    `;
    tbody.appendChild(tr);
  }
}

function filterAndRenderFindings() {
  if (!currentReport) return;

  const query = findingSearch.value.trim().toLowerCase();
  const stFilter = statusFilter.value;
  const sevFilter = severityFilter.value;

  const sevRank = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
    informational: 0
  };

  const filtered = currentReport.findings.filter(f => {
    // Status
    if (stFilter !== 'all' && f.status !== stFilter) {
      return false;
    }

    // Severity
    const severity = String(f.severity || '').toLowerCase();

    if (sevFilter === 'critical' && severity !== 'critical') return false;
    if (sevFilter === 'high' && (sevRank[severity] || 0) < 3) return false;
    if (sevFilter === 'medium' && (sevRank[severity] || 0) < 2) return false;
    if (sevFilter === 'low' && (sevRank[severity] || 0) < 1) return false;

    // Search query
    if (query) {
      const match = (
        String(f.title || '').toLowerCase().includes(query) ||
        String(f.check_id || '').toLowerCase().includes(query) ||
        String(f.service || '').toLowerCase().includes(query) ||
        String(f.resource_id || '').toLowerCase().includes(query) ||
        String(f.resource_arn || '').toLowerCase().includes(query) ||
        String(f.region || '').toLowerCase().includes(query)
      );

      if (!match) return false;
    }

    return true;
  });

  /*
   * =========================================================
   * FINAL FINDINGS HIERARCHY
   *
   * Severity
   *   └── AWS Service / Category
   *         └── Region
   *               └── Individual Finding
   *
   * Severity order:
   *   Critical → High → Medium → Low
   *
   * AWS category order:
   *   IAM / Users
   *   S3 / Buckets
   *   EC2
   *   VPC / Networking
   *   CloudTrail
   *   CloudWatch
   *   KMS
   *   RDS
   *   Lambda
   *   ECR
   *   ECS
   *   EKS
   *   DynamoDB
   *   SNS / SQS
   *   Other services
   * =========================================================
   */

  const severityPriority = {
    critical: 1,
    high: 2,
    medium: 3,
    low: 4,
    informational: 5
  };

  function getServiceCategory(service) {
    const normalized = String(service || '').toLowerCase().trim();

    if (
      normalized === 'iam' ||
      normalized.includes('iam') ||
      normalized.includes('identity') ||
      normalized.includes('access')
    ) {
      return { key: 'iam', name: 'IAM / Users', priority: 1 };
    }

    if (normalized === 's3' || normalized.includes('s3')) {
      return { key: 's3', name: 'S3 / Buckets', priority: 2 };
    }

    if (normalized === 'ec2' || normalized.includes('ec2')) {
      return { key: 'ec2', name: 'EC2', priority: 3 };
    }

    if (
      normalized === 'vpc' ||
      normalized.includes('vpc') ||
      normalized.includes('network')
    ) {
      return { key: 'vpc', name: 'VPC / Networking', priority: 4 };
    }

    if (
      normalized === 'cloudtrail' ||
      normalized.includes('cloudtrail')
    ) {
      return { key: 'cloudtrail', name: 'CloudTrail', priority: 5 };
    }

    if (
      normalized === 'cloudwatch' ||
      normalized.includes('cloudwatch')
    ) {
      return { key: 'cloudwatch', name: 'CloudWatch', priority: 6 };
    }

    if (normalized === 'kms' || normalized.includes('kms')) {
      return { key: 'kms', name: 'KMS', priority: 7 };
    }

    if (normalized === 'rds' || normalized.includes('rds')) {
      return { key: 'rds', name: 'RDS', priority: 8 };
    }

    if (normalized === 'lambda' || normalized.includes('lambda')) {
      return { key: 'lambda', name: 'Lambda', priority: 9 };
    }

    if (normalized === 'ecr' || normalized.includes('ecr')) {
      return { key: 'ecr', name: 'ECR', priority: 10 };
    }

    if (normalized === 'ecs' || normalized.includes('ecs')) {
      return { key: 'ecs', name: 'ECS', priority: 11 };
    }

    if (normalized === 'eks' || normalized.includes('eks')) {
      return { key: 'eks', name: 'EKS', priority: 12 };
    }

    if (
      normalized === 'dynamodb' ||
      normalized.includes('dynamodb')
    ) {
      return { key: 'dynamodb', name: 'DynamoDB', priority: 13 };
    }

    if (
      normalized === 'sns' ||
      normalized.includes('sns') ||
      normalized === 'sqs' ||
      normalized.includes('sqs')
    ) {
      return { key: 'sns-sqs', name: 'SNS / SQS', priority: 14 };
    }

    return { key: 'other', name: 'Other services', priority: 15 };
  }

  function getSeverityLabel(severity) {
    const normalized = String(severity || '').toLowerCase();

    return normalized
      ? normalized.charAt(0).toUpperCase() + normalized.slice(1)
      : 'Informational';
  }

  function getSeverityClass(severity) {
    return String(severity || 'informational').toLowerCase();
  }

  function getServiceIcon(categoryKey) {
    const icons = {
      iam: `
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none"
             stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
             aria-hidden="true">
          <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
          <circle cx="12" cy="7" r="4"/>
        </svg>
      `,
      s3: `
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none"
             stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
             aria-hidden="true">
          <path d="M5 6h14"/>
          <path d="M6 6l1 13h10l1-13"/>
          <path d="M9 6V4h6v2"/>
          <path d="M9 10v5"/>
          <path d="M12 10v5"/>
          <path d="M15 10v5"/>
        </svg>
      `,
      ec2: `
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none"
             stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
             aria-hidden="true">
          <rect x="5" y="5" width="14" height="14" rx="2"/>
          <path d="M9 9h6v6H9z"/>
          <path d="M9 1v4M15 1v4M9 19v4M15 19v4M1 9h4M1 15h4M19 9h4M19 15h4"/>
        </svg>
      `,
      vpc: `
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none"
             stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
             aria-hidden="true">
          <circle cx="12" cy="12" r="3"/>
          <circle cx="5" cy="5" r="2"/>
          <circle cx="19" cy="5" r="2"/>
          <circle cx="19" cy="19" r="2"/>
          <path d="M7 6l3 4M17 6l-3 4M15 14l3 3"/>
        </svg>
      `,
      default: `
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none"
             stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
             aria-hidden="true">
          <circle cx="12" cy="12" r="9"/>
          <path d="M12 8v8M8 12h8"/>
        </svg>
      `
    };

    return icons[categoryKey] || icons.default;
  }

  function buildFindingCard(f, idx) {
    const item = document.createElement('div');
    const severityClass = getSeverityClass(f.severity);
    item.className = `finding-item finding-grouped-item finding-severity-card-${severityClass}`;

    const isFail = f.status === 'FAIL';
    const statusBadgeClass = isFail ? 'badge-fail' : 'badge-pass';
    const sevBadgeClass = `badge-${severityClass}`;

    item.innerHTML = `
      <div class="finding-header-row grouped-finding-header">
        <div class="finding-main-content">
          <div class="finding-title finding-title-prominent">
            #${idx}. ${escapeHtml(f.title)}
          </div>

          <div class="finding-meta-sub grouped-finding-meta">
            <span class="finding-badges">
              <span class="badge ${statusBadgeClass}">[${f.status}]</span>
              <span class="badge ${sevBadgeClass}">[${String(f.severity || '').toUpperCase()}]</span>
            </span>

            <span>Service: <strong>${escapeHtml(f.service || '')}</strong></span>
            <span>Region: <strong>${escapeHtml(f.region || '')}</strong></span>
            <span>ID: <code>${escapeHtml(f.check_id || '')}</code></span>
          </div>
        </div>

        <div class="accordion-arrow">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none"
               stroke="currentColor" stroke-width="2">
            <polyline points="6 9 12 15 18 9"/>
          </svg>
        </div>
      </div>

      <div class="finding-details-panel">
        <div class="detail-section">
          <div class="detail-label">AFFECTED RESOURCE / SCOPE</div>
          <div class="detail-text" style="font-family: var(--font-mono); font-size: 0.8rem; word-break: break-all;">
            ${escapeHtml(f.resolved_resource || f.resource_arn || f.resource_id || 'Not explicitly identified by scanner')}
          </div>
        </div>

        ${f.resource_tags ? `
          <div class="detail-section">
            <div class="detail-label">RESOURCE TAGS</div>
            <div class="detail-text" style="color: var(--text-muted); font-size: 0.85rem;">
              ${escapeHtml(f.resource_tags)}
            </div>
          </div>
        ` : ''}

        <div class="detail-section">
          <div class="detail-label">STATUS DETAILS</div>
          <div class="detail-text">${escapeHtml(f.status_extended || f.description || '')}</div>
        </div>

        ${f.risk ? `
          <div class="detail-section">
            <div class="detail-label">RISK IMPACT</div>
            <div class="risk-alert">${escapeHtml(f.risk)}</div>
          </div>
        ` : ''}

        ${f.remediation_text ? `
          <div class="detail-section">
            <div class="detail-label">REMEDIATION GUIDANCE</div>
            <div class="detail-text">${escapeHtml(f.remediation_text)}</div>
          </div>
        ` : ''}

        ${f.remediation_code ? `
          <div class="detail-section">
            <div class="detail-label">REMEDIATION FIX COMMAND</div>
            <div class="code-remediation-box">
              <button class="copy-code-btn" data-code="${escapeHtml(f.remediation_code)}">Copy Command</button>
              <pre><code>${escapeHtml(f.remediation_code)}</code></pre>
            </div>
          </div>
        ` : ''}

        ${f.remediation_url ? `
          <div>
            <a href="${escapeHtml(f.remediation_url)}" target="_blank" rel="noopener" class="ref-link">
              ↗ Official Documentation & Remediation Guide
            </a>
          </div>
        ` : ''}
      </div>
    `;

    item.querySelector('.finding-header-row').addEventListener('click', () => {
      item.classList.toggle('open');
    });

    const copyBtn = item.querySelector('.copy-code-btn');
    if (copyBtn) {
      copyBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const code = copyBtn.getAttribute('data-code');
        navigator.clipboard.writeText(code).then(() => {
          copyBtn.textContent = "Copied!";
          setTimeout(() => {
            copyBtn.textContent = "Copy Command";
          }, 1500);
        });
      });
    }

    return item;
  }

  /*
   * Sort once before building the hierarchy.
   */
  filtered.sort((a, b) => {
    const severityA =
      severityPriority[String(a.severity || '').toLowerCase()] || 99;
    const severityB =
      severityPriority[String(b.severity || '').toLowerCase()] || 99;

    if (severityA !== severityB) {
      return severityA - severityB;
    }

    const categoryA = getServiceCategory(a.service);
    const categoryB = getServiceCategory(b.service);

    if (categoryA.priority !== categoryB.priority) {
      return categoryA.priority - categoryB.priority;
    }

    const regionA = String(a.region || 'Unknown Region').toLowerCase();
    const regionB = String(b.region || 'Unknown Region').toLowerCase();

    if (regionA !== regionB) {
      return regionA.localeCompare(regionB);
    }

    const titleA = String(a.title || '').toLowerCase();
    const titleB = String(b.title || '').toLowerCase();

    if (titleA !== titleB) {
      return titleA.localeCompare(titleB);
    }

    return String(a.check_id || '').localeCompare(String(b.check_id || ''));
  });

  findingsList.innerHTML = '';

  document.getElementById('findingsSubtitle').textContent =
    `Showing ${filtered.length} of ${currentReport.findings.length} findings`;

  if (filtered.length === 0) {
    noFindingsMsg.style.display = 'block';
    return;
  }

  noFindingsMsg.style.display = 'none';

  /*
   * Build:
   * Severity → Service → Region → Finding
   */
  let findingIndex = 0;

  const severityGroups = new Map();

  filtered.forEach(f => {
    const severityKey = String(f.severity || 'informational').toLowerCase();
    const category = getServiceCategory(f.service);
    const region = String(f.region || 'Unknown Region').trim() || 'Unknown Region';

    if (!severityGroups.has(severityKey)) {
      severityGroups.set(severityKey, {
        severityKey,
        findings: [],
        services: new Map()
      });
    }

    const severityGroup = severityGroups.get(severityKey);

    if (!severityGroup.services.has(category.key)) {
      severityGroup.services.set(category.key, {
        category,
        findings: [],
        regions: new Map()
      });
    }

    const serviceGroup = severityGroup.services.get(category.key);

    if (!serviceGroup.regions.has(region)) {
      serviceGroup.regions.set(region, []);
    }

    serviceGroup.regions.get(region).push(f);
    serviceGroup.findings.push(f);
    severityGroup.findings.push(f);
  });

  for (const [severityKey, severityGroup] of severityGroups) {
    const severityClass = getSeverityClass(severityKey);
    const severityLabel = getSeverityLabel(severityKey);

    const severitySection = document.createElement('section');
    severitySection.className = `finding-severity-section finding-severity-${severityClass}`;

    const severityHeader = document.createElement('div');
    severityHeader.className = 'finding-severity-header';
    severityHeader.innerHTML = `
      <div class="finding-severity-title">
        <span class="finding-severity-marker"></span>
        <span>${severityLabel} Findings (${severityGroup.findings.length})</span>
      </div>
      <span class="finding-severity-count">
        ${severityGroup.findings.length} failed checks
      </span>
    `;

    severitySection.appendChild(severityHeader);

    for (const serviceGroup of severityGroup.services.values()) {
      const serviceHeader = document.createElement('div');
      serviceHeader.className = `finding-service-header service-${serviceGroup.category.key}`;
      serviceHeader.innerHTML = `
        <div class="finding-service-title">
          <span class="finding-service-icon">
            ${getServiceIcon(serviceGroup.category.key)}
          </span>
          <span>${serviceGroup.category.name} (${serviceGroup.findings.length})</span>
        </div>
        <span class="finding-service-count">
          ${serviceGroup.findings.length} failed checks
        </span>
      `;

      severitySection.appendChild(serviceHeader);

      const sortedRegions = Array.from(serviceGroup.regions.entries())
        .sort(([regionA], [regionB]) => regionA.localeCompare(regionB));

      for (const [region, regionFindings] of sortedRegions) {
        const regionHeader = document.createElement('div');
        regionHeader.className = 'finding-region-header';
        regionHeader.innerHTML = `
          <div class="finding-region-title">
            <span class="finding-region-icon">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none"
                   stroke="currentColor" stroke-width="2"
                   stroke-linecap="round" stroke-linejoin="round"
                   aria-hidden="true">
                <circle cx="12" cy="12" r="9"/>
                <path d="M3 12h18"/>
                <path d="M12 3a14 14 0 0 1 0 18"/>
                <path d="M12 3a14 14 0 0 0 0 18"/>
              </svg>
            </span>
            <span>${escapeHtml(region)} (${regionFindings.length})</span>
          </div>
          <span class="finding-region-count">
            ${regionFindings.length} ${regionFindings.length === 1 ? 'failed check' : 'failed checks'}
          </span>
        `;

        severitySection.appendChild(regionHeader);

        regionFindings.forEach(f => {
          const item = buildFindingCard(f, ++findingIndex);
          severitySection.appendChild(item);
        });
      }
    }

    findingsList.appendChild(severitySection);
  }
}

// PDF Download
async function downloadPdf(customConfig) {
  if (!currentReport) {
    alert("Please upload or select a report first.");
    return;
  }

  updateManualReportFields();

  const originalTitle = document.title;
  const finalName = currentFileName.replace(/\.[^/.]+$/, "");
  document.title = finalName;

  const wasDark = document.body.classList.contains('dark-theme');

  if (wasDark) {
    renderCharts(currentReport, true);
  }

  if (severityChartInstance) {
    severityChartInstance.options.animation = false;
    severityChartInstance.resize();
    severityChartInstance.update('none');
  }

  if (servicesChartInstance) {
    servicesChartInstance.options.animation = false;
    servicesChartInstance.resize();
    servicesChartInstance.update('none');
  }

  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      window.print();
      document.title = originalTitle;
      if (wasDark) {
        renderCharts(currentReport, false);
      }
    });
  });
}


// CSV Export
function exportToCsv() {
  if (!currentReport || !currentReport.findings) return;

  const headers = ["Status", "Severity", "Service", "Region", "Check ID", "Title", "Resource", "Status Extended", "Remediation"];
  const rows = [headers];

  currentReport.findings.forEach(f => {
    rows.push([
      `"${f.status}"`,
      `"${f.severity}"`,
      `"${f.service}"`,
      `"${f.region}"`,
      `"${f.check_id}"`,
      `"${(f.title || '').replace(/"/g, '""')}"`,
      `"${(f.resource_arn || f.resource_id || '').replace(/"/g, '""')}"`,
      `"${(f.status_extended || '').replace(/"/g, '""')}"`,
      `"${(f.remediation_text || '').replace(/"/g, '""')}"`
    ]);
  });

  const csvContent = "data:text/csv;charset=utf-8," + rows.map(r => r.join(",")).join("\n");
  const encodedUri = encodeURI(csvContent);
  const a = document.createElement("a");
  a.setAttribute("href", encodedUri);
  a.setAttribute("download", `${currentFileName}_findings.csv`);
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

window.addEventListener('beforeprint', () => {
  if (severityChartInstance) {
    severityChartInstance.options.animation = false;
    severityChartInstance.resize();
    severityChartInstance.update('none');
  }
  if (servicesChartInstance) {
    servicesChartInstance.options.animation = false;
    servicesChartInstance.resize();
    servicesChartInstance.update('none');
  }
});
