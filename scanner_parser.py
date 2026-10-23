"""
scanner_parser.py
Universal security report parser and normalizer.
Supports:
- Prowler JSON (JSON array & NDJSON / JSON Lines)
- Prowler HTML reports (tables, cards, embedded scripts)
- Trivy vulnerability & misconfiguration JSON
- Checkov infrastructure-as-code scan JSON
- Generic security scanner JSON & HTML reports
"""

import json
import re
from datetime import datetime, timezone
from bs4 import BeautifulSoup


def decode_bytes(raw):
    """Decode file bytes robustly (UTF-8, UTF-8 BOM, UTF-16 LE/BE).
    Windows PowerShell redirects (`prowler ... > out.json`) often produce UTF-16."""
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8", errors="replace")
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="replace")
    # UTF-16 without BOM: lots of NUL bytes
    if raw[:200].count(b"\x00") > 20:
        enc = "utf-16-le" if raw[1:2] == b"\x00" else "utf-16-be"
        return raw.decode(enc, errors="replace")
    return raw.decode("utf-8", errors="replace")


def _flatten_ocsf(item):
    """Convert a Prowler v4/v5 OCSF finding into the flat legacy structure
    the rest of the parser understands. Non-OCSF items are returned unchanged."""
    if not isinstance(item, dict) or not ("finding_info" in item or "status_code" in item):
        return item
    fi = item.get("finding_info") or {}
    meta = item.get("metadata") or {}
    cloud = item.get("cloud") or {}
    acct = cloud.get("account") or {}
    res = (item.get("resources") or [{}])[0] or {}
    grp = res.get("group") or {}
    rem = item.get("remediation") or {}
    refs = rem.get("references") or []
    unmapped = item.get("unmapped") or {}
    compliance = unmapped.get("compliance") or item.get("compliance") or {}
    return {
        "check_id": meta.get("event_code") or fi.get("uid"),
        "check_title": fi.get("title") or item.get("message"),
        "status": item.get("status_code"),
        "severity": item.get("severity"),
        "service": grp.get("name") or res.get("type"),
        "region": res.get("region") or cloud.get("region"),
        "account_id": acct.get("uid"),
        "provider": cloud.get("provider"),
        "resource_id": res.get("uid") or res.get("name"),
        "resource_tags": res.get("labels") or "",
        "status_extended": item.get("status_detail") or item.get("message"),
        "description": fi.get("desc"),
        "risk": item.get("risk_details"),
        "compliance": compliance,
        "categories": unmapped.get("categories") or [],
        "remediation": {
            "recommendation": {
                "text": rem.get("desc") if isinstance(rem.get("desc"), str) else "",
                "url": refs[0] if refs and isinstance(refs[0], str) else "",
            }
        },
    }


def _safe_str(val, default=""):
    if val is None:
        return default
    return str(val).strip()


def _normalize_severity(sev):
    if not sev:
        return "medium"
    s = str(sev).lower().strip()
    if any(k in s for k in ["crit", "fatal"]):
        return "critical"
    if "high" in s:
        return "high"
    if any(k in s for k in ["med", "mod"]):
        return "medium"
    if "low" in s:
        return "low"
    if any(k in s for k in ["info", "note", "none"]):
        return "informational"
    return "medium"


def _normalize_status(st):
    if not st:
        return "FAIL"
    s = str(st).upper().strip()
    if any(k in s for k in ["FAIL", "FAILED", "ERROR", "VULNERABLE", "ALARM", "BAD", "NON_COMPLIANT"]):
        return "FAIL"
    if any(k in s for k in ["PASS", "PASSED", "OK", "SUCCESS", "COMPLIANT"]):
        return "PASS"
    if any(k in s for k in ["MANUAL", "MANUAL_VERIFICATION"]):
        return "MANUAL"
    if any(k in s for k in ["MUTE", "MUTED", "SKIP", "SKIPPED", "SUPPRESSED", "IGNORE"]):
        return "MUTED"
    return "INFO"


def _resolve_affected_resource(finding_data):
    """
    Implements a generic fallback chain to resolve the affected resource or scope.
    Returns a dict with displayValue, sourceType, and confidence.
    """
    def is_empty(val):
        if not val:
            return True
        v = str(val).strip().lower()
        if v in ["", "null", "undefined", "n/a", "na", "none", "-"]:
            return True
        return False

    res_id = finding_data.get("resource_id", finding_data.get("ResourceId", finding_data.get("Resource", "")))
    status_ext = finding_data.get("status_extended", finding_data.get("StatusExtended", ""))
    tags = finding_data.get("resource_tags", finding_data.get("Tags", ""))
    service = str(finding_data.get("service_name", finding_data.get("service", "general"))).strip()
    region = str(finding_data.get("region", "global")).strip()
    check_title = str(finding_data.get("check_title", finding_data.get("title", ""))).lower()
    check_id = str(finding_data.get("check_id", finding_data.get("id", ""))).lower()

    # Priority 1: Exact Prowler Resource ID
    if not is_empty(res_id):
        return {
            "displayValue": str(res_id).strip(),
            "sourceType": "resource_id",
            "confidence": "exact"
        }

    # Priority 2: Extract an explicit resource from Status Extended / Status Details
    if status_ext:
        text = str(status_ext)
        # AWS ARN
        arn_match = re.search(r'(arn:aws:[^\s\'"]+)', text)
        if arn_match:
            return {"displayValue": arn_match.group(1), "sourceType": "status_details", "confidence": "derived"}
        
        # Well known IDs
        id_match = re.search(r'\b(i-[a-zA-Z0-9]{8,}|vol-[a-zA-Z0-9]{8,}|snap-[a-zA-Z0-9]{8,}|sg-[a-zA-Z0-9]{8,}|acl-[a-zA-Z0-9]{8,}|vpc-[a-zA-Z0-9]{8,}|subnet-[a-zA-Z0-9]{8,}|rtb-[a-zA-Z0-9]{8,}|igw-[a-zA-Z0-9]{8,}|nat-[a-zA-Z0-9]{8,})\b', text)
        if id_match:
            return {"displayValue": id_match.group(1), "sourceType": "status_details", "confidence": "derived"}
        
        # Explicit Noun + Name patterns
        noun_match = re.search(r'(S3 Bucket|EKS cluster|RDS Instance|RDS Cluster|RDS Snapshot|IAM Role|IAM User|Lambda function|CloudTrail trail|Load Balancer|CloudFront distribution|Secrets Manager secret|DynamoDB table|SNS topic|SQS queue|OpenSearch domain)\s+([a-zA-Z0-9\-_]+)', text, re.IGNORECASE)
        if noun_match:
            return {"displayValue": f"{noun_match.group(1)}: {noun_match.group(2)}", "sourceType": "status_details", "confidence": "derived"}

    # Priority 3: Resource Tags
    if not is_empty(tags):
        tag_str = str(tags)
        name_match = re.search(r'Name=([a-zA-Z0-9\-_]+)', tag_str, re.IGNORECASE)
        if name_match:
            return {"displayValue": f"Tagged Resource: {name_match.group(1)}", "sourceType": "tags", "confidence": "derived"}

    # Priority 4: Generic Scope Fallback
    text_lower = str(status_ext).lower()
    
    if "root" in check_title or "root" in check_id or "root" in text_lower:
        return {"displayValue": "AWS Root Account", "sourceType": "scope", "confidence": "derived"}
    
    if service.lower() == "iam" and ("account" in check_title or "password" in check_title or "policy" in check_title or "credential" in check_title):
        return {"displayValue": "Account-level IAM configuration", "sourceType": "scope", "confidence": "derived"}

    if service.lower() == "s3" and ("account" in check_title or "block public access" in check_title or "macie" in check_title):
        return {"displayValue": "Account-level S3 configuration", "sourceType": "scope", "confidence": "derived"}
        
    if region and region.lower() not in ["global", "unknown", ""] and not is_empty(region):
        if service.lower() not in ["general", "unknown", ""] and not is_empty(service):
            svc_disp = service.upper() if len(service) <= 3 else service.capitalize()
            return {"displayValue": f"{svc_disp} configuration \u2014 {region}", "sourceType": "scope", "confidence": "derived"}

    if service.lower() not in ["general", "unknown", ""] and not is_empty(service):
        svc_disp = service.upper() if len(service) <= 3 else service.capitalize()
        if "account" in check_title or "account" in text_lower:
            return {"displayValue": f"{svc_disp} \u2014 Account-level configuration", "sourceType": "scope", "confidence": "derived"}
        return {"displayValue": f"{svc_disp} security configuration", "sourceType": "scope", "confidence": "derived"}

    # Final Fallback
    return {"displayValue": "Not explicitly identified by scanner", "sourceType": "unspecified", "confidence": "derived"}


class NormalizedFinding:
    def __init__(self, finding_data):
        self.check_id = _safe_str(finding_data.get("check_id") or finding_data.get("CheckID") or finding_data.get("id"))
        self.title = _safe_str(
            finding_data.get("check_title") or finding_data.get("CheckTitle") or 
            finding_data.get("title") or finding_data.get("check_name") or self.check_id or "Security Check"
        )
        self.status = _normalize_status(
            finding_data.get("status") or finding_data.get("Status") or finding_data.get("state")
        )
        self.severity = _normalize_severity(
            finding_data.get("severity") or finding_data.get("Severity") or finding_data.get("level")
        )
        self.service = _safe_str(
            finding_data.get("service_name") or finding_data.get("ServiceName") or 
            finding_data.get("service") or finding_data.get("Service") or "general"
        ).lower()
        self.region = _safe_str(
            finding_data.get("region") or finding_data.get("Region") or 
            finding_data.get("location") or "global"
        )
        self.account_id = _safe_str(
            finding_data.get("account_id") or finding_data.get("AccountId") or 
            finding_data.get("account") or finding_data.get("project_id") or "default"
        )
        self.provider = _safe_str(
            finding_data.get("provider") or finding_data.get("Provider") or "cloud"
        ).lower()
        self.resource_id = _safe_str(
            finding_data.get("resource_id") or finding_data.get("ResourceId") or 
            finding_data.get("resource") or finding_data.get("Target") or ""
        )
        self.resource_arn = _safe_str(
            finding_data.get("resource_arn") or finding_data.get("ResourceArn") or self.resource_id
        )
        self.resource_tags = _safe_str(
            finding_data.get("resource_tags") or finding_data.get("ResourceTags") or finding_data.get("tags") or finding_data.get("Tags") or ""
        )
        self.status_extended = _safe_str(
            finding_data.get("status_extended") or finding_data.get("StatusExtended") or 
            finding_data.get("message") or finding_data.get("details") or self.title
        )
        self.description = _safe_str(
            finding_data.get("description") or finding_data.get("Description") or self.title
        )
        self.risk = _safe_str(
            finding_data.get("risk") or finding_data.get("Risk") or ""
        )
        
        # Remediation resolution
        remediation_obj = finding_data.get("remediation") or finding_data.get("Remediation") or {}
        if isinstance(remediation_obj, dict):
            rec = remediation_obj.get("Recommendation") or remediation_obj.get("recommendation") or {}
            code = remediation_obj.get("Code") or remediation_obj.get("code") or {}
            self.remediation_text = _safe_str(
                rec.get("Text") or rec.get("text") or finding_data.get("remediation_recommendation_text") or
                remediation_obj.get("text") or finding_data.get("resolution") or ""
            )
            self.remediation_url = _safe_str(
                rec.get("Url") or rec.get("url") or finding_data.get("remediation_recommendation_url") or
                finding_data.get("related_url") or finding_data.get("RelatedUrl") or ""
            )
            self.remediation_code = _safe_str(
                code.get("CLI") or code.get("cli") or code.get("Terraform") or code.get("terraform") or
                code.get("NativeIaC") or finding_data.get("remediation_recommendation_code_cli") or ""
            )
        else:
            self.remediation_text = _safe_str(
                finding_data.get("remediation_recommendation_text") or str(remediation_obj) or ""
            )
            self.remediation_url = _safe_str(
                finding_data.get("remediation_recommendation_url") or finding_data.get("related_url") or ""
            )
            self.remediation_code = _safe_str(
                finding_data.get("remediation_recommendation_code_cli") or ""
            )

        # Compliance parsing
        comp = finding_data.get("compliance") or finding_data.get("Compliance") or {}
        self.compliance = {}
        if isinstance(comp, dict):
            for k, v in comp.items():
                if isinstance(v, list):
                    self.compliance[k] = [str(x) for x in v]
                else:
                    self.compliance[k] = [str(v)]
        elif isinstance(comp, str) and comp:
            # parse string format e.g. "CIS-1.5: 1.1, 1.2 | NIST: AC-2"
            parts = comp.split("|")
            for part in parts:
                if ":" in part:
                    k, v = part.split(":", 1)
                    self.compliance[k.strip()] = [x.strip() for x in v.split(",") if x.strip()]

        categories = finding_data.get("categories") or finding_data.get("Categories") or []
        if isinstance(categories, list):
            self.categories = [str(c) for c in categories]
        elif isinstance(categories, str) and categories:
            self.categories = [c.strip() for c in categories.split("|") if c.strip()]
        else:
            self.categories = []

        # Resolve Affected Resource
        resolved = _resolve_affected_resource(finding_data)
        self.resolved_resource = resolved["displayValue"]
        self.resolved_source = resolved["sourceType"]
        self.resolved_confidence = resolved["confidence"]

    def to_dict(self):
        return {
            "check_id": self.check_id,
            "title": self.title,
            "status": self.status,
            "severity": self.severity,
            "service": self.service,
            "region": self.region,
            "account_id": self.account_id,
            "provider": self.provider,
            "resource_id": self.resource_id,
            "resource_arn": self.resource_arn,
            "status_extended": self.status_extended,
            "description": self.description,
            "risk": self.risk,
            "remediation_text": self.remediation_text,
            "remediation_url": self.remediation_url,
            "remediation_code": self.remediation_code,
            "compliance": self.compliance,
            "categories": self.categories,
            "resource_tags": self.resource_tags,
            "resolved_resource": self.resolved_resource,
            "resolved_source": self.resolved_source,
            "resolved_confidence": self.resolved_confidence
        }


class ScanReport:
    def __init__(self, raw_findings, metadata=None):
        self.metadata = metadata or {}
        self.raw_findings = raw_findings
        self.raw_findings = [_flatten_ocsf(f) for f in raw_findings if isinstance(f, dict)]
        self.findings = [NormalizedFinding(f) for f in self.raw_findings]
        self._calculate_metrics()

    def _calculate_metrics(self):
        self.total_checks = len(self.findings)
        self.passed_checks = sum(1 for f in self.findings if f.status == "PASS")
        self.failed_checks = sum(1 for f in self.findings if f.status == "FAIL")
        self.muted_checks = sum(1 for f in self.findings if f.status == "MUTED")
        self.manual_checks = sum(1 for f in self.findings if f.status == "MANUAL")
        self.info_checks = sum(1 for f in self.findings if f.status == "INFO")

        # Total unique resources
        resources = set()
        for f in self.findings:
            if f.resource_id and f.resource_id != "N/A":
                resources.add(f.resource_id)
        self.total_resources = len(resources)

        # Security Score: 0 to 100%
        # Score calculation: passed / (passed + failed)
        eval_total = self.passed_checks + self.failed_checks
        if eval_total > 0:
            self.security_score = round((self.passed_checks / eval_total) * 100, 1)
        else:
            self.security_score = 100.0

        # Assign Grade
        if self.security_score >= 90:
            self.security_grade = "A+"
            self.posture_text = "Excellent"
        elif self.security_score >= 80:
            self.security_grade = "A"
            self.posture_text = "Good"
        elif self.security_score >= 70:
            self.security_grade = "B"
            self.posture_text = "Fair"
        elif self.security_score >= 50:
            self.security_grade = "C"
            self.posture_text = "Needs Improvement"
        else:
            self.security_grade = "F"
            self.posture_text = "Critical Attention Required"

        # Severity breakdown of FAILS (and overall)
        self.severity_counts = {
            "critical": sum(1 for f in self.findings if f.severity == "critical" and f.status == "FAIL"),
            "high": sum(1 for f in self.findings if f.severity == "high" and f.status == "FAIL"),
            "medium": sum(1 for f in self.findings if f.severity == "medium" and f.status == "FAIL"),
            "low": sum(1 for f in self.findings if f.severity == "low" and f.status == "FAIL"),
            "informational": sum(1 for f in self.findings if f.severity == "informational" and f.status == "FAIL")
        }
        
        self.overall_severity_counts = {
            "critical": sum(1 for f in self.findings if f.severity == "critical"),
            "high": sum(1 for f in self.findings if f.severity == "high"),
            "medium": sum(1 for f in self.findings if f.severity == "medium"),
            "low": sum(1 for f in self.findings if f.severity == "low"),
            "informational": sum(1 for f in self.findings if f.severity == "informational")
        }

        # Service breakdown
        service_stats = {}
        for f in self.findings:
            srv = f.service or "general"
            if srv not in service_stats:
                service_stats[srv] = {"pass": 0, "fail": 0, "total": 0}
            service_stats[srv]["total"] += 1
            if f.status == "PASS":
                service_stats[srv]["pass"] += 1
            elif f.status == "FAIL":
                service_stats[srv]["fail"] += 1

        self.service_stats = service_stats
        # Top failed services
        top_failed = [
            {"service": srv, "fail_count": stats["fail"], "total": stats["total"], "pass_count": stats["pass"]}
            for srv, stats in service_stats.items() if stats["fail"] > 0
        ]
        top_failed.sort(key=lambda x: x["fail_count"], reverse=True)
        self.top_failed_services = top_failed

        # Compliance breakdown
        comp_stats = {}
        for f in self.findings:
            if f.compliance:
                for fw in f.compliance.keys():
                    if fw not in comp_stats:
                        comp_stats[fw] = {"pass": 0, "fail": 0, "total": 0}
                    comp_stats[fw]["total"] += 1
                    if f.status == "PASS":
                        comp_stats[fw]["pass"] += 1
                    elif f.status == "FAIL":
                        comp_stats[fw]["fail"] += 1

        for fw, data in comp_stats.items():
            tot = data["pass"] + data["fail"]
            data["compliance_pct"] = round((data["pass"] / tot * 100), 1) if tot > 0 else 100.0

        self.compliance_summary = comp_stats

        # Extract common metadata if not set
        if not self.metadata.get("account_id") and self.findings:
            for f in self.findings:
                if f.account_id and f.account_id != "default":
                    self.metadata["account_id"] = f.account_id
                    break

        if not self.metadata.get("provider") and self.findings:
            for f in self.findings:
                if f.provider and f.provider != "cloud":
                    self.metadata["provider"] = f.provider.upper()
                    break

        if not self.metadata.get("timestamp"):
            self.metadata["timestamp"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    def to_dict(self):
        return {
            "metadata": self.metadata,
            "summary": {
                "total_checks": self.total_checks,
                "passed_checks": self.passed_checks,
                "failed_checks": self.failed_checks,
                "muted_checks": self.muted_checks,
                "info_checks": self.info_checks,
                "security_score": self.security_score,
                "security_grade": self.security_grade,
                "posture_text": self.posture_text,
                "severity_counts": self.severity_counts,
                "overall_severity_counts": self.overall_severity_counts,
                "top_failed_services": self.top_failed_services,
                "compliance_summary": self.compliance_summary,
                "manual_checks": self.manual_checks,
                "total_resources": self.total_resources
            },
            "findings": [f.to_dict() for f in self.findings]
        }


def parse_json_content(content_str):
    """Parses JSON array, NDJSON, or scanner-specific schemas."""
    raw_findings = []
    metadata = {}
    content_str = content_str.strip()

    # Try standard JSON parse
    try:
        data = json.loads(content_str)
        if isinstance(data, list):
            raw_findings = data
        elif isinstance(data, dict):
            # Check for Trivy format
            if "Results" in data:
                metadata["scanner"] = "Trivy"
                metadata["artifact_name"] = data.get("ArtifactName", "Container/FS")
                for res in data["Results"]:
                    target = res.get("Target", "")
                    for vuln in res.get("Vulnerabilities", []):
                        raw_findings.append({
                            "check_id": vuln.get("VulnerabilityID"),
                            "check_title": f"{vuln.get('PkgName')} - {vuln.get('VulnerabilityID')}",
                            "status": "FAIL",
                            "severity": vuln.get("Severity"),
                            "service": "packages",
                            "resource_id": target,
                            "status_extended": f"Installed: {vuln.get('InstalledVersion')}, Fixed in: {vuln.get('FixedVersion', 'None')}",
                            "description": vuln.get("Description", vuln.get("Title", "")),
                            "risk": f"CVSS Score: {vuln.get('CVSS', {}).get('nvd', {}).get('V3Score', 'N/A')}",
                            "remediation": {
                                "recommendation": {
                                    "text": f"Upgrade {vuln.get('PkgName')} to version {vuln.get('FixedVersion', 'latest')}",
                                    "url": vuln.get("PrimaryURL", "")
                                }
                            }
                        })
                    for misconf in res.get("Misconfigurations", []):
                        raw_findings.append({
                            "check_id": misconf.get("ID"),
                            "check_title": misconf.get("Title"),
                            "status": misconf.get("Status", "FAIL"),
                            "severity": misconf.get("Severity"),
                            "service": "config",
                            "resource_id": target,
                            "status_extended": misconf.get("Message"),
                            "description": misconf.get("Description"),
                            "risk": "Misconfiguration in infrastructure file",
                            "remediation": {
                                "recommendation": {
                                    "text": misconf.get("Resolution", ""),
                                    "url": misconf.get("PrimaryURL", "")
                                }
                            }
                        })
            # Check for Checkov format
            elif "results" in data and isinstance(data["results"], dict):
                metadata["scanner"] = "Checkov"
                chk_res = data["results"]
                for f_chk in chk_res.get("failed_checks", []):
                    raw_findings.append({
                        "check_id": f_chk.get("check_id"),
                        "check_title": f_chk.get("check_name"),
                        "status": "FAIL",
                        "severity": f_chk.get("severity") or "high",
                        "service": f_chk.get("check_type") or "iac",
                        "resource_id": f_chk.get("resource"),
                        "status_extended": f"Failed check on {f_chk.get('file_path')}:{f_chk.get('file_line_range', '')}",
                        "description": f_chk.get("check_name"),
                        "remediation": {
                            "recommendation": {
                                "text": f_chk.get("guideline", "Refer to Checkov documentation for remediation"),
                                "url": f_chk.get("guideline", "")
                            }
                        }
                    })
                for p_chk in chk_res.get("passed_checks", []):
                    raw_findings.append({
                        "check_id": p_chk.get("check_id"),
                        "check_title": p_chk.get("check_name"),
                        "status": "PASS",
                        "severity": p_chk.get("severity") or "medium",
                        "service": p_chk.get("check_type") or "iac",
                        "resource_id": p_chk.get("resource"),
                        "status_extended": "Passed compliance policy",
                        "description": p_chk.get("check_name")
                    })
            # Check for wrapper like {"findings": [...]} or {"data": [...]}
            elif "findings" in data and isinstance(data["findings"], list):
                raw_findings = data["findings"]
            elif "data" in data and isinstance(data["data"], list):
                raw_findings = data["data"]
            else:
                # Single finding object
                raw_findings = [data]
    except Exception:
        # Try Newline Delimited JSON (NDJSON)
        lines = content_str.splitlines()
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    raw_findings.append(item)
            except Exception:
                continue

    if not metadata.get("scanner"):
        metadata["scanner"] = "Prowler / Security Scanner"

    raw_findings = [f for f in raw_findings if isinstance(f, dict)]
    if not raw_findings:
        raise ValueError(
            "No findings found in the JSON. Expected a Prowler JSON/OCSF array, "
            "NDJSON, Trivy or Checkov report."
        )
    return ScanReport(raw_findings, metadata)


def parse_html_content(html_str):
    """Parses Prowler or generic HTML security reports."""
    soup = BeautifulSoup(html_str, "html.parser")
    metadata = {"scanner": "Security Scanner (HTML)"}
    raw_findings = []

    # 1. Check for embedded JSON inside <script>
    scripts = soup.find_all("script")
    for s in scripts:
        text = s.string or ""
        # Look for JSON arrays or finding variables
        match = re.search(r'(?:findings|data|results|table_data)\s*=\s*(\[.*?\]);', text, re.DOTALL)
        if match:
            try:
                data = json.loads(match.group(1))
                if isinstance(data, list) and len(data) > 0:
                    metadata["scanner"] = "Prowler (Embedded JS Data)"
                    return ScanReport(data, metadata)
            except Exception:
                pass

    # 2. Extract overview cards / text metadata
    text_content = soup.get_text()
    acc_match = re.search(r'Account\s*(?:ID)?\s*[:=]\s*([0-9a-zA-Z\-_]+)', text_content, re.IGNORECASE)
    if acc_match:
        metadata["account_id"] = acc_match.group(1)

    prov_match = re.search(r'Provider\s*[:=]\s*(AWS|Azure|GCP|Kubernetes)', text_content, re.IGNORECASE)
    if prov_match:
        metadata["provider"] = prov_match.group(1).upper()

    date_match = re.search(r'Date\s*[:=]\s*([0-9]{4}-[0-9]{2}-[0-9]{2}[^|\n]*)', text_content, re.IGNORECASE)
    if date_match:
        metadata["timestamp"] = date_match.group(1).strip()

    # 3. Find findings tables
    tables = soup.find_all("table")
    for table in tables:
        rows = table.find_all("tr")
        if not rows:
            continue

        # Inspect headers
        header_cells = rows[0].find_all(["th", "td"])
        headers = [c.get_text().strip().lower() for c in header_cells]

        # Check if table looks like security findings
        if not any(h in ["status", "severity", "check id", "check title", "resource", "service"] for h in headers):
            continue

        # Map header positions
        col_map = {}
        for idx, h in enumerate(headers):
            h_lower = h.lower()
            if h_lower == "status":
                col_map["status"] = idx
            elif "severity" in h_lower or "level" in h_lower:
                col_map["severity"] = idx
            elif "service" in h_lower:
                col_map["service"] = idx
            elif "region" in h_lower or "location" in h_lower:
                col_map["region"] = idx
            elif "check id" in h_lower or h_lower == "id":
                col_map["check_id"] = idx
            elif "title" in h_lower or "check" in h_lower:
                col_map["check_title"] = idx
            elif "resource id" in h_lower or h_lower == "resource" or h_lower == "resource_id":
                col_map["resource_id"] = idx
            elif "extended" in h_lower or "detail" in h_lower:
                col_map["status_extended"] = idx
            elif "risk" in h_lower:
                col_map["risk"] = idx
            elif "url" in h_lower and ("recommend" in h_lower or "remediat" in h_lower or "reference" in h_lower):
                col_map["remediation_url"] = idx
            elif "remediat" in h_lower or "fix" in h_lower or "solution" in h_lower or "recommendation" in h_lower:
                col_map["remediation"] = idx
            elif "tag" in h_lower:
                col_map["resource_tags"] = idx
            elif "compliance" in h_lower:
                col_map["compliance"] = idx

        for row in rows[1:]:
            cells = row.find_all(["td", "th"])
            if len(cells) < 2:
                continue

            def get_cell(key, default=""):
                if key in col_map and col_map[key] < len(cells):
                    return cells[col_map[key]].get_text().strip()
                return default

            raw_findings.append({
                "status": get_cell("status", "FAIL"),
                "severity": get_cell("severity", "medium"),
                "service": get_cell("service", "general"),
                "region": get_cell("region", "global"),
                "check_id": get_cell("check_id", ""),
                "check_title": get_cell("check_title", "Security Check"),
                "resource_id": get_cell("resource_id", ""),
                "resource_tags": get_cell("resource_tags", ""),
                "status_extended": get_cell("status_extended", ""),
                "risk": get_cell("risk", ""),
                "compliance": get_cell("compliance", ""),
                "remediation": {
                    "recommendation": {
                        "text": get_cell("remediation", ""),
                        "url": get_cell("remediation_url", "")
                    }
                }
            })

    if not raw_findings:
        raise ValueError(
            "No findings table found in the HTML. The report needs a table with "
            "columns such as Status, Severity, Check ID / Check Title."
        )
    return ScanReport(raw_findings, metadata)


def parse_report_file(filepath):
    """Detects whether file is JSON or HTML and parses it."""
    with open(filepath, "rb") as f:
        content = decode_bytes(f.read())

    lower_path = filepath.lower()
    if lower_path.endswith(".html") or lower_path.endswith(".htm") or "<html" in content[:200].lower():
        return parse_html_content(content)
    else:
        return parse_json_content(content)
