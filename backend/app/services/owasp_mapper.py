"""
OWASP Top 10 2021 Mapper — Structured coverage object for all 10 categories.

Maps existing ShieldCheck scanner findings and module outputs to the OWASP Top 10
2021 categories. Produces machine-readable coverage data for the ASPM report.

Each category returns:
    status: TESTED | PARTIAL | NOT_TESTED
    findings_count: int
    highest_severity: str
    findings: list of finding IDs in this category
    modules_tested: list of scanner modules that tested this category
    notes: optional coverage limitation note

Usage:
    from app.services.owasp_mapper import compute_owasp_top10_coverage
    coverage = compute_owasp_top10_coverage(all_findings, enterprise_results)
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)

SEVERITY_ORDER = ["CRITICAL", "RED", "AMBER", "GREEN", "INFO"]


# ── OWASP Top 10 2021 Category Definitions ───────────────────────────────────

OWASP_TOP10_2021: dict[str, dict] = {
    "A01": {
        "id": "A01:2021",
        "name": "Broken Access Control",
        "finding_keys": {
            "api_bola",
            "bola_confirmed",
            "bola_vulnerable_endpoints",
            "idor_confirmed",
            "forced_browsing_sensitive",
            "auth_bypass_api",
            "auth_bypass_endpoints",
            "cms_admin_no_auth",
        },
        "modules": {"api_security_check", "business_logic_check", "api_security"},
        "status_logic": "full",
        "notes": None,
    },
    "A02": {
        "id": "A02:2021",
        "name": "Cryptographic Failures",
        "finding_keys": {
            "ssl_invalid",
            "ssl_unavailable",
            "ssl_self_signed",
            "ssl_tls10_supported",
            "ssl_tls11_supported",
            "ssl_null_cipher",
            "ssl_rc4_cipher",
            "ssl_des_cipher",
            "ssl_export_cipher",
            "ssl_heartbleed",
            "ssl_expiring_critical",
            "ssl_expiring_soon",
            "sensitive_data_in_jwt",
            "jwt_none_algorithm",
            "session_cookie_insecure",
            "headers_no_https_redirect",
            "weak_cipher_detected",
            "mixed_content_detected",
        },
        "modules": {
            "ssl_check",
            "cookie_check",
            "headers_check",
            "auth_protocol_check",
        },
        "status_logic": "full",
        "notes": None,
    },
    "A03": {
        "id": "A03:2021",
        "name": "Injection",
        "finding_keys": {
            "iast_stack_trace",
            "iast_db_error",
            "oast_ssrf_confirmed",
            "oast_log4j_surface",
            "graphql_introspection_enabled",
            "error_verbosity_db",
            "webapp_sql_injection",
            "db_errors_found",
        },
        "modules": {"iast_behavioral", "oast_check", "graphql_check"},
        "status_logic": "partial",
        "notes": (
            "Passive detection only — stack traces, DB errors, and OAST callbacks "
            "indicate injection surfaces. Manual penetration test recommended "
            "for confirmed injection validation."
        ),
    },
    "A04": {
        "id": "A04:2021",
        "name": "Insecure Design",
        "finding_keys": {
            "price_manipulation_surface",
            "workflow_bypass",
            "account_enumeration_confirmed",
            "transaction_replay_surface",
            "race_condition_surface",
            "cors_credentials_wildcard",
            "graphql_no_depth_limit",
        },
        "modules": {"business_logic_check", "graphql_check", "cors_check"},
        "status_logic": "full",
        "notes": None,
    },
    "A05": {
        "id": "A05:2021",
        "name": "Security Misconfiguration",
        "finding_keys": {
            # Headers
            "headers_many_missing",
            "headers_some_missing",
            "headers_server_version_exposed",
            "headers_tech_stack_exposed",
            "headers_no_https_redirect",
            # Webapp
            "webapp_exposed_.env",
            "webapp_exposed_.git_config",
            "debug_endpoints_exposed",
            "swagger_ui_exposed",
            # Ports
            "dangerous_ports_exposed",
            "unusual_ports_open",
            # DNS
            "dns_zone_transfer",
            # CMS
            "cms_admin_login_visible",
            "cms_install_files_exposed",
            # GraphQL
            "graphql_introspection_enabled",
            "graphql_playground_exposed",
            # HTTP Methods
            "trace_enabled",
            "trace_with_reflection",
            "dangerous_methods_enabled",
        },
        "modules": {
            "headers_check",
            "webapp_check",
            "port_check",
            "dns_check",
            "cms_check",
            "graphql_check",
            "http_methods_check",
        },
        "status_logic": "full",
        "notes": None,
    },
    "A06": {
        "id": "A06:2021",
        "name": "Vulnerable and Outdated Components",
        "finding_keys": {
            "cms_wp_vulnerable_plugins",
            "cms_wp_core_vulnerable",
            "cms_outdated",
            "jquery_outdated",
            "js_library_outdated",
            "vulnerable_libraries",
            "dependency_confusion_risk",
            "sri_hash_mismatch",
            "sri_missing",
            "malicious_package_detected",
            "typosquat_dependency",
        },
        "modules": {
            "dependency_check",
            "javascript_check",
            "cms_check",
            "cve_intelligence",
        },
        "status_logic": "full",
        "notes": None,
    },
    "A07": {
        "id": "A07:2021",
        "name": "Identification and Authentication Failures",
        "finding_keys": {
            "auth_bypass_api",
            "auth_bypass_endpoints",
            "jwt_no_expiry",
            "jwt_none_algorithm",
            "sensitive_data_in_jwt",
            "missing_rate_limiting",
            "account_enumeration_confirmed",
            "session_cookie_insecure",
            "domain_in_breach",
            "cms_default_credentials",
        },
        "modules": {
            "api_security_check",
            "auth_protocol_check",
            "cookie_check",
            "breach_check",
            "cms_check",
            "business_logic_check",
        },
        "status_logic": "full",
        "notes": None,
    },
    "A08": {
        "id": "A08:2021",
        "name": "Software and Data Integrity Failures",
        "finding_keys": {
            "sri_hash_mismatch",
            "sri_missing",
            "malicious_package_detected",
            "typosquat_dependency",
            "dependency_confusion_risk",
            "source_map_exposed",
            "terraform_state_exposed",
            "iac_container_misconfig",
        },
        "modules": {"dependency_check", "javascript_check", "container_security_check"},
        "status_logic": "full",
        "notes": None,
    },
    "A09": {
        "id": "A09:2021",
        "name": "Security Logging and Monitoring Failures",
        "finding_keys": {
            "iast_stack_trace",
            "iast_db_error",
            "error_verbosity_score",
            "debug_code_in_production",
            "debug_endpoints_exposed",
            "server_status_exposed",
        },
        "modules": {"iast_behavioral", "webapp_check", "oast_check"},
        "status_logic": "partial",
        "notes": (
            "Cannot fully test logging and monitoring without application-level access. "
            "Passive indicators assessed: error verbosity, debug endpoints, stack trace leakage."
        ),
    },
    "A10": {
        "id": "A10:2021",
        "name": "Server-Side Request Forgery (SSRF)",
        "finding_keys": {
            "oast_ssrf_confirmed",
            "ssrf_confirmed",
            "api7_ssrf_indicators",
            "graphql_ssrf",
            "metadata_ssrf_indicator",
        },
        "modules": {
            "oast_check",
            "api_security_check",
            "graphql_check",
            "container_security_check",
        },
        "status_logic": "full",
        "notes": None,
    },
}


def _get_worst_severity(findings: list[dict]) -> str:
    """Return the most severe severity label from a list of findings."""
    for sev in SEVERITY_ORDER:
        if any(f.get("severity") == sev for f in findings):
            return sev
    return "INFO"


def compute_owasp_top10_coverage(
    all_findings: list[dict],
    enterprise_results: dict[str, Any],
) -> dict:
    """
    Compute OWASP Top 10 2021 coverage from all scan findings.

    Args:
        all_findings: Combined list of classified + enterprise findings
        enterprise_results: Dict of enterprise module raw results

    Returns:
        {
            "categories": {
                "A01": {
                    "id": "A01:2021",
                    "name": "Broken Access Control",
                    "status": "TESTED",
                    "findings_count": 2,
                    "highest_severity": "CRITICAL",
                    "findings": [...],
                    "modules_tested": [...],
                    "notes": None,
                },
                ...
            },
            "owasp_coverage_score": 90,
            "owasp_overall_pass": 7,
            "owasp_partial_test": 2,
            "owasp_not_tested": 1,
        }
    """
    # Build lookup sets
    all_finding_keys = set()
    for f in all_findings:
        key = f.get("key") or f.get("check_type") or ""
        if key:
            all_finding_keys.add(key)

    all_modules_run = set()
    # Also add module prefixes from findings checks
    for f in all_findings:
        check = f.get("check") or f.get("module") or ""
        if check:
            # Reconstruct the _check suffix since findings often use just the prefix or full name
            if check.endswith("_check") or check.endswith("_security"):
                all_modules_run.add(check)
            else:
                all_modules_run.add(f"{check}_check")

    # From enterprise results
    for k, v in enterprise_results.items():
        if v and not (isinstance(v, dict) and v.get("error")):
            all_modules_run.add(k)
            all_modules_run.add(
                f"{k}_check"
            )  # Also add the suffixed version just in case

    categories: dict[str, dict] = {}
    tested_count = 0
    partial_count = 0
    pass_count = 0

    for cat_id, cat_def in OWASP_TOP10_2021.items():
        # Find matching findings
        cat_findings = [
            f
            for f in all_findings
            if (f.get("key") or f.get("check_type") or "") in cat_def["finding_keys"]
        ]

        # Check if modules for this category were tested
        modules_tested = list(cat_def["modules"] & all_modules_run)
        has_module_coverage = len(modules_tested) > 0

        # Determine status
        if not has_module_coverage:
            status = "NOT_TESTED"
        elif cat_def["status_logic"] == "partial":
            status = "PARTIAL"
        else:
            status = "TESTED"

        if status == "TESTED":
            tested_count += 1
        elif status == "PARTIAL":
            partial_count += 1

        if status in ("TESTED", "PARTIAL") and len(cat_findings) == 0:
            pass_count += 1

        categories[cat_id] = {
            "id": cat_def["id"],
            "name": cat_def["name"],
            "status": status,
            "findings_count": len(cat_findings),
            "highest_severity": (
                _get_worst_severity(cat_findings) if cat_findings else "INFO"
            ),
            "findings": [
                f.get("key") or f.get("check_type") or "" for f in cat_findings
            ][
                :20
            ],  # Cap at 20 finding IDs per category
            "modules_tested": modules_tested,
            "notes": cat_def.get("notes"),
        }

    not_tested_count = 10 - tested_count - partial_count
    coverage_score = int(round((tested_count + partial_count * 0.5) / 10 * 100))

    return {
        "categories": categories,
        "owasp_coverage_score": coverage_score,
        "owasp_overall_pass": pass_count,
        "owasp_partial_test": partial_count,
        "owasp_not_tested": not_tested_count,
    }
