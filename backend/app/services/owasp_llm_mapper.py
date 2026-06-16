"""
OWASP LLM Top 10 2025 Mapper — LLM-specific security coverage object.

Maps ShieldCheck LLM security scan findings to the OWASP LLM Top 10 2025
categories. Integrates with the llm_security_check.py scanner results.

Usage:
    from app.services.owasp_llm_mapper import compute_owasp_llm_coverage
    coverage = compute_owasp_llm_coverage(llm_security_results, all_findings)
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)

SEVERITY_ORDER = ["CRITICAL", "RED", "AMBER", "GREEN", "INFO"]


# ── OWASP LLM Top 10 2025 Category Definitions ───────────────────────────────

OWASP_LLM_2025: dict[str, dict] = {
    "LLM01": {
        "id": "LLM01:2025",
        "name": "Prompt Injection",
        "description": (
            "Manipulating LLM inputs through adversarial prompts embedded in "
            "untrusted content, causing the model to execute attacker-controlled instructions."
        ),
        "finding_keys": {
            "llm_prompt_injection_surface",
            "llm_indirect_prompt_injection",
            "llm_url_input_accepted",
            "llm_document_input_accepted",
        },
        "llm_result_fields": ["prompt_injection_surfaces"],
        "notes": (
            "Passive assessment only — detected endpoints accepting untrusted content "
            "(URLs, documents, emails) without input sanitization signals."
        ),
    },
    "LLM02": {
        "id": "LLM02:2025",
        "name": "Sensitive Information Disclosure",
        "description": (
            "LLM inadvertently reveals confidential data, system information, "
            "API keys, or PII through its generated outputs."
        ),
        "finding_keys": {
            "llm_system_prompt_leaked",
            "llm_api_key_exposed",
            "llm_pii_in_response",
            "llm_internal_path_disclosed",
        },
        "llm_result_fields": ["system_prompt_leaked", "api_keys_in_response"],
        "notes": None,
    },
    "LLM03": {
        "id": "LLM03:2025",
        "name": "Supply Chain",
        "description": (
            "Vulnerabilities in the LLM supply chain, including third-party model "
            "providers, pre-trained models, and fine-tuning data sources."
        ),
        "finding_keys": {
            "llm_outdated_model",
            "llm_third_party_provider_detected",
            "malicious_package_detected",
            "typosquat_dependency",
        },
        "llm_result_fields": ["models_detected"],
        "notes": (
            "Model version enumeration used to assess supply chain risk. "
            "Outdated model versions mapped to known vulnerabilities."
        ),
    },
    "LLM04": {
        "id": "LLM04:2025",
        "name": "Data and Model Poisoning",
        "description": (
            "Manipulating training data or fine-tuning processes to introduce "
            "backdoors, biases, or deliberately incorrect behaviors into LLM models."
        ),
        "finding_keys": set(),  # Cannot test passively
        "llm_result_fields": [],
        "notes": (
            "Cannot be assessed passively from external scanning. "
            "Requires access to model training pipeline and data governance controls. "
            "Manual review required."
        ),
    },
    "LLM05": {
        "id": "LLM05:2025",
        "name": "Improper Output Handling",
        "description": (
            "Insufficient validation, sanitization, or handling of LLM-generated "
            "outputs before they are passed to other system components or downstream processes."
        ),
        "finding_keys": {
            "llm_response_not_sanitized",
            "llm_xss_in_response",
            "llm_html_in_response",
        },
        "llm_result_fields": [],
        "notes": (
            "Partially assessed via response content analysis. "
            "Full assessment requires testing all downstream output handling paths."
        ),
    },
    "LLM06": {
        "id": "LLM06:2025",
        "name": "Excessive Agency",
        "description": (
            "LLM-based systems are granted excessive functionality, permissions, "
            "or autonomy, enabling exploitation to perform unintended harmful actions."
        ),
        "finding_keys": {
            "llm_excessive_agency_unauth",
            "llm_action_endpoint_detected",
            "llm_tool_calling_detected",
            "llm_no_confirmation_step",
        },
        "llm_result_fields": ["excessive_agency_endpoints"],
        "notes": None,
    },
    "LLM07": {
        "id": "LLM07:2025",
        "name": "System Prompt Leakage",
        "description": (
            "LLM system prompts containing sensitive instructions, business logic, "
            "or confidential information are exposed through model responses."
        ),
        "finding_keys": {
            "llm_system_prompt_leaked",
            "llm_system_prompt_partial_leak",
        },
        "llm_result_fields": ["system_prompt_leaked"],
        "notes": None,
    },
    "LLM08": {
        "id": "LLM08:2025",
        "name": "Vector and Embedding Weaknesses",
        "description": (
            "Vulnerabilities in how vector embeddings are generated, stored, "
            "and retrieved, enabling data reconstruction or poisoning of RAG systems."
        ),
        "finding_keys": {
            "llm_rag_endpoint_detected",
            "llm_vector_db_exposed",
        },
        "llm_result_fields": [],
        "notes": (
            "Cannot be fully assessed without access to embedding pipeline. "
            "RAG endpoints detected where applicable."
        ),
    },
    "LLM09": {
        "id": "LLM09:2025",
        "name": "Misinformation",
        "description": (
            "LLMs produce plausible but incorrect information, potentially leading "
            "to harmful decisions when used in high-stakes or autonomous contexts."
        ),
        "finding_keys": set(),  # Cannot test passively
        "llm_result_fields": [],
        "notes": (
            "Cannot be assessed via external passive scanning. "
            "Requires manual red-teaming of model outputs."
        ),
    },
    "LLM10": {
        "id": "LLM10:2025",
        "name": "Unbounded Consumption",
        "description": (
            "LLM applications that lack resource controls, enabling attackers to "
            "cause denial of service, excessive costs, or model extraction through "
            "high-volume or resource-intensive queries."
        ),
        "finding_keys": {
            "llm_no_rate_limiting",
            "llm_no_input_length_limit",
            "llm_unauthenticated_access",
        },
        "llm_result_fields": ["rate_limited"],
        "notes": None,
    },
}


def compute_owasp_llm_coverage(
    llm_security_results: dict[str, Any],
    all_findings: list[dict],
) -> dict:
    """
    Compute OWASP LLM Top 10 2025 coverage from LLM security scan results.

    Args:
        llm_security_results: Raw results from llm_security_check.run()
        all_findings: All classified findings (to cross-reference LLM keys)

    Returns:
        {
            "categories": {
                "LLM01": {
                    "id": "LLM01:2025",
                    "name": "Prompt Injection",
                    "status": "TESTED" | "PARTIAL" | "NOT_TESTED",
                    "findings_count": 0,
                    "highest_severity": "INFO",
                    "findings": [...],
                    "notes": None,
                },
                ...
            },
            "llm_coverage_score": 70,
            "llm_endpoints_scanned": 3,
            "total_llm_findings": 5,
        }
    """
    if not llm_security_results:
        llm_security_results = {}

    # Build finding key set from all_findings (LLM-related)
    llm_finding_keys = set()
    llm_findings_by_key: dict[str, list] = {}
    for f in all_findings:
        key = f.get("key") or f.get("check_type") or ""
        if key.startswith("llm_") or any(
            key in cat_def["finding_keys"] for cat_def in OWASP_LLM_2025.values()
        ):
            llm_finding_keys.add(key)
            llm_findings_by_key.setdefault(key, []).append(f)

    # Also extract finding keys from llm_security_results.findings
    llm_findings_raw = llm_security_results.get("findings", []) or []
    for f in llm_findings_raw:
        key = f.get("key") or f.get("check_id") or ""
        if key:
            llm_finding_keys.add(key)
            llm_findings_by_key.setdefault(key, []).append(f)

    llm_detected = bool(
        llm_security_results.get("llm_endpoints_found")
        or llm_security_results.get("total_llm_endpoints", 0) > 0
    )

    categories: dict[str, dict] = {}
    total_findings = 0

    for cat_id, cat_def in OWASP_LLM_2025.items():
        # Match findings
        cat_matching_keys = cat_def["finding_keys"] & llm_finding_keys
        cat_findings_list = []
        for key in cat_matching_keys:
            cat_findings_list.extend(llm_findings_by_key.get(key, []))

        # Check result fields
        has_result_data = any(
            llm_security_results.get(field) is not None
            for field in cat_def.get("llm_result_fields", [])
        )

        # Determine status
        if not llm_detected and not cat_def["finding_keys"] and not has_result_data:
            status = "NOT_TESTED"
        elif not llm_detected:
            status = "NOT_TESTED"
        elif cat_def["notes"] and "Cannot be assessed" in cat_def["notes"]:
            status = "NOT_TESTED"
        elif cat_def["notes"] and "Passive" in cat_def["notes"]:
            status = "PARTIAL"
        elif has_result_data or cat_matching_keys:
            status = "TESTED"
        else:
            status = "PARTIAL" if llm_detected else "NOT_TESTED"

        worst_sev = "INFO"
        for sev in SEVERITY_ORDER:
            if any(f.get("severity") == sev for f in cat_findings_list):
                worst_sev = sev
                break

        total_findings += len(cat_findings_list)
        categories[cat_id] = {
            "id": cat_def["id"],
            "name": cat_def["name"],
            "description": cat_def["description"],
            "status": status,
            "findings_count": len(cat_findings_list),
            "highest_severity": worst_sev if cat_findings_list else "INFO",
            "findings": [
                f.get("key") or f.get("check_id") or "" for f in cat_findings_list
            ][:10],
            "notes": cat_def.get("notes"),
        }

    tested = sum(1 for c in categories.values() if c["status"] == "TESTED")
    partial = sum(1 for c in categories.values() if c["status"] == "PARTIAL")
    coverage_score = int(round((tested + partial * 0.5) / 10 * 100))

    return {
        "categories": categories,
        "llm_coverage_score": coverage_score,
        "llm_endpoints_scanned": llm_security_results.get("total_llm_endpoints", 0),
        "total_llm_findings": total_findings,
        "llm_detected": llm_detected,
    }
