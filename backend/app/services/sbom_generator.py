"""
SBOM Generator — Software Bill of Materials (CycloneDX 1.4 + SPDX 2.3).

Builds an SBOM from ShieldCheck scan data, including:
  - Technology inventory (from tech_check + javascript_check)
  - Dependency analysis (from dependency_check / sca_check)
  - CVE findings (from cve_intelligence)

Outputs:
  - CycloneDX 1.4 JSON (default)
  - SPDX 2.3 Tag-Value or JSON (on request)

Usage:
    from app.services.sbom_generator import generate_sbom, SBOMFormat
    sbom = generate_sbom(scan_results, domain, format=SBOMFormat.CYCLONEDX)
"""

import hashlib
import logging
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

logger = logging.getLogger(__name__)


class SBOMFormat(StrEnum):
    CYCLONEDX = "cyclonedx"
    SPDX = "spdx"


# ── Data Extraction Helpers ───────────────────────────────────────────────────


def _extract_components(scan_results: dict[str, Any]) -> list[dict]:
    """
    Extract software components from multiple scan module results.

    Returns list of component dicts:
        {
            "name": str,
            "version": str | None,
            "type": "library" | "framework" | "runtime" | "operating-system" | "container" | "firmware" | "device" | "application",
            "purl": str | None,
            "cpe": str | None,
            "cves": list[str],
            "source": str,  # which module detected it
        }
    """
    components: list[dict] = []
    seen: set[str] = set()

    # ── From tech_check ────────────────────────────────────────────────────
    tech_module = scan_results.get("tech", {})
    tech_data = tech_module.get("data") if "data" in tech_module else tech_module
    tech_data = tech_data or {}
    for tech in tech_data.get("technologies", []):
        name = tech.get("name") or tech.get("tech_name") or ""
        if not name:
            continue
        version = tech.get("version") or tech.get("detected_version") or None
        dedup_key = f"{name}:{version}"
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        components.append(
            {
                "name": name,
                "version": version,
                "type": _infer_type(name),
                "purl": _build_purl(name, version, tech.get("category", "")),
                "cpe": tech.get("cpe") or None,
                "cves": [],
                "source": "tech_check",
            }
        )

    # ── From javascript_check — libraries ─────────────────────────────────
    js_module = scan_results.get("javascript", {})
    js_data = js_module.get("data") if "data" in js_module else js_module
    js_data = js_data or {}
    for lib in js_data.get("libraries_detected", []):
        name = lib.get("name") or lib.get("library") or ""
        if not name:
            continue
        version = lib.get("version") or None
        dedup_key = f"{name}:{version}"
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        components.append(
            {
                "name": name,
                "version": version,
                "type": "library",
                "purl": _build_purl(name, version, "npm"),
                "cpe": None,
                "cves": lib.get("cves", []),
                "source": "javascript_check",
            }
        )

    # ── From dependency_check / sca_check ─────────────────────────────────
    dep_module = scan_results.get("dependency", {})
    dep_data = dep_module.get("data") if "data" in dep_module else dep_module
    dep_data = dep_data or {}
    for pkg in dep_data.get("packages", []) or dep_data.get("dependencies", []):
        name = pkg.get("name") or pkg.get("package") or ""
        if not name:
            continue
        version = pkg.get("version") or pkg.get("installed_version") or None
        ecosystem = pkg.get("ecosystem") or pkg.get("package_manager") or ""
        dedup_key = f"{name}:{version}:{ecosystem}"
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        cves_raw = pkg.get("vulnerabilities") or pkg.get("cves") or []
        cve_ids = [
            v.get("cve_id") or v.get("id") or v if isinstance(v, str) else ""
            for v in cves_raw
        ]
        components.append(
            {
                "name": name,
                "version": version,
                "type": "library",
                "purl": _build_purl(name, version, ecosystem),
                "cpe": pkg.get("cpe") or None,
                "cves": [c for c in cve_ids if c],
                "source": "dependency_check",
            }
        )

    # ── From cve_intelligence ─────────────────────────────────────────────
    cve_module = scan_results.get("cve", {})
    cve_data = cve_module.get("data") if "data" in cve_module else cve_module
    cve_data = cve_data or {}
    for finding in cve_data.get("findings", []) or cve_data.get("cve_findings", []):
        name = (
            finding.get("product")
            or finding.get("component")
            or finding.get("tech")
            or ""
        )
        if not name:
            continue
        version = finding.get("version") or None
        dedup_key = f"{name}:{version}:cve"
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        cve_id = finding.get("cve_id") or finding.get("id") or ""
        components.append(
            {
                "name": name,
                "version": version,
                "type": _infer_type(name),
                "purl": _build_purl(name, version, ""),
                "cpe": finding.get("cpe") or None,
                "cves": [cve_id] if cve_id else [],
                "source": "cve_intelligence",
            }
        )

    return components


def _infer_type(name: str) -> str:
    """Infer CycloneDX component type from component name."""
    name_lower = name.lower()
    frameworks = {
        "wordpress",
        "django",
        "rails",
        "laravel",
        "spring",
        "express",
        "next.js",
        "nextjs",
        "react",
        "angular",
        "vue",
        "nuxt",
    }
    runtimes = {"node", "node.js", "python", "php", "java", "ruby", "golang"}
    web_servers = {"nginx", "apache", "iis", "caddy", "traefik", "lighttpd"}

    if any(fw in name_lower for fw in frameworks):
        return "framework"
    if any(rt in name_lower for rt in runtimes):
        return "runtime"
    if any(ws in name_lower for ws in web_servers):
        return "application"
    return "library"


def _build_purl(name: str, version: str | None, ecosystem: str) -> str | None:
    """Build a Package URL (purl) for a software component."""
    if not name:
        return None

    name_clean = name.lower().replace(" ", "-")
    eco_lower = (ecosystem or "").lower()

    # Infer ecosystem from name patterns
    if not eco_lower:
        if any(
            c in name.lower() for c in ["jquery", "react", "vue", "angular", "express"]
        ):
            eco_lower = "npm"
        elif any(c in name.lower() for c in ["django", "flask", "requests", "boto"]):
            eco_lower = "pypi"
        elif any(c in name.lower() for c in ["spring", "junit", "jackson"]):
            eco_lower = "maven"
        elif any(c in name.lower() for c in ["wordpress", "php", "laravel"]):
            eco_lower = "packagist"
        else:
            eco_lower = "generic"

    if eco_lower in ("npm", "node"):
        eco_lower = "npm"
    elif eco_lower in ("pip", "pypi", "python"):
        eco_lower = "pypi"
    elif eco_lower == "maven":
        return (
            f"pkg:maven/{name_clean}/{version}"
            if version
            else f"pkg:maven/{name_clean}"
        )
    elif eco_lower == "packagist":
        return f"pkg:packagist/{name_clean}" + (f"@{version}" if version else "")

    purl = f"pkg:{eco_lower}/{name_clean}"
    if version:
        purl += f"@{version}"
    return purl


# ── CycloneDX 1.4 Generator ───────────────────────────────────────────────────


def _component_to_cyclonedx(comp: dict, bom_ref_prefix: str) -> dict:
    """Convert a component dict to a CycloneDX 1.4 component object."""
    name = comp["name"]
    version_str = comp.get("version") or ""
    bom_ref = (
        f"{bom_ref_prefix}-{hashlib.md5((name + version_str).encode()).hexdigest()[:8]}"
    )

    cdx_comp: dict = {
        "type": comp.get("type", "library"),
        "bom-ref": bom_ref,
        "name": name,
    }

    if comp.get("version"):
        cdx_comp["version"] = comp["version"]

    if comp.get("purl"):
        cdx_comp["purl"] = comp["purl"]

    if comp.get("cpe"):
        cdx_comp["cpe"] = comp["cpe"]

    # External references for CVEs
    if comp.get("cves"):
        cdx_comp["externalReferences"] = []
        for cve_id in comp["cves"]:
            cdx_comp["externalReferences"].append(
                {
                    "type": "advisories",
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "comment": f"Known vulnerability: {cve_id}",
                }
            )

    return cdx_comp


def generate_cyclonedx_sbom(
    scan_results: dict[str, Any],
    domain: str,
    scan_id: str | None = None,
) -> dict:
    """
    Generate a CycloneDX 1.4 SBOM JSON object.

    Args:
        scan_results: Raw per-module results dict
        domain: Target domain name
        scan_id: Optional scan UUID for traceability

    Returns:
        Complete CycloneDX 1.4 BOM as a Python dict (JSON-serializable)
    """
    serial = str(uuid.uuid4())
    timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    bom_prefix = domain.replace(".", "-").replace("_", "-")[:16]

    components = _extract_components(scan_results)

    cdx_components = [_component_to_cyclonedx(c, bom_prefix) for c in components]

    # Collect all CVE vulnerabilities
    vulnerabilities = []
    for comp in components:
        for cve_id in comp.get("cves", []):
            vuln = {
                "id": cve_id,
                "source": {
                    "name": "NVD",
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                },
                "affects": [
                    {
                        "ref": f"{bom_prefix}-{hashlib.md5((comp['name'] + (comp.get('version') or '')).encode()).hexdigest()[:8]}",
                        "versions": [
                            {
                                "version": comp.get("version") or "unknown",
                                "status": "affected",
                            }
                        ],
                    }
                ],
            }
            vulnerabilities.append(vuln)

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [
                {
                    "vendor": "ShieldCheck NAANZ",
                    "name": "ShieldCheck ASPM Engine",
                    "version": "2.0",
                }
            ],
            "component": {
                "type": "application",
                "name": domain,
                "description": f"External attack surface SBOM for {domain}",
            },
            "properties": [
                {"name": "shieldcheck:scan_id", "value": scan_id or serial},
                {"name": "shieldcheck:target", "value": domain},
                {"name": "shieldcheck:scan_date", "value": timestamp},
            ],
        },
        "components": cdx_components,
        "vulnerabilities": vulnerabilities,
    }

    return bom


# ── SPDX 2.3 Generator ────────────────────────────────────────────────────────


def generate_spdx_sbom(
    scan_results: dict[str, Any],
    domain: str,
    scan_id: str | None = None,
) -> dict:
    """
    Generate an SPDX 2.3 SBOM JSON object.

    Args:
        scan_results: Raw per-module results dict
        domain: Target domain name
        scan_id: Optional scan UUID

    Returns:
        SPDX 2.3 JSON document as Python dict
    """
    timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    doc_id = scan_id or str(uuid.uuid4())
    domain_clean = domain.replace(".", "-")

    components = _extract_components(scan_results)

    packages = []
    for idx, comp in enumerate(components):
        pkg_id = f"SPDXRef-Package-{idx + 1}"
        package: dict = {
            "SPDXID": pkg_id,
            "name": comp["name"],
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "versionInfo": comp.get("version") or "NOASSERTION",
            "primaryPackagePurpose": comp.get("type", "LIBRARY").upper(),
        }
        if comp.get("purl"):
            package["externalRefs"] = [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": comp["purl"],
                }
            ]
        if comp.get("cpe"):
            refs = package.setdefault("externalRefs", [])
            refs.append(
                {
                    "referenceCategory": "SECURITY",
                    "referenceType": "cpe23Type",
                    "referenceLocator": comp["cpe"],
                }
            )
        if comp.get("cves"):
            refs = package.setdefault("externalRefs", [])
            for cve_id in comp["cves"]:
                refs.append(
                    {
                        "referenceCategory": "SECURITY",
                        "referenceType": "advisory",
                        "referenceLocator": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    }
                )
        packages.append(package)

    spdx_doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"ShieldCheck-SBOM-{domain_clean}",
        "documentNamespace": f"https://shieldcheck.io/sbom/{doc_id}",
        "creationInfo": {
            "created": timestamp,
            "creators": [
                "Tool: ShieldCheck NAANZ ASPM Engine 2.0",
                "Organization: ShieldCheck Security Platform",
            ],
            "licenseListVersion": "3.21",
        },
        "packages": packages,
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": f"SPDXRef-Package-{idx + 1}",
            }
            for idx in range(len(packages))
        ],
    }

    return spdx_doc


# ── Main Entrypoint ────────────────────────────────────────────────────────────


def generate_sbom(
    scan_results: dict[str, Any],
    domain: str,
    format: SBOMFormat = SBOMFormat.CYCLONEDX,
    scan_id: str | None = None,
) -> dict:
    """
    Generate an SBOM in the requested format.

    Args:
        scan_results: Full raw_findings dict from orchestrator
        domain: Target domain
        format: SBOMFormat.CYCLONEDX or SBOMFormat.SPDX
        scan_id: Optional scan UUID for traceability

    Returns:
        SBOM document as Python dict (JSON-serializable)
    """
    if format == SBOMFormat.SPDX:
        return generate_spdx_sbom(scan_results, domain, scan_id)
    return generate_cyclonedx_sbom(scan_results, domain, scan_id)
