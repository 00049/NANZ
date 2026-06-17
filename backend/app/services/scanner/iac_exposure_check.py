"""
IaC & Container File Exposure Audit.

Detects explicitly leaked Infrastructure as Code and deployment files.
Checks for:
  - Terraform state files (terraform.tfstate, .terraform/terraform.tfstate)
  - Docker files (Dockerfile, docker-compose.yml)
  - Kubernetes manifests (k8s.yaml, deployment.yml, secrets.yaml)
"""

import asyncio
import logging
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 10.0

IAC_PATHS = [
    # Terraform
    "/terraform.tfstate",
    "/terraform.tfstate.backup",
    "/.terraform/terraform.tfstate",
    # Docker
    "/Dockerfile",
    "/docker-compose.yml",
    "/docker-compose.yaml",
    "/.dockerignore",
    # Kubernetes
    "/k8s.yaml",
    "/k8s.yml",
    "/deployment.yaml",
    "/deployment.yml",
    "/secrets.yaml",
    "/secret.yaml",
    "/configmap.yaml",
]

@dataclass
class IacExposureResult:
    files_exposed: list = field(default_factory=list)
    terraform_state_exposed: bool = False
    dockerfile_exposed: bool = False
    k8s_manifest_exposed: bool = False
    findings: list = field(default_factory=list)
    error: str | None = None

async def run(url: str, domain: str) -> IacExposureResult:
    result = IacExposureResult()
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(REQUEST_TIMEOUT, connect=5.0),
            follow_redirects=False,
            verify=False,
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)",
            },
            limits=httpx.Limits(max_connections=6),
        ) as client:

            sem = asyncio.Semaphore(6)

            async def check_path(path: str) -> None:
                async with sem:
                    try:
                        resp = await client.get(f"{base}{path}")
                        if resp.status_code == 200:
                            body = resp.text.lower()
                            
                            # Basic validation to avoid false positives (e.g. wildcard 200s returning HTML)
                            if "<html" in body and "terraform_version" not in body and "from " not in body and "apiVersion:" not in body:
                                return

                            result.files_exposed.append(path)
                            
                            if "tfstate" in path:
                                result.terraform_state_exposed = True
                                result.findings.append({
                                    "type": "iac_tfstate_exposed",
                                    "endpoint": path,
                                    "severity": "CRITICAL",
                                    "detail": f"Terraform state file exposed at {path}. Contains sensitive infrastructure secrets and topology.",
                                })
                            elif "docker" in path.lower():
                                result.dockerfile_exposed = True
                                result.findings.append({
                                    "type": "iac_dockerfile_exposed",
                                    "endpoint": path,
                                    "severity": "RED",
                                    "detail": f"Docker configuration file exposed at {path}. May reveal internal structure or secrets.",
                                })
                            elif any(k in path for k in ["k8s", "deployment", "secret", "configmap"]):
                                result.k8s_manifest_exposed = True
                                severity = "CRITICAL" if "secret" in path else "RED"
                                result.findings.append({
                                    "type": "iac_k8s_manifest_exposed",
                                    "endpoint": path,
                                    "severity": severity,
                                    "detail": f"Kubernetes manifest file exposed at {path}. Reveals cluster configuration.",
                                })
                    except Exception:
                        pass
                    await asyncio.sleep(0.1)

            await asyncio.gather(*[check_path(p) for p in IAC_PATHS], return_exceptions=True)

    except Exception as exc:
        logger.error(f"IaC Exposure scan failed for {url}: {exc}")
        result.error = str(exc)[:200]

    return result
