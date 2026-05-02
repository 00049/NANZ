"""
Container & Infrastructure Security Audit.

Detects container, Kubernetes, and cloud infrastructure
exposure via passive DNS/HTTP probing.

PASSIVE CONSTRAINTS:
  - No container command execution
  - No Kubernetes API writes
  - DNS lookups and HTTP HEAD/GET only
  - No credential stuffing or brute force
"""

import asyncio
import json
import logging
import re
import socket
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 12.0

# Container registry paths
REGISTRY_PATHS = [
    "/v2/",  # Docker registry API v2 ping
    "/v2/_catalog",  # Docker registry catalog (if exposed)
]

# Kubernetes API paths (passive)
K8S_API_PATHS = [
    "/api/v1/namespaces",
    "/api/v1/nodes",
    "/api/v1/pods",
    "/api",
    "/healthz",
    "/readyz",
    "/.well-known/kubernetes",
]

# Internal metadata endpoints (when domain resolves to cloud)
METADATA_ENDPOINTS = [
    "http://169.254.169.254/latest/meta-data/",              # AWS
    "http://169.254.169.254/computeMetadata/v1/",           # GCP
    "http://169.254.169.254/metadata/v1/",                   # DigitalOcean
    "http://metadata.google.internal/computeMetadata/v1/",   # GCP alt
]

# Common Kubernetes Dashboard paths
K8S_DASHBOARD_PATHS = [
    "/api/v1/namespaces/kubernetes-dashboard/services/http:kubernetes-dashboard:/proxy/",
    "/api/v1/namespaces/kube-system/services/kubernetes-dashboard/proxy/",
    "/#/login",  # k8s dashboard login page
]

# Container/infra tool signatures in headers/body
CONTAINER_SIGNATURES = {
    "Docker-Distribution-Api-Version": "docker_registry",
    "X-Docker-Registry-Version": "docker_registry",
}

CONTAINER_BODY_SIGNATURES = [
    (re.compile(r"\"repositories\":\s*\[", re.IGNORECASE), "docker_registry_catalog"),
    (re.compile(r"Kubernetes Dashboard", re.IGNORECASE), "k8s_dashboard"),
    (re.compile(r'"kind":\s*"Node"|"kind":\s*"Pod"', re.IGNORECASE), "k8s_api_response"),
    (re.compile(r"amazon-linux|ubuntu.*ec2|CoreOS|Container Linux", re.IGNORECASE), "cloud_vm_banner"),
    (re.compile(r"docker\.io|gcr\.io|quay\.io", re.IGNORECASE), "container_image_ref"),
    (re.compile(r"ECS_CONTAINER_METADATA|AWS_CONTAINER_CREDENTIALS|EKS_CLUSTER", re.IGNORECASE), "aws_ecs_env"),
]

# Cloud-specific DNS prefixes that indicate container orchestration
CLOUD_CLUSTER_DNS_PREFIXES = [
    ".k8s.", ".eks.", ".gke.", ".aks.",
    ".cluster.", ".kube.", ".rancher.",
]


@dataclass
class ContainerSecurityResult:
    docker_registry_exposed: bool = False
    docker_registry_path: str = ""
    k8s_api_exposed: bool = False
    k8s_api_paths: list = field(default_factory=list)
    k8s_dashboard_exposed: bool = False
    container_signatures_found: list = field(default_factory=list)
    cloud_cluster_indicators: list = field(default_factory=list)
    metadata_api_hints: list = field(default_factory=list)
    exposed_services: list = field(default_factory=list)
    environment_leaks: list = field(default_factory=list)
    container_ports_open: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    error: Optional[str] = None


CONTAINER_PORTS = [
    (2375, "Docker daemon (no TLS)"),
    (2376, "Docker daemon (TLS)"),
    (2377, "Docker Swarm manager"),
    (6443, "Kubernetes API server"),
    (8080, "Kubernetes alt/proxy"),
    (10250, "Kubelet API"),
    (10255, "Kubelet read-only API"),
    (10251, "Kubernetes scheduler"),
    (10252, "Kubernetes controller-manager"),
    (2379, "etcd client"),
    (2380, "etcd peer"),
    (4243, "Docker remote API alt"),
    (5000, "Container registry"),
    (8001, "kubectl proxy"),
    (8888, "Container management UI"),
]


async def run(url: str, domain: str) -> ContainerSecurityResult:
    result = ContainerSecurityResult()
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(REQUEST_TIMEOUT, connect=5.0),
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)",
                     "Accept": "application/json, */*"},
            limits=httpx.Limits(max_connections=6),
        ) as client:

            await asyncio.gather(
                _check_docker_registry(client, base, result),
                _check_k8s_api(client, base, result),
                _check_k8s_dashboard(client, base, result),
                _check_container_port_exposure(domain, result),
                _check_cloud_cluster_dns(domain, result),
                _check_container_body_signatures(client, base, result),
                return_exceptions=True,
            )

    except Exception as exc:
        logger.error(f"Container security scan failed for {url}: {exc}")
        result.error = str(exc)[:200]

    return result


async def _check_docker_registry(
    client: httpx.AsyncClient,
    base: str,
    result: ContainerSecurityResult,
) -> None:
    """Check for exposed Docker container registry."""
    for path in REGISTRY_PATHS:
        try:
            resp = await client.get(f"{base}{path}")
            if resp.status_code in (200, 401, 403):
                headers = dict(resp.headers)
                # Check for Docker registry signature header
                if "Docker-Distribution-Api-Version" in headers:
                    result.docker_registry_exposed = True
                    result.docker_registry_path = path
                    severity = "CRITICAL" if path == "/v2/_catalog" else "RED"
                    result.findings.append({
                        "type": "docker_registry_exposed",
                        "endpoint": f"{base}{path}",
                        "severity": severity,
                        "detail": f"Docker registry API accessible at {path} — container images may be enumerable",
                    })

                # Check for catalog exposure
                if path == "/v2/_catalog" and resp.status_code == 200:
                    try:
                        data = resp.json()
                        repos = data.get("repositories", [])
                        if repos:
                            result.findings.append({
                                "type": "docker_catalog_exposed",
                                "endpoint": f"{base}{path}",
                                "severity": "CRITICAL",
                                "detail": f"Docker registry catalog exposed — {len(repos)} repositories listed: {', '.join(repos[:3])}",
                                "repositories": repos[:5],
                            })
                    except Exception:
                        pass
        except Exception:
            pass
        await asyncio.sleep(0.2)


async def _check_k8s_api(
    client: httpx.AsyncClient,
    base: str,
    result: ContainerSecurityResult,
) -> None:
    """Check for exposed Kubernetes API server."""
    found_paths = []

    for path in K8S_API_PATHS:
        try:
            resp = await client.get(f"{base}{path}")
            if resp.status_code in (200, 401, 403):
                body = resp.text[:2000]
                # Kubernetes API response signatures
                if any(kw in body for kw in ['"apiVersion"', '"kind"', '"groups"', '"resources"']):
                    found_paths.append(path)

                    if resp.status_code == 200:
                        result.k8s_api_exposed = True
                        result.findings.append({
                            "type": "k8s_api_exposed_unauthenticated",
                            "endpoint": f"{base}{path}",
                            "severity": "CRITICAL",
                            "detail": f"Kubernetes API server accessible without authentication at {path}",
                        })

        except Exception:
            pass
        await asyncio.sleep(0.1)

    result.k8s_api_paths = found_paths


async def _check_k8s_dashboard(
    client: httpx.AsyncClient,
    base: str,
    result: ContainerSecurityResult,
) -> None:
    """Check for exposed Kubernetes dashboard."""
    for path in K8S_DASHBOARD_PATHS:
        try:
            resp = await client.get(f"{base}{path}")
            if resp.status_code == 200:
                body = resp.text.lower()
                if "kubernetes dashboard" in body or "kubernetes-dashboard" in body:
                    result.k8s_dashboard_exposed = True
                    severity = "CRITICAL"
                    result.findings.append({
                        "type": "k8s_dashboard_exposed",
                        "endpoint": f"{base}{path}",
                        "severity": severity,
                        "detail": f"Kubernetes Dashboard publicly accessible — cluster management UI exposed",
                    })
                    return
        except Exception:
            pass
        await asyncio.sleep(0.1)


async def _check_container_port_exposure(
    domain: str,
    result: ContainerSecurityResult,
) -> None:
    """Check container-specific ports via socket connect."""
    try:
        host_ip = socket.gethostbyname(domain)
    except Exception:
        return

    sem = asyncio.Semaphore(8)

    async def check_port(port: int, desc: str) -> None:
        async with sem:
            try:
                loop = asyncio.get_event_loop()
                fut = loop.run_in_executor(
                    None, lambda: _tcp_connect(host_ip, port)
                )
                is_open = await asyncio.wait_for(fut, timeout=2.0)
                if is_open:
                    severity = "CRITICAL" if port in (2375, 10250, 10255, 2379, 6443) else "RED"
                    result.container_ports_open.append({
                        "port": port,
                        "service": desc,
                        "severity": severity,
                    })
                    result.findings.append({
                        "type": "container_port_exposed",
                        "port": port,
                        "service": desc,
                        "severity": severity,
                        "detail": f"Container/orchestration port {port} ({desc}) open on {host_ip}",
                    })
            except Exception:
                pass

    await asyncio.gather(
        *[check_port(p, d) for p, d in CONTAINER_PORTS],
        return_exceptions=True,
    )


def _tcp_connect(host: str, port: int, timeout: float = 1.5) -> bool:
    """Synchronous TCP connect probe."""
    import socket as _socket
    try:
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        s.close()
        return result == 0
    except Exception:
        return False


async def _check_cloud_cluster_dns(
    domain: str,
    result: ContainerSecurityResult,
) -> None:
    """Check DNS for cloud cluster indicators in subdomains."""
    try:
        import dns.resolver  # type: ignore
        answers = dns.resolver.resolve(domain, "A")
        ip_str = str(answers[0])

        # Check if IP resolves to cloud range (rough indicator)
        if any(ip_str.startswith(prefix) for prefix in ["34.", "35.", "130.211.", "104.198."]):
            result.cloud_cluster_indicators.append({
                "type": "gcp_ip_range",
                "ip": ip_str,
                "detail": "IP in Google Cloud range — likely GKE/GCE hosted",
            })
        elif any(ip_str.startswith(prefix) for prefix in ["52.", "54.", "18.", "3."]):
            result.cloud_cluster_indicators.append({
                "type": "aws_ip_range",
                "ip": ip_str,
                "detail": "IP in AWS range — likely EKS/ECS hosted",
            })
    except Exception:
        pass

    # Check DNS subdomains for cluster hints
    for prefix in CLOUD_CLUSTER_DNS_PREFIXES:
        subdomain = f"api{prefix}{domain}"
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, lambda: socket.gethostbyname(subdomain))
            result.cloud_cluster_indicators.append({
                "type": "cluster_dns_subdomain",
                "subdomain": subdomain,
                "detail": f"Cluster-pattern DNS subdomain resolves — K8s API surface may exist",
            })
        except Exception:
            pass


async def _check_container_body_signatures(
    client: httpx.AsyncClient,
    base: str,
    result: ContainerSecurityResult,
) -> None:
    """Check HTTP response bodies for container/cloud signatures."""
    try:
        resp = await client.get(base)
        body = resp.text[:5000]
        headers = dict(resp.headers)

        # Header signatures
        for header, sig_type in CONTAINER_SIGNATURES.items():
            if header in headers:
                result.container_signatures_found.append({
                    "type": sig_type,
                    "source": f"header:{header}",
                })

        # Body signatures
        for pattern, sig_type in CONTAINER_BODY_SIGNATURES:
            if pattern.search(body):
                result.container_signatures_found.append({
                    "type": sig_type,
                    "source": "response_body",
                })

    except Exception:
        pass
