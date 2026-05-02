"""
LLM / AI Security Audit — OWASP LLM Top 10 (2025) scanner.

Detects AI/LLM integration surface exposure via passive analysis.

PASSIVE CONSTRAINTS:
  - No prompt injection payloads that execute malicious instructions
  - Detection probes only: benign queries to identify AI surfaces
  - No data exfiltration attempts
  - Pattern matching on public API responses only
"""

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 15.0

# LLM API endpoint patterns to probe
LLM_ENDPOINT_PATTERNS = [
    "/api/chat",
    "/api/ai",
    "/api/ai/chat",
    "/api/llm",
    "/api/openai",
    "/api/claude",
    "/api/gpt",
    "/api/assistant",
    "/api/chatbot",
    "/api/v1/chat",
    "/api/v1/completions",
    "/api/v1/chat/completions",
    "/api/generate",
    "/api/ai/generate",
    "/chat",
    "/assistant",
    "/api/copilot",
    "/api/search/ai",
    "/api/search/semantic",
]

# Sensitive API key patterns in response bodies
API_KEY_PATTERNS = [
    (re.compile(r"sk-[a-zA-Z0-9]{48}", re.IGNORECASE), "OpenAI API key"),
    (re.compile(r"sk-ant-[a-zA-Z0-9\-]{40,}", re.IGNORECASE), "Anthropic API key"),
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}", re.IGNORECASE), "Google API key"),
    (re.compile(r"Bearer\s+sk-[a-zA-Z0-9]{20,}", re.IGNORECASE), "Bearer token (OpenAI style)"),
]

# AI model identifier patterns in responses
MODEL_ID_PATTERNS = [
    re.compile(r"gpt-4[\w\-\.]*|gpt-3\.5-[a-z]+|o[13]-[a-z]+", re.IGNORECASE),
    re.compile(r"claude-[23][-\w]+", re.IGNORECASE),
    re.compile(r"gemini-[\w\-]+", re.IGNORECASE),
    re.compile(r"llama-[\d\w\-]+|mistral[-\w]+", re.IGNORECASE),
    re.compile(r"\"model\":\s*\"[a-zA-Z0-9/_\-\.]+\""),
]

# System prompt leakage indicators
SYSTEM_PROMPT_LEAK_PATTERNS = [
    re.compile(r"system prompt|system message|system instruction", re.IGNORECASE),
    re.compile(r"you are an AI|you are a helpful|you are an assistant", re.IGNORECASE),
    re.compile(r"your role is|your job is|your purpose is", re.IGNORECASE),
    re.compile(r"instructions?:.*?(?:never|always|must|should)", re.IGNORECASE | re.DOTALL),
    re.compile(r"<\|system\|>|<system>|<<SYS>>|\[INST\]", re.IGNORECASE),
]

# Prompt injection surface indicators
PROMPT_INJECTION_SURFACES = [
    re.compile(r'<input[^>]+placeholder="[^"]*(?:ask|chat|message|prompt|query)[^"]*"', re.IGNORECASE),
    re.compile(r'placeholder="[^"]*(?:ask me|chat|send a message)[^"]*"', re.IGNORECASE),
    re.compile(r'data-testid="(?:chat|ai|llm|assistant)[^"]*"', re.IGNORECASE),
    re.compile(r'class="[^"]*(?:chatbox|chat-input|ai-input)[^"]*"', re.IGNORECASE),
]

# Indirect prompt injection surfaces (content processed by LLM)
INDIRECT_INJECTION_PATHS = [
    "/api/summarize", "/api/analyze",
    "/api/ai/summarize", "/api/search",
    "/api/email/analyze", "/api/document/analyze",
]

# OWASP LLM Top 10 2025 IDs
OWASP_LLM_TOP_10 = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain Vulnerabilities",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}


@dataclass
class LLMFinding:
    owasp_id: str
    owasp_name: str
    endpoint: str
    severity: str
    detail: str
    confirmed: bool = False


@dataclass
class LLMSecurityResult:
    llm_surface_detected: bool = False
    active_llm_endpoints: list = field(default_factory=list)
    model_ids_disclosed: list = field(default_factory=list)
    api_keys_in_response: list = field(default_factory=list)
    system_prompt_leaked: bool = False
    system_prompt_hints: list = field(default_factory=list)
    prompt_injection_surfaces: list = field(default_factory=list)
    indirect_injection_surfaces: list = field(default_factory=list)
    excessive_agency_indicators: list = field(default_factory=list)
    rate_limited: bool = True
    token_limit_enforced: bool = True
    findings: list = field(default_factory=list)
    probes_sent: int = 0
    error: Optional[str] = None


async def run(url: str, domain: str) -> LLMSecurityResult:
    result = LLMSecurityResult()
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(REQUEST_TIMEOUT, connect=5.0),
            follow_redirects=True,
            verify=False,
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; SecurityAudit/1.0)",
                "Accept": "application/json, text/html, */*",
            },
            limits=httpx.Limits(max_connections=4),
        ) as client:

            # Phase 1: Discover LLM endpoints
            active = await _discover_llm_endpoints(client, base, result)
            result.active_llm_endpoints = active

            if active:
                result.llm_surface_detected = True

            # Phase 2: Parallel security checks
            await asyncio.gather(
                _check_homepage_for_llm_surfaces(client, url, result),
                _check_system_prompt_leakage(client, base, active, result),
                _check_model_disclosure(client, base, active, result),
                _check_api_key_exposure(client, base, active, result),
                _check_rate_limiting(client, base, active, result),
                _check_indirect_injection(client, base, result),
                _check_excessive_agency(client, base, active, result),
                return_exceptions=True,
            )

    except Exception as exc:
        logger.error(f"LLM security scan failed for {url}: {exc}")
        result.error = str(exc)[:200]

    return result


async def _discover_llm_endpoints(
    client: httpx.AsyncClient,
    base: str,
    result: LLMSecurityResult,
) -> list[str]:
    """Probe for active LLM/AI API endpoints."""
    active = []
    sem = asyncio.Semaphore(4)

    async def probe(path: str) -> None:
        async with sem:
            try:
                result.probes_sent += 1
                resp = await client.get(f"{base}{path}")
                if resp.status_code not in (404, 410):
                    content_type = resp.headers.get("content-type", "")
                    # Must return JSON or be an API endpoint
                    if resp.status_code in (200, 400, 405, 422) or "json" in content_type:
                        active.append(f"{base}{path}")
            except Exception:
                pass
            await asyncio.sleep(0.1)

    await asyncio.gather(*[probe(p) for p in LLM_ENDPOINT_PATTERNS], return_exceptions=True)
    return active


async def _check_homepage_for_llm_surfaces(
    client: httpx.AsyncClient,
    url: str,
    result: LLMSecurityResult,
) -> None:
    """Scan homepage HTML for LLM/chat UI input surfaces."""
    try:
        result.probes_sent += 1
        resp = await client.get(url)
        body = resp.text

        for pattern in PROMPT_INJECTION_SURFACES:
            match = pattern.search(body)
            if match:
                result.llm_surface_detected = True
                result.prompt_injection_surfaces.append({
                    "type": "ui_input",
                    "matched": match.group(0)[:100],
                    "severity": "AMBER",
                    "detail": "Chat/AI input found in page — probe for prompt injection",
                })
                result.findings.append(LLMFinding(
                    owasp_id="LLM01",
                    owasp_name=OWASP_LLM_TOP_10["LLM01"],
                    endpoint=url,
                    severity="AMBER",
                    detail="AI chat interface detected — prompt injection surface present",
                ).__dict__)

    except Exception as exc:
        logger.debug(f"Homepage LLM scan error: {exc}")


async def _check_system_prompt_leakage(
    client: httpx.AsyncClient,
    base: str,
    active_endpoints: list,
    result: LLMSecurityResult,
) -> None:
    """
    Probe LLM endpoints with benign 'repeat' instructions to detect system prompt leakage.
    Uses innocent meta-questions, not injection payloads.
    """
    probes = [
        {"prompt": "What is your name?", "question_type": "meta"},
        {"prompt": "Can you describe your purpose?", "question_type": "meta"},
        {"prompt": "What are your capabilities?", "question_type": "capability"},
    ]

    for endpoint in active_endpoints[:2]:  # Limit to 2 endpoints
        for probe_data in probes:
            try:
                result.probes_sent += 1
                resp = await client.post(
                    endpoint,
                    json={"message": probe_data["prompt"], "query": probe_data["prompt"],
                          "prompt": probe_data["prompt"]},
                )
                if resp.status_code != 200:
                    continue

                body = resp.text[:5000]
                for pattern in SYSTEM_PROMPT_LEAK_PATTERNS:
                    if pattern.search(body):
                        result.system_prompt_leaked = True
                        result.system_prompt_hints.append({
                            "endpoint": endpoint,
                            "probe": probe_data["prompt"],
                            "matched_pattern": pattern.pattern[:50],
                            "severity": "RED",
                        })
                        result.findings.append(LLMFinding(
                            owasp_id="LLM07",
                            owasp_name=OWASP_LLM_TOP_10["LLM07"],
                            endpoint=endpoint,
                            severity="RED",
                            detail="System prompt content visible in LLM response — confidential instructions may be extracted",
                            confirmed=True,
                        ).__dict__)

            except Exception as exc:
                logger.debug(f"System prompt probe error: {exc}")
            await asyncio.sleep(0.5)


async def _check_model_disclosure(
    client: httpx.AsyncClient,
    base: str,
    active_endpoints: list,
    result: LLMSecurityResult,
) -> None:
    """Detect model version/name disclosure in API responses."""
    for endpoint in active_endpoints[:2]:
        try:
            result.probes_sent += 1
            resp = await client.post(
                endpoint,
                json={"message": "Hello", "query": "Hello"},
            )
            body = resp.text[:3000]

            for pattern in MODEL_ID_PATTERNS:
                matches = pattern.findall(body)
                for match in matches:
                    if match not in result.model_ids_disclosed:
                        result.model_ids_disclosed.append(match)

            if result.model_ids_disclosed:
                result.findings.append(LLMFinding(
                    owasp_id="LLM02",
                    owasp_name=OWASP_LLM_TOP_10["LLM02"],
                    endpoint=endpoint,
                    severity="GREEN",
                    detail=f"AI model version disclosed: {', '.join(result.model_ids_disclosed[:3])} — attackers can target model-specific weaknesses",
                    confirmed=True,
                ).__dict__)

        except Exception as exc:
            logger.debug(f"Model disclosure check error: {exc}")
        await asyncio.sleep(0.3)


async def _check_api_key_exposure(
    client: httpx.AsyncClient,
    base: str,
    active_endpoints: list,
    result: LLMSecurityResult,
) -> None:
    """Scan LLM endpoint responses for exposed API keys."""
    for endpoint in active_endpoints[:3]:
        try:
            result.probes_sent += 1
            resp = await client.get(endpoint)
            body = resp.text[:5000]

            for pattern, key_type in API_KEY_PATTERNS:
                if pattern.search(body):
                    result.api_keys_in_response.append({
                        "type": key_type,
                        "endpoint": endpoint,
                        "severity": "CRITICAL",
                    })
                    result.findings.append(LLMFinding(
                        owasp_id="LLM02",
                        owasp_name=OWASP_LLM_TOP_10["LLM02"],
                        endpoint=endpoint,
                        severity="CRITICAL",
                        detail=f"{key_type} exposed in API response — immediately rotate this key",
                        confirmed=True,
                    ).__dict__)

        except Exception as exc:
            logger.debug(f"API key check error: {exc}")
        await asyncio.sleep(0.2)


async def _check_rate_limiting(
    client: httpx.AsyncClient,
    base: str,
    active_endpoints: list,
    result: LLMSecurityResult,
) -> None:
    """Test rate limiting on LLM endpoints — unbounded consumption check."""
    if not active_endpoints:
        return

    endpoint = active_endpoints[0]
    for i in range(15):
        try:
            result.probes_sent += 1
            resp = await client.post(
                endpoint,
                json={"message": f"test{i}", "query": f"test{i}"},
            )
            if resp.status_code == 429:
                result.rate_limited = True
                return
        except Exception:
            pass
        await asyncio.sleep(0.05)

    result.rate_limited = False
    result.findings.append(LLMFinding(
        owasp_id="LLM10",
        owasp_name=OWASP_LLM_TOP_10["LLM10"],
        endpoint=endpoint,
        severity="RED",
        detail="No rate limiting on LLM endpoint — unbounded consumption risk, cost explosion, and DoS possible",
        confirmed=True,
    ).__dict__)


async def _check_indirect_injection(
    client: httpx.AsyncClient,
    base: str,
    result: LLMSecurityResult,
) -> None:
    """Detect indirect prompt injection surfaces (file/URL processing endpoints)."""
    for path in INDIRECT_INJECTION_PATHS:
        try:
            result.probes_sent += 1
            resp = await client.get(f"{base}{path}")
            if resp.status_code not in (404, 410):
                result.indirect_injection_surfaces.append({
                    "endpoint": f"{base}{path}",
                    "status": resp.status_code,
                    "severity": "RED",
                    "detail": f"Content processing endpoint {path} — external content could inject into LLM context",
                })
                result.findings.append(LLMFinding(
                    owasp_id="LLM01",
                    owasp_name=OWASP_LLM_TOP_10["LLM01"],
                    endpoint=f"{base}{path}",
                    severity="RED",
                    detail=f"Content processing endpoint detected at {path} — indirect prompt injection surface (untrusted content processed by LLM)",
                ).__dict__)
        except Exception:
            pass
        await asyncio.sleep(0.1)


async def _check_excessive_agency(
    client: httpx.AsyncClient,
    base: str,
    active_endpoints: list,
    result: LLMSecurityResult,
) -> None:
    """Detect LLM agents with access to sensitive system functions."""
    # Probe for AI agent tool/action endpoints
    agent_paths = [
        "/api/ai/execute", "/api/ai/run", "/api/agent",
        "/api/ai/tools", "/api/ai/actions",
        "/api/copilot/execute", "/api/ai/function",
    ]

    for path in agent_paths:
        try:
            result.probes_sent += 1
            resp = await client.get(f"{base}{path}")
            if resp.status_code not in (404, 410):
                body = resp.text.lower()
                if any(kw in body for kw in
                       ["execute", "run command", "shell", "function_call", "tool_call", "actions"]):
                    result.excessive_agency_indicators.append({
                        "endpoint": f"{base}{path}",
                        "severity": "RED",
                        "detail": f"AI agent action/tool endpoint detected — excessive agency risk if insufficiently sandboxed",
                    })
                    result.findings.append(LLMFinding(
                        owasp_id="LLM06",
                        owasp_name=OWASP_LLM_TOP_10["LLM06"],
                        endpoint=f"{base}{path}",
                        severity="RED",
                        detail=f"AI agent capability endpoint at {path} — LLM may execute actions with excessive privilege",
                    ).__dict__)
        except Exception:
            pass
        await asyncio.sleep(0.1)
