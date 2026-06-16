"""
FixGeneratorService — calls OpenAI (GPT-4o-mini) to produce structured remediation
guides for security findings. Falls back to a rule-based generator when the
API key is missing or calls fail. Results are cached in Redis for 24 hours.
"""

import json
import logging
import re
from collections.abc import AsyncGenerator

from redis.asyncio import Redis

from app.config import settings
from app.schemas.fix import FixRequest, FixResponse
from app.services.rule_based_fix import generate_rule_based_fix

logger = logging.getLogger(__name__)

CACHE_TTL_SECONDS = 60 * 60 * 24  # 24 hours

SYSTEM_PROMPT = """You are a senior security engineer generating remediation guides for ShieldCheck, a professional security scanning platform. A developer is looking at their security report and clicked "Fix Now" on a finding.

Your response MUST be a single valid JSON object — no markdown, no preamble, no explanation outside the JSON. The object must match this exact schema:
{
  "summary": "2 sentences max. Plain English. What the vulnerability is and why it exists.",
  "impact": "1-2 sentences. What an attacker can concretely do if this is not fixed. Be specific.",
  "steps": [
    {
      "order": 1,
      "title": "Short imperative title",
      "description": "Clear instruction",
      "code_snippet": "exact config change or command, or null",
      "code_language": "nginx|apache|bash|yaml|python|json|null"
    }
  ],
  "verification": "Plain English description of how to verify the fix worked",
  "verification_command": "exact copy-pasteable command, or null if not applicable",
  "estimated_minutes": 15,
  "difficulty": "easy|medium|hard",
  "references": ["real URL only — CVE, RFC, OWASP, or vendor docs. Never invent URLs."]
}

Rules:
- Code snippets must be real, working configuration for the technology involved. Never use placeholders like YOUR_DOMAIN or example.com unless they are genuinely needed for the developer to substitute.
- Steps must be ordered from "do this first" to "do this last". Include a verification step as the final step.
- References must be real URLs you are certain exist (CVE IDs, OWASP top 10, RFC numbers, Mozilla SSL config). If unsure, omit the reference rather than guess.
- Difficulty: easy = config change only, no code; medium = code change or multiple config files; hard = architectural change or dependency upgrade.
- Do not mention ShieldCheck, do not mention yourself, do not add commentary. Only the JSON object."""

USER_PROMPT_TEMPLATE = """Finding: {finding_title}
Description: {finding_description}
Technical detail: {finding_detail}
Severity: {severity}
Category: {category}
Scanned target: {target_domain}

Generate the remediation guide for this finding."""


def _has_openai_key() -> bool:
    """Check if a real OpenAI API key is configured."""
    key = settings.OPENAI_API_KEY
    return bool(
        key and key not in ("", "your_openai_api_key_here", "sk-xxx", "changeme")
    )


def _make_cache_key(finding_title: str, category: str) -> str:
    """Build a deterministic Redis cache key from the finding title and category."""
    slug = re.sub(r"[^a-z0-9]+", "_", finding_title.lower()).strip("_")
    return f"fix:{slug}:{category}"


def _extract_json(text: str) -> str:
    """Extract JSON from raw model output."""
    cleaned = text.strip()

    # Strip markdown fences first
    if cleaned.startswith("```json"):
        cleaned = cleaned[len("```json") :].strip()
    if cleaned.startswith("```"):
        cleaned = cleaned[len("```") :].strip()
    if cleaned.endswith("```"):
        cleaned = cleaned[: -len("```")].strip()

    # Strip everything before the first `{` and after the last `}`
    first_brace = cleaned.find("{")
    last_brace = cleaned.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        cleaned = cleaned[first_brace : last_brace + 1]

    return cleaned


class FixGeneratorService:
    """Generates AI-powered remediation guides with Redis caching and rule-based fallback."""

    def __init__(self) -> None:
        self._redis: Redis = Redis.from_url(
            settings.REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=1.0,
            socket_timeout=1.0,
        )
        self._client = None
        if _has_openai_key():
            try:
                from openai import AsyncOpenAI

                self._client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)
                logger.info("OpenAI client initialized — AI fixes enabled")
            except Exception as exc:
                logger.warning("Failed to initialize OpenAI client: %s", exc)
        else:
            logger.info("No OpenAI API key configured — using rule-based fix generator")

    # ── Public API ───────────────────────────────────────────────────────────

    async def generate_fix(self, req: FixRequest) -> FixResponse:
        """Return a FixResponse — from cache, AI, or rule-based fallback."""
        cache_key = _make_cache_key(req.finding_title, req.category)

        # 1. Cache check
        try:
            cached = await self._redis.get(cache_key)
            if cached:
                logger.debug("Cache HIT for %s", cache_key)
                data = json.loads(cached)
                return FixResponse(finding_id=req.finding_id, cached=True, **data)
            else:
                logger.debug("Cache MISS for %s", cache_key)
        except Exception as exc:
            logger.warning("Redis read failed, proceeding without cache: %s", exc)

        # 2. Try OpenAI if available
        if self._client:
            try:
                raw_json = await self._call_openai(req)
                data = self._parse_response(raw_json)
                if data is None:
                    logger.warning("First JSON parse failed, retrying…")
                    raw_json = await self._call_openai(req)
                    data = self._parse_response(raw_json)

                if data is not None:
                    self._cache_write(cache_key, data)
                    return FixResponse(finding_id=req.finding_id, cached=False, **data)

                logger.warning("OpenAI parse failed twice, falling back to rule-based")
            except Exception as exc:
                logger.warning(
                    "OpenAI call failed, falling back to rule-based: %s", exc
                )

        # 3. Rule-based fallback
        data = generate_rule_based_fix(req)
        self._cache_write(cache_key, data)
        return FixResponse(finding_id=req.finding_id, cached=False, **data)

    async def stream_fix(self, req: FixRequest) -> AsyncGenerator[str, None]:
        """Yield SSE-formatted data. Uses AI streaming if available, else rule-based."""
        cache_key = _make_cache_key(req.finding_title, req.category)

        # ── Check Redis cache first ──
        try:
            cached = await self._redis.get(cache_key)
            if cached:
                logger.debug("Stream cache HIT for %s", cache_key)
                yield f"data: {cached}\n\n"
                yield "data: [DONE]\n\n"
                return
        except Exception as exc:
            logger.warning("Redis read failed during stream: %s", exc)

        # ── Try OpenAI streaming if available ──
        if self._client:
            try:
                user_prompt = USER_PROMPT_TEMPLATE.format(
                    finding_title=req.finding_title,
                    finding_description=req.finding_description,
                    finding_detail=req.finding_detail,
                    severity=req.severity,
                    category=req.category,
                    target_domain=req.target_domain,
                )
                accumulated = ""
                stream = await self._client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": user_prompt},
                    ],
                    response_format={"type": "json_object"},
                    stream=True,
                )
                async for chunk in stream:
                    content = chunk.choices[0].delta.content
                    if content is not None:
                        accumulated += content
                        yield f"data: {content}\n\n"

                yield "data: [DONE]\n\n"

                parsed = self._parse_response(accumulated)
                if parsed is not None:
                    self._cache_write(cache_key, parsed)
                return
            except Exception as exc:
                logger.warning(
                    "OpenAI streaming failed, falling back to rule-based: %s", exc
                )

        # ── Rule-based fallback (emit as single JSON payload) ──
        data = generate_rule_based_fix(req)
        payload = json.dumps(data)
        self._cache_write(cache_key, data)
        yield f"data: {payload}\n\n"
        yield "data: [DONE]\n\n"

    # ── Internals ────────────────────────────────────────────────────────────

    async def _call_openai(self, req: FixRequest) -> str:
        """Send a single non-streaming request to OpenAI and return raw text."""
        user_prompt = USER_PROMPT_TEMPLATE.format(
            finding_title=req.finding_title,
            finding_description=req.finding_description,
            finding_detail=req.finding_detail,
            severity=req.severity,
            category=req.category,
            target_domain=req.target_domain,
        )
        response = await self._client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            response_format={"type": "json_object"},
        )
        return response.choices[0].message.content.strip()

    def _cache_write(self, cache_key: str, data: dict) -> None:
        """Fire-and-forget cache write (runs in background)."""
        import asyncio

        async def _write():
            try:
                await self._redis.set(cache_key, json.dumps(data), ex=CACHE_TTL_SECONDS)
                logger.debug("Cache WRITE for %s", cache_key)
            except Exception as exc:
                logger.warning("Redis write failed: %s", exc)

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.ensure_future(_write())
            else:
                loop.run_until_complete(_write())
        except Exception:
            pass

    @staticmethod
    def _parse_response(raw: str) -> dict | None:
        """Attempt to parse the raw text as JSON."""
        try:
            cleaned = _extract_json(raw)
            return json.loads(cleaned)
        except (json.JSONDecodeError, TypeError) as exc:
            logger.warning("JSON parse error: %s — raw[:200]: %s", exc, raw[:200])
            return None
