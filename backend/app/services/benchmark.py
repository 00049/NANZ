"""
Industry Benchmark Module — static lookup tables for security score comparison.

Detects industry from domain TLD/keywords, returns percentile and comparison text.
No external API calls — purely deterministic.
"""

import re
from typing import Optional


INDUSTRY_BENCHMARKS = {
    "education": {
        "avg_score": 52,
        "percentile_map": [
            (90, 95), (80, 85), (70, 70), (60, 55), (50, 40),
            (40, 25), (30, 15), (20, 8), (10, 3), (0, 1),
        ],
    },
    "ecommerce": {
        "avg_score": 61,
        "percentile_map": [
            (90, 92), (80, 80), (70, 65), (60, 50), (50, 35),
            (40, 22), (30, 12), (20, 6), (10, 2), (0, 1),
        ],
    },
    "finance": {
        "avg_score": 74,
        "percentile_map": [
            (90, 90), (80, 75), (70, 58), (60, 42), (50, 28),
            (40, 18), (30, 10), (20, 5), (10, 2), (0, 1),
        ],
    },
    "healthcare": {
        "avg_score": 63,
        "percentile_map": [
            (90, 93), (80, 82), (70, 68), (60, 52), (50, 37),
            (40, 24), (30, 14), (20, 7), (10, 3), (0, 1),
        ],
    },
    "government": {
        "avg_score": 58,
        "percentile_map": [
            (90, 94), (80, 84), (70, 70), (60, 55), (50, 40),
            (40, 26), (30, 15), (20, 8), (10, 3), (0, 1),
        ],
    },
    "media": {
        "avg_score": 55,
        "percentile_map": [
            (90, 95), (80, 85), (70, 72), (60, 57), (50, 42),
            (40, 28), (30, 16), (20, 9), (10, 4), (0, 1),
        ],
    },
    "technology": {
        "avg_score": 69,
        "percentile_map": [
            (90, 91), (80, 78), (70, 62), (60, 46), (50, 32),
            (40, 20), (30, 11), (20, 5), (10, 2), (0, 1),
        ],
    },
    "default": {
        "avg_score": 57,
        "percentile_map": [
            (90, 95), (80, 85), (70, 72), (60, 56), (50, 40),
            (40, 26), (30, 15), (20, 8), (10, 3), (0, 1),
        ],
    },
}

# Industry detection patterns
_EDUCATION_TLDS = {".edu", ".ac.in", ".edu.in", ".ac.uk", ".edu.au", ".ac.jp"}
_GOVERNMENT_TLDS = {".gov", ".gov.in", ".gov.uk", ".gov.au", ".mil"}
_ECOMMERCE_KEYWORDS = {"shop", "store", "buy", "cart", "market", "mall", "bazaar", "deals"}
_FINANCE_KEYWORDS = {"bank", "finance", "pay", "credit", "loan", "invest", "insurance", "mutual", "fund"}
_HEALTH_KEYWORDS = {"health", "clinic", "hospital", "medical", "pharma", "care", "doctor", "wellness"}
_TECH_KEYWORDS = {"tech", "software", "cloud", "app", "digital", "cyber", "data", "code", "dev", "ai"}
_MEDIA_KEYWORDS = {"news", "media", "press", "blog", "journal", "times", "post", "gazette"}


def _detect_industry(domain: str) -> str:
    """Detect industry from domain TLD and keywords."""
    domain_lower = domain.lower().strip()

    # TLD-based detection
    for tld in _EDUCATION_TLDS:
        if domain_lower.endswith(tld):
            return "education"
    for tld in _GOVERNMENT_TLDS:
        if domain_lower.endswith(tld):
            return "government"

    # Keyword-based detection (check domain name, not TLD)
    base = domain_lower.split(".")[0] if "." in domain_lower else domain_lower

    for kw in _FINANCE_KEYWORDS:
        if kw in base:
            return "finance"
    for kw in _HEALTH_KEYWORDS:
        if kw in base:
            return "healthcare"
    for kw in _ECOMMERCE_KEYWORDS:
        if kw in base:
            return "ecommerce"
    for kw in _TECH_KEYWORDS:
        if kw in base:
            return "technology"
    for kw in _MEDIA_KEYWORDS:
        if kw in base:
            return "media"

    return "default"


def _score_to_percentile(score: int, percentile_map: list[tuple[int, int]]) -> int:
    """Map a security score to a percentile using the industry-specific lookup table."""
    for threshold, percentile in percentile_map:
        if score >= threshold:
            return percentile
    return 1


def get_benchmark(domain: str, score: int) -> dict:
    """
    Return industry benchmark comparison for a domain and score.

    Returns:
        {
            "industry": str,
            "industry_avg": int,
            "percentile": int,
            "comparison": str,
        }
    """
    industry = _detect_industry(domain)
    bench = INDUSTRY_BENCHMARKS.get(industry, INDUSTRY_BENCHMARKS["default"])

    avg = bench["avg_score"]
    percentile = _score_to_percentile(score, bench["percentile_map"])

    diff = score - avg
    industry_label = industry.replace("_", " ").title()

    if diff >= 15:
        comparison = f"Significantly above average for {industry_label} sites"
    elif diff >= 5:
        comparison = f"Above average for {industry_label} sites"
    elif diff >= -5:
        comparison = f"On par with average {industry_label} sites"
    elif diff >= -15:
        comparison = f"Below average for {industry_label} sites"
    else:
        comparison = f"Significantly below average for {industry_label} sites"

    return {
        "industry": industry,
        "industry_avg": avg,
        "percentile": percentile,
        "comparison": comparison,
    }
