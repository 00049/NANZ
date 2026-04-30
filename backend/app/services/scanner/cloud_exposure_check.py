"""
Cloud Storage Exposure Module — checks for publicly accessible cloud buckets.

Generates bucket name guesses from domain and checks AWS S3, Google Cloud Storage,
and Azure Blob Storage for public listing.

All checks are passive HTTP GET requests — no write operations.
"""

import httpx
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

MAX_REQUESTS = 15
REQUEST_TIMEOUT = 5.0


@dataclass
class CloudResult:
    public_buckets: list[dict] = field(default_factory=list)
    protected_buckets: list[dict] = field(default_factory=list)
    total_checked: int = 0
    error: Optional[str] = None


def _generate_bucket_names(domain: str) -> list[str]:
    """Generate candidate bucket names from domain."""
    # Extract base name from domain
    parts = domain.lower().split(".")
    if len(parts) >= 2:
        base = parts[0] if parts[0] != "www" else parts[1]
    else:
        base = parts[0]

    # Also try full domain without TLD
    full_base = ".".join(parts[:-1]) if len(parts) > 1 else parts[0]
    full_base_dashed = full_base.replace(".", "-")

    candidates = [
        base,
        f"{base}-backup",
        f"{base}-backups",
        f"{base}-assets",
        f"{base}-static",
        f"{base}-uploads",
        f"{base}-files",
        f"{base}-media",
        f"{base}-dev",
        f"{base}-staging",
        f"{base}-prod",
        f"{base}-data",
        f"www-{base}",
        full_base_dashed,
        f"{full_base_dashed}-assets",
    ]

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for c in candidates:
        if c not in seen and len(c) >= 3:
            seen.add(c)
            unique.append(c)

    return unique[:MAX_REQUESTS]


async def _check_s3(client: httpx.AsyncClient, bucket: str) -> Optional[dict]:
    """Check AWS S3 bucket for public access."""
    urls = [
        f"https://{bucket}.s3.amazonaws.com/",
        f"https://s3.amazonaws.com/{bucket}/",
    ]

    for url in urls:
        try:
            res = await client.get(url)
            body = res.text[:500]

            if res.status_code == 200 and "<ListBucketResult" in body:
                return {"provider": "AWS S3", "url": url, "name": bucket, "access": "public"}
            elif res.status_code == 403:
                return {"provider": "AWS S3", "url": url, "name": bucket, "access": "protected"}
            # 404 or NoSuchBucket = doesn't exist, skip
        except Exception:
            continue

    return None


async def _check_gcs(client: httpx.AsyncClient, bucket: str) -> Optional[dict]:
    """Check Google Cloud Storage bucket for public access."""
    url = f"https://storage.googleapis.com/{bucket}/"
    try:
        res = await client.get(url)
        body = res.text[:500]

        if res.status_code == 200 and ("<ListBucketResult" in body or "Contents" in body):
            return {"provider": "Google Cloud Storage", "url": url, "name": bucket, "access": "public"}
        elif res.status_code == 403:
            return {"provider": "Google Cloud Storage", "url": url, "name": bucket, "access": "protected"}
    except Exception:
        pass

    return None


async def _check_azure(client: httpx.AsyncClient, base: str) -> Optional[dict]:
    """Check Azure Blob Storage for public access."""
    url = f"https://{base}.blob.core.windows.net/{base}?restype=container&comp=list"
    try:
        res = await client.get(url)
        body = res.text[:500]

        if res.status_code == 200 and "<EnumerationResults" in body:
            return {"provider": "Azure Blob", "url": url, "name": base, "access": "public"}
        elif res.status_code == 403:
            return {"provider": "Azure Blob", "url": url, "name": base, "access": "protected"}
    except Exception:
        pass

    return None


async def run(domain: str) -> CloudResult:
    """
    Check for exposed cloud storage buckets by guessing bucket names from domain.
    Checks AWS S3, Google Cloud Storage, and Azure Blob Storage.
    """
    result = CloudResult()

    try:
        bucket_names = _generate_bucket_names(domain)

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(5.0),
            follow_redirects=False,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (compatible; ShieldCheck/2.0)"}
        ) as client:

            for bucket in bucket_names:
                result.total_checked += 1

                try:
                    # Check S3
                    s3_result = await _check_s3(client, bucket)
                    if s3_result:
                        if s3_result["access"] == "public":
                            result.public_buckets.append(s3_result)
                        else:
                            result.protected_buckets.append(s3_result)
                        continue  # Found on S3, skip other providers for this name

                    # Check GCS
                    gcs_result = await _check_gcs(client, bucket)
                    if gcs_result:
                        if gcs_result["access"] == "public":
                            result.public_buckets.append(gcs_result)
                        else:
                            result.protected_buckets.append(gcs_result)
                        continue

                    # Check Azure (only for base name)
                    if bucket == _generate_bucket_names(domain)[0]:
                        azure_result = await _check_azure(client, bucket)
                        if azure_result:
                            if azure_result["access"] == "public":
                                result.public_buckets.append(azure_result)
                            else:
                                result.protected_buckets.append(azure_result)
                except Exception as e:
                    logger.warning(f"Error checking bucket {bucket}: {e}")
                    continue

    except Exception as e:
        logger.error(f"Cloud exposure check failed: {e}", exc_info=True)
        result.error = "Cloud exposure check partially failed"

    return result
