import logging
import dns.asyncresolver
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class DNSResult:
    """Result of email-protection DNS record checks."""

    has_spf: bool
    has_dmarc: bool
    has_dkim: bool
    spf_record: Optional[str]
    dmarc_record: Optional[str]
    error: Optional[str] = None


async def query_txt(domain: str) -> list[str]:
    """Query TXT records for a domain and return decoded record values."""
    records = []
    try:
        answers = await dns.asyncresolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt = "".join([part.decode('utf-8') for part in rdata.strings])
            records.append(txt)
    except (dns.resolver.DNSException, TimeoutError, OSError) as e:
        logger.error(f"TXT lookup failed for domain={domain}: {e}", exc_info=True)
    return records


async def run(domain: str) -> DNSResult:
    """
    Checks for SPF, DMARC, and DKIM DNS records.
    """
    try:
        domain_txts = await query_txt(domain)
        spf_record = next((t for t in domain_txts if t.startswith("v=spf1")), None)
        
        dmarc_txts = await query_txt(f"_dmarc.{domain}")
        dmarc_record = next((t for t in dmarc_txts if t.startswith("v=DMARC1")), None)
        
        dkim_txts = await query_txt(f"default._domainkey.{domain}")
        has_dkim = len(dkim_txts) > 0
        
        return DNSResult(
            has_spf=bool(spf_record),
            has_dmarc=bool(dmarc_record),
            has_dkim=has_dkim,
            spf_record=spf_record,
            dmarc_record=dmarc_record
        )
    except Exception as e:
        logger.error(f"DNS check failed for domain={domain}: {e}", exc_info=True)
        return DNSResult(
            has_spf=False,
            has_dmarc=False,
            has_dkim=False,
            spf_record=None,
            dmarc_record=None,
            error="DNS check unavailable"
        )
