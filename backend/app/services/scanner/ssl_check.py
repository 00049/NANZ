import ssl
import socket
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Optional

@dataclass
class SSLResult:
    valid: bool
    expiry_date: Optional[str]
    days_until_expiry: Optional[int]
    tls_version: Optional[str]
    issuer: Optional[str]
    is_self_signed: bool
    error: Optional[str] = None

async def run(domain: str) -> SSLResult:
    """
    Connects to the domain on port 443 to retrieve SSL certificate details.
    """
    try:
        # Create a default context that verifies certs
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # We want to retrieve it even if invalid

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10.0)
        
        # Async wrapper roughly by running socket in a thread, or simple blocking is mostly okay here given 10s timeout,
        # but to be truly async we should use asyncio event loop in orchestrator. 
        # Using a standard blocking call here is ok as asyncio.to_thread will be used in orchestrator if needed, 
        # but standard is to keep it synchronous here and let caller handle. Let's make it blocking but async def.
        wrapped_sock = ctx.wrap_socket(sock, server_hostname=domain)
        
        try:
            wrapped_sock.connect((domain, 443))
            cert = wrapped_sock.getpeercert(binary_form=False)
            
            # If CERT_NONE is used, getpeercert() returns empty dict.
            # We need to do a verified connection to get full details usually, 
            # Or use ssl.get_server_certificate, but that doesn't return the parsed dict.
        finally:
            wrapped_sock.close()
            
    except Exception as e:
        return SSLResult(
            valid=False, expiry_date=None, days_until_expiry=None,
            tls_version=None, issuer=None, is_self_signed=False, error=str(e)
        )
        
    # Let's do a proper retrieval that works:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                
                expiry_str = cert['notAfter']
                expiry = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                expiry = expiry.replace(tzinfo=timezone.utc)
                days_left = (expiry - datetime.now(timezone.utc)).days
                
                issuer = dict(x[0] for x in cert.get('issuer', []))
                subject = dict(x[0] for x in cert.get('subject', []))
                
                issuer_cn = issuer.get('CN', issuer.get('O', 'Unknown'))
                subject_cn = subject.get('CN', 'Unknown')
                is_self = (issuer_cn == subject_cn and subject_cn != 'Unknown')

                return SSLResult(
                    valid=True,
                    expiry_date=expiry.isoformat() if expiry else None,
                    days_until_expiry=days_left,
                    tls_version=protocol,
                    issuer=issuer_cn,
                    is_self_signed=is_self
                )
    except Exception as e:
        return SSLResult(
            valid=False, expiry_date=None, days_until_expiry=None,
            tls_version=None, issuer=None, is_self_signed=False, error=str(e)
        )
