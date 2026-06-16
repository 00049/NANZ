from typing import Any

import httpx

from app.security.url_validator import SSRFValidator


class SecureTransport(httpx.AsyncHTTPTransport):
    """
    A custom transport that ensures all outbound HTTP requests,
    including those following redirects, are validated against SSRF.
    """

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        url_str = str(request.url)
        # Pre-flight SSRF validation (resolves DNS, blocks internal IPs)
        SSRFValidator.validate_url(url_str)

        # Proceed with the actual request
        return await super().handle_async_request(request)


def get_secure_async_client(
    timeout: float = 10.0,
    verify: bool = True,
    follow_redirects: bool = True,
    headers: dict[str, str] | None = None,
    **kwargs: Any,
) -> httpx.AsyncClient:
    """
    Returns an httpx.AsyncClient that is heavily protected against SSRF.
    It hooks into the transport layer to ensure all redirects are validated.
    """
    transport = SecureTransport(retries=kwargs.pop("retries", 0), verify=verify)

    return httpx.AsyncClient(
        transport=transport,
        timeout=timeout,
        follow_redirects=follow_redirects,
        headers=headers,
        **kwargs,
    )
