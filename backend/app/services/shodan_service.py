import logging
from typing import Any

import shodan

from app.config import settings

logger = logging.getLogger(__name__)

# Initialize Shodan client if API key is provided
_shodan_api = None
if settings.SHODAN_API_KEY:
    try:
        _shodan_api = shodan.Shodan(settings.SHODAN_API_KEY)
    except Exception as e:
        logger.error(f"Failed to initialize Shodan client: {e}")


def _get_api() -> shodan.Shodan:
    """Helper to ensure the API is configured before calling methods."""
    if not _shodan_api:
        raise ValueError("SHODAN_API_KEY is not configured in the environment.")
    return _shodan_api


async def host_lookup(ip: str) -> dict[str, Any]:
    """
    Look up an IP address in Shodan.

    Args:
        ip (str): The IP address to look up.

    Returns:
        dict: The host information dictionary.
    """
    try:
        api = _get_api()
        # Shodan python library is synchronous, we use it directly here.
        # In a high-throughput async app, this could be wrapped in asyncio.to_thread
        # if the request is blocking the event loop.
        host = api.host(ip)
        return host
    except shodan.APIError as e:
        logger.error(f"Shodan API Error during host lookup for {ip}: {e}")
        return {"error": str(e)}
    except ValueError as e:
        logger.warning(str(e))
        return {"error": str(e)}
    except Exception as e:
        logger.error(
            f"Unexpected error during Shodan host lookup for {ip}: {e}", exc_info=True
        )
        return {"error": "Internal error during Shodan host lookup"}


async def search(query: str) -> dict[str, Any]:
    """
    Search Shodan using a query string.

    Args:
        query (str): The search query.

    Returns:
        dict: The search results.
    """
    try:
        api = _get_api()
        results = api.search(query)
        return results
    except shodan.APIError as e:
        logger.error(f"Shodan API Error during search for '{query}': {e}")
        return {"error": str(e)}
    except ValueError as e:
        logger.warning(str(e))
        return {"error": str(e)}
    except Exception as e:
        logger.error(
            f"Unexpected error during Shodan search for '{query}': {e}", exc_info=True
        )
        return {"error": "Internal error during Shodan search"}


async def domain_lookup(domain: str) -> dict[str, Any]:
    """
    Get all subdomains and DNS information for a given domain from Shodan.
    Requires an Enterprise API key (or upgraded API key) depending on the endpoint.

    Args:
        domain (str): The domain to look up.

    Returns:
        dict: The domain information.
    """
    try:
        api = _get_api()
        domain_info = api.dns.domain_info(domain)
        return domain_info
    except shodan.APIError as e:
        logger.error(f"Shodan API Error during domain lookup for {domain}: {e}")
        return {"error": str(e)}
    except ValueError as e:
        logger.warning(str(e))
        return {"error": str(e)}
    except Exception as e:
        logger.error(
            f"Unexpected error during Shodan domain lookup for {domain}: {e}",
            exc_info=True,
        )
        return {"error": "Internal error during Shodan domain lookup"}
