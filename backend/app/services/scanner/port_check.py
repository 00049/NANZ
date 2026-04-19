import json
import logging
import httpx
import asyncio
from dataclasses import dataclass, field
from typing import Optional

from app.config import settings
from redis.asyncio import Redis

logger = logging.getLogger(__name__)


@dataclass
class PortResult:
    """Result of passive exposed-port inspection."""

    open_ports: list[int] = field(default_factory=list)
    services: list[dict] = field(default_factory=list)
    source: str = ""
    error: Optional[str] = None


async def check_port_direct(ip: str, port: int) -> bool:
    """Return True when a TCP connection can be opened to a port."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=3.0
        )
        writer.close()
        await writer.wait_closed()
        return True
    except (ConnectionError, TimeoutError, OSError, asyncio.TimeoutError) as e:
        logger.error(f"Direct port probe failed for ip={ip} port={port}: {e}", exc_info=True)
        return False


async def run(ip_address: str, redis_client: Redis) -> PortResult:
    """
    Checks for open ports using Shodan API (if available) or direct connection.
    Caches Shodan results in Redis.
    """
    if not ip_address:
        return PortResult(error="No IP address provided")
        
    cache_key = f"shodan:ip:{ip_address}"
    
    try:
        cached_data = await redis_client.get(cache_key)
        if cached_data:
            data = json.loads(cached_data)
            return PortResult(
                open_ports=data.get("open_ports", []),
                services=data.get("services", []),
                source="shodan-cache"
            )
    except (ConnectionError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as e:
        logger.error(f"Shodan cache read failed for ip={ip_address}: {e}", exc_info=True)

    if settings.SHODAN_API_KEY:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.get(f"https://api.shodan.io/shodan/host/{ip_address}?key={settings.SHODAN_API_KEY}")
                if res.status_code == 200:
                    data = res.json()
                    ports = data.get("ports", [])
                    services = []
                    for item in data.get("data", []):
                        services.append({
                            "port": item.get("port"),
                            "product": item.get("product"),
                            "version": item.get("version")
                        })
                        
                    result_dict = {
                        "open_ports": ports,
                        "services": services
                    }
                    try:
                        await redis_client.set(cache_key, json.dumps(result_dict), ex=86400)
                    except (ConnectionError, TimeoutError, OSError, ValueError) as cache_error:
                        logger.error(f"Shodan cache write failed for ip={ip_address}: {cache_error}", exc_info=True)
                    return PortResult(open_ports=ports, services=services, source="shodan")
                return PortResult(open_ports=[], services=[], source="shodan", error="Shodan unavailable")
        except (httpx.HTTPError, ValueError) as e:
            logger.error(f"Shodan API unavailable for ip={ip_address}: {e}", exc_info=True)
            return PortResult(error="Shodan unavailable")

    dangerous_ports = [21, 23, 3306, 5432, 27017, 6379]
    open_ports = []
    
    try:
        tasks = [check_port_direct(ip_address, p) for p in dangerous_ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for p, r in zip(dangerous_ports, results):
            if isinstance(r, bool) and r is True:
                open_ports.append(p)
                
        return PortResult(open_ports=open_ports, source="direct")
    except Exception as e:
        logger.error(f"Direct port fallback failed for ip={ip_address}: {e}", exc_info=True)
        return PortResult(error="Port check unavailable")
