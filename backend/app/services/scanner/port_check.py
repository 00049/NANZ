import json
import httpx
import traceback
import socket
import asyncio
from dataclasses import dataclass, field
from typing import Optional

from app.config import settings
from redis.asyncio import Redis

@dataclass
class PortResult:
    open_ports: list[int] = field(default_factory=list)
    services: list[dict] = field(default_factory=list)
    source: str = ""
    error: Optional[str] = None

async def check_port_direct(ip: str, port: int) -> bool:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=3.0
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False

async def run(ip_address: str, redis_client: Redis) -> PortResult:
    """
    Checks for open ports using Shodan API (if available) or direct connection.
    Caches Shodan results in Redis.
    """
    if not ip_address:
        return PortResult(error="No IP address provided")
        
    cache_key = f"shodan:ip:{ip_address}"
    
    # Try cache first
    cached_data = await redis_client.get(cache_key)
    if cached_data:
        try:
            data = json.loads(cached_data)
            return PortResult(
                open_ports=data.get("open_ports", []),
                services=data.get("services", []),
                source="shodan-cache"
            )
        except Exception:
            pass

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
                    await redis_client.set(cache_key, json.dumps(result_dict), ex=86400) # 24 hours
                    return PortResult(open_ports=ports, services=services, source="shodan")
        except Exception as e:
            return PortResult(error=f"Shodan API error: {str(e)}")

    # Fallback to direct port scanning for dangerous ports
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
        return PortResult(error=str(e))
