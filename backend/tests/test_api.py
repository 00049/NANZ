import uuid
from unittest.mock import patch

import pytest


@pytest.mark.asyncio
async def test_health_endpoint_returns_ok(test_client):
    response = await test_client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


@pytest.mark.asyncio
@patch("app.utils.url_validator.socket.gethostbyname")
async def test_post_scan_valid_url_returns_202(mock_dns, test_client):
    mock_dns.return_value = "8.8.8.8"
    with patch("app.services.scan_service.run_scan"):
        response = await test_client.post(
            "/api/scans", json={"url": "https://example.com"}
        )
        assert response.status_code == 202
        assert "scan_id" in response.json()
        assert response.json()["status"] == "pending"


@pytest.mark.asyncio
async def test_post_scan_invalid_url_returns_422(test_client):
    response = await test_client.post("/api/scans", json={"url": "invalid-url"})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_post_scan_private_ip_returns_400(test_client):
    response = await test_client.post("/api/scans", json={"url": "http://10.0.0.1"})
    assert response.status_code == 400
    assert "Cannot scan bare IP addresses" in response.json()["detail"]


@pytest.mark.asyncio
async def test_get_scan_not_found_returns_404(test_client):
    random_id = str(uuid.uuid4())
    response = await test_client.get(f"/api/scans/{random_id}")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_get_report_without_jwt_returns_403(test_client, sample_completed_scan):
    response = await test_client.get(f"/api/reports/{sample_completed_scan}")
    assert response.status_code == 403


@pytest.mark.asyncio
@patch("app.utils.url_validator.socket.gethostbyname")
async def test_rate_limit_scan_endpoint(mock_dns, test_client):
    mock_dns.return_value = "8.8.8.8"
    # The rate limit is 5 per hour.
    # Send 6 requests, the 6th should fail.
    # We spoof the IP explicitly to ensure clean test
    with patch("app.services.scan_service.run_scan"):
        headers = {"X-Forwarded-For": "192.168.1.100"}
        for i in range(5):
            res = await test_client.post(
                "/api/scans", json={"url": f"https://example{i}.com"}, headers=headers
            )
            assert res.status_code == 202

        # 6th request
        res = await test_client.post(
            "/api/scans", json={"url": "https://example6.com"}, headers=headers
        )
        assert res.status_code == 429
