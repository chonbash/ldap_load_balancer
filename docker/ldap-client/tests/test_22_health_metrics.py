"""Scenario 22: Health and metrics HTTP endpoints."""
import urllib.request
import pytest


@pytest.mark.order(22)
def test_health_endpoint(metrics_url):
    """GET /health returns 200."""
    req = urllib.request.urlopen(f"{metrics_url}/health", timeout=5)
    assert req.status == 200


@pytest.mark.order(22)
def test_ready_endpoint(metrics_url):
    """GET /ready returns 200 or 503."""
    req = urllib.request.urlopen(f"{metrics_url}/ready", timeout=5)
    assert req.status in (200, 503)


@pytest.mark.order(22)
def test_metrics_backend_up(metrics_url):
    """GET /metrics contains ldap_lb_backend_up."""
    req = urllib.request.urlopen(f"{metrics_url}/metrics", timeout=5)
    body = req.read().decode()
    assert "ldap_lb_backend_up" in body
