import pytest
from starlette.testclient import TestClient
from main import app
from database import init_db

@pytest.fixture(autouse=True)
def setup_db():
    init_db()

client = TestClient(app)

def test_health_endpoint():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["service"] == "CognoSieve"
    assert "zap_daemon_online" in data
    assert "gemini_api_configured" in data

def test_scope_validation_endpoint():
    res = client.post("/api/validate-scope", params={
        "target_url": "https://api.example.com/v1",
        "in_scope": "*.example.com",
        "out_of_scope": "/admin/*"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["is_in_scope"] is True

    # Out of scope match
    res = client.post("/api/validate-scope", params={
        "target_url": "https://api.example.com/admin/secrets",
        "in_scope": "*.example.com",
        "out_of_scope": "/admin/*"
    })
    assert res.status_code == 200
    assert res.json()["is_in_scope"] is False

def test_reject_unauthorized_scan():
    # Authorization confirmation is False -> MUST REJECT
    payload = {
        "target_url": "https://example.com",
        "in_scope": "*.example.com",
        "out_of_scope": "",
        "authorization_confirmation": False,
        "scan_mode": "passive",
        "active_scan_confirmed": False
    }
    res = client.post("/api/scans", json=payload)
    # Pydantic validator catches False and returns 422
    assert res.status_code in (400, 403, 422)

def test_reject_out_of_scope_target():
    payload = {
        "target_url": "https://unauthorized-domain.com",
        "in_scope": "*.my-allowed-target.com",
        "out_of_scope": "",
        "authorization_confirmation": True,
        "scan_mode": "passive",
        "active_scan_confirmed": False
    }
    res = client.post("/api/scans", json=payload)
    assert res.status_code == 400
    assert "not authorized by the defined scope" in res.json()["detail"]

def test_reject_unconfirmed_active_scan():
    payload = {
        "target_url": "https://example.com",
        "in_scope": "*.example.com",
        "out_of_scope": "",
        "authorization_confirmation": True,
        "scan_mode": "active",
        "active_scan_confirmed": False  # Missing 2nd explicit confirmation!
    }
    res = client.post("/api/scans", json=payload)
    assert res.status_code == 400
    assert "Active scanning requires second explicit confirmation" in res.json()["detail"]

def test_successful_scan_submission_and_retrieval():
    payload = {
        "target_url": "https://testphp.vulnweb.com",
        "in_scope": "*.vulnweb.com",
        "out_of_scope": "/admin/*",
        "authorization_confirmation": True,
        "scan_mode": "passive",
        "active_scan_confirmed": False,
        "business_impact_multiplier": 1.2,
        "exposure_factor": 1.0
    }
    res = client.post("/api/scans", json=payload)
    assert res.status_code == 201
    scan = res.json()
    assert scan["target_url"] == "https://testphp.vulnweb.com"
    assert scan["authorization_confirmed"] is True
    scan_id = scan["id"]

    # Verify retrieval
    res_get = client.get(f"/api/scans/{scan_id}")
    assert res_get.status_code == 200
    assert res_get.json()["id"] == scan_id
