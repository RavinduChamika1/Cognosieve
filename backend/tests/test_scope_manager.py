import pytest
from services.scope_manager import ScopeManager, ScopeRule

def test_wildcard_domain_in_scope():
    in_scope = "*.example.com\nexample.com"
    out_scope = ""

    # Should match
    is_in, _ = ScopeManager.evaluate_url("https://example.com/test", in_scope, out_scope)
    assert is_in is True

    is_in, _ = ScopeManager.evaluate_url("https://api.example.com/v1", in_scope, out_scope)
    assert is_in is True

    is_in, _ = ScopeManager.evaluate_url("https://deep.sub.example.com/", in_scope, out_scope)
    assert is_in is True

    # Should NOT match
    is_in, _ = ScopeManager.evaluate_url("https://attacker.com/test", in_scope, out_scope)
    assert is_in is False

    is_in, _ = ScopeManager.evaluate_url("https://notexample.com", in_scope, out_scope)
    assert is_in is False

def test_out_of_scope_always_wins():
    in_scope = "*.example.com\nhttps://example.com"
    out_scope = "/admin/*\n*.staging.example.com"

    # In-scope general path
    is_in, _ = ScopeManager.evaluate_url("https://example.com/user/profile", in_scope, out_scope)
    assert is_in is True

    # Out-of-scope path on in-scope host -> MUST BE REJECTED
    is_in, reason = ScopeManager.evaluate_url("https://example.com/admin/delete", in_scope, out_scope)
    assert is_in is False
    assert "out-of-scope rule" in reason

    # Out-of-scope subdomain on in-scope root -> MUST BE REJECTED
    is_in, reason = ScopeManager.evaluate_url("https://api.staging.example.com/data", in_scope, out_scope)
    assert is_in is False
    assert "out-of-scope rule" in reason

def test_cidr_scope_matching():
    in_scope = "192.168.1.0/24\n10.0.0.5"
    out_scope = "192.168.1.50"

    is_in, _ = ScopeManager.evaluate_url("http://192.168.1.20:8080/app", in_scope, out_scope)
    assert is_in is True

    is_in, _ = ScopeManager.evaluate_url("http://10.0.0.5/", in_scope, out_scope)
    assert is_in is True

    # Out of scope specific IP wins over subnet
    is_in, reason = ScopeManager.evaluate_url("http://192.168.1.50/login", in_scope, out_scope)
    assert is_in is False

    # IP outside CIDR
    is_in, _ = ScopeManager.evaluate_url("http://192.168.2.1/", in_scope, out_scope)
    assert is_in is False

def test_filter_urls():
    candidates = [
        "https://example.com/home",
        "https://example.com/admin/settings",
        "https://api.example.com/data",
        "https://thirdparty.com/cdn"
    ]
    in_scope = "*.example.com"
    out_scope = "/admin/*"

    filtered = ScopeManager.filter_urls(candidates, in_scope, out_scope)
    assert "https://example.com/home" in filtered
    assert "https://api.example.com/data" in filtered
    assert "https://example.com/admin/settings" not in filtered
    assert "https://thirdparty.com/cdn" not in filtered
