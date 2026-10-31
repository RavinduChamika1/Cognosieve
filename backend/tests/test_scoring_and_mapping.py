import pytest
from services.scoring_engine import ScoringEngine
from services.mapping_engine import MappingEngine

def test_cvss_base_score_resolution():
    score, vector = ScoringEngine.get_base_score_and_vector("CWE-89")
    assert score == 9.8
    assert "CVSS:3.1" in vector

    score, vector = ScoringEngine.get_base_score_and_vector("CWE-79")
    assert score == 7.2

    score, vector = ScoringEngine.get_base_score_and_vector("CWE-1021")
    assert score == 4.3

def test_adjusted_score_calculation():
    # Base 8.0 with default 1.0 multiplier and 1.0 exposure
    adj = ScoringEngine.calculate_adjusted_score(8.0, 1.0, 1.0)
    assert adj == 8.0

    # Base 5.0 with 1.5 business multiplier -> 7.5
    adj = ScoringEngine.calculate_adjusted_score(5.0, 1.5, 1.0)
    assert adj == 7.5

    # Base 9.8 with 1.5 business multiplier -> capped at 10.0
    adj = ScoringEngine.calculate_adjusted_score(9.8, 1.5, 1.0)
    assert adj == 10.0

    # Base 8.0 with 0.5 multiplier and 0.8 exposure
    adj = ScoringEngine.calculate_adjusted_score(8.0, 0.5, 0.8)
    assert adj == 3.2

def test_severity_mapping():
    assert ScoringEngine.map_score_to_severity(9.8) == "Critical"
    assert ScoringEngine.map_score_to_severity(9.0) == "Critical"
    assert ScoringEngine.map_score_to_severity(8.9) == "High"
    assert ScoringEngine.map_score_to_severity(7.0) == "High"
    assert ScoringEngine.map_score_to_severity(6.9) == "Medium"
    assert ScoringEngine.map_score_to_severity(4.0) == "Medium"
    assert ScoringEngine.map_score_to_severity(3.9) == "Low"
    assert ScoringEngine.map_score_to_severity(0.5) == "Low"

def test_mapping_engine_cwe_resolution():
    # Explicit CWE ID
    cwe = MappingEngine.resolve_cwe("89", "40018", "SQL Injection")
    assert cwe == "CWE-89"

    # From ZAP Plugin ID
    cwe = MappingEngine.resolve_cwe("0", "10020", "Anti-clickjacking Header Not Set")
    assert cwe == "CWE-1021"

    # From keyword in alert title
    cwe = MappingEngine.resolve_cwe("", "", "Reflected Cross Site Scripting")
    assert cwe == "CWE-79"

def test_mapping_engine_metadata():
    meta = MappingEngine.get_metadata("CWE-89")
    assert meta["owasp"] == "A03:2021-Injection"
    assert meta["mitre"] == "T1190"
    assert len(meta["references"]) >= 2
