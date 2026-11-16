"""Report parsing and normalisation (incl. secret-value suppression)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from conftest import load_fixture
from engine.finding_normalizer import Coverage, NormalizedFinding, deduplicate
from engine.report_parser import (ReportParseError, parse_gitleaks_data, parse_gitleaks_report, parse_trivy_data,
                                  parse_trivy_report)


def test_trivy_fixture_categories_and_dedup() -> None:
    findings = parse_trivy_data(load_fixture("trivy_fs.json"))
    by_cat: dict[str, list[NormalizedFinding]] = {}
    for f in findings:
        by_cat.setdefault(f.category, []).append(f)
    assert len(by_cat["VULNERABILITY"]) == 2  # duplicate jinja2 entry collapsed
    assert len(by_cat["MISCONFIGURATION"]) == 1  # PASS ignored
    assert len(by_cat["SECRET"]) == 1
    req = next(f for f in by_cat["VULNERABILITY"] if f.package_name == "requests")
    assert (req.vulnerability_id, req.installed_version, req.fixed_version, req.severity) == \
           ("CVE-2023-32681", "2.25.0", "2.31.0", "MEDIUM")
    assert "Upgrade requests" in req.remediation
    jinja = next(f for f in by_cat["VULNERABILITY"] if f.package_name == "jinja2")
    assert jinja.fixed_version is None and "No fixed version" in jinja.remediation
    mis = by_cat["MISCONFIGURATION"][0]
    assert mis.rule_id == "AVD-DS-0002" and mis.line == 1 and "USER" in mis.remediation


def test_secret_values_never_copied() -> None:
    findings = parse_trivy_data(load_fixture("trivy_fs.json")) + parse_gitleaks_data(load_fixture("gitleaks.json"))
    blob = json.dumps([f.to_dict() for f in findings])
    assert "SHOULDNEVERBESTORED" not in blob
    assert "test@example.invalid" not in blob  # author email not retained


def test_gitleaks_metadata() -> None:
    [f] = parse_gitleaks_data(load_fixture("gitleaks.json"), scan_type="git")
    assert f.category == "SECRET" and f.severity == "HIGH" and f.rule_id == "github-pat"
    assert f.file_path == "app/config.py" and f.line == 3
    assert f.metadata["commit"].startswith("a1b2c3")
    assert "revoke and rotate" in f.remediation


def test_fingerprints_are_stable_and_distinct() -> None:
    a = parse_trivy_data(load_fixture("trivy_fs.json"))
    b = parse_trivy_data(load_fixture("trivy_fs.json"))
    assert sorted(f.fingerprint for f in a) == sorted(f.fingerprint for f in b)
    assert len({f.fingerprint for f in a}) == len(a)
    # Same data under different scan type -> different fingerprint
    c = parse_trivy_data(load_fixture("trivy_fs.json"), scan_type="config")
    assert not ({f.fingerprint for f in a} & {f.fingerprint for f in c})


def test_empty_trivy_results() -> None:
    assert parse_trivy_data({"SchemaVersion": 2, "Results": None}) == []
    assert parse_trivy_data({"SchemaVersion": 2}) == []


@pytest.mark.parametrize("payload", [[], "x", {"foo": 1}])
def test_invalid_trivy_structure(payload: object) -> None:
    with pytest.raises(ReportParseError):
        parse_trivy_data(payload)


def test_invalid_and_missing_files(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(ReportParseError):
        parse_trivy_report(bad)
    with pytest.raises(ReportParseError):
        parse_gitleaks_report(tmp_path / "missing.json")
    empty = tmp_path / "empty.json"
    empty.write_text("", encoding="utf-8")
    with pytest.raises(ReportParseError):
        parse_gitleaks_report(empty)


def test_gitleaks_empty_and_invalid() -> None:
    assert parse_gitleaks_data([]) == []
    with pytest.raises(ReportParseError):
        parse_gitleaks_data({"not": "a list"})
    with pytest.raises(ReportParseError):
        parse_gitleaks_data(["string entry"])


def test_unknown_severity_and_category_normalised() -> None:
    f = NormalizedFinding("trivy", "fs", "weird", "SEVERE", vulnerability_id="X")
    assert f.severity == "UNKNOWN" and f.category == "OTHER"


def test_deduplicate_keeps_worst_severity() -> None:
    a = NormalizedFinding("trivy", "fs", "VULNERABILITY", "LOW", identity=("same",))
    b = NormalizedFinding("trivy", "fs", "VULNERABILITY", "HIGH", identity=("same",))
    [d] = deduplicate([a, b])
    assert d.severity == "HIGH"


def test_coverage_roundtrip_and_covers() -> None:
    cov = Coverage("trivy", "fs", ".", frozenset({"VULNERABILITY"}), frozenset({"HIGH", "CRITICAL"}))
    assert Coverage.from_key(cov.key()) == cov
    assert cov.covers("trivy", "fs", ".", "VULNERABILITY", "HIGH")
    assert not cov.covers("trivy", "fs", ".", "VULNERABILITY", "LOW")
    assert not cov.covers("trivy", "fs", ".", "SECRET", "HIGH")
    assert not cov.covers("gitleaks", "fs", ".", "VULNERABILITY", "HIGH")
