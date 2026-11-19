"""API testing from OpenAPI / Swagger descriptions (part of the web scan)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from engine import api_scanner as A
from engine.dast_scanner import DastScanner
from utils.config import AppConfig
from vapt.create_lab import LAB_OPENAPI
from vapt.lab_web_app import LabWebApp

OAS3 = {
    "openapi": "3.0.0", "info": {"title": "t", "version": "1"}, "servers": [{"url": "/v1"}],
    "security": [{"key": []}],
    "components": {"schemas": {"Loan": {"type": "object", "properties": {
        "income": {"type": "number", "example": 5000}, "name": {"type": "string"},
        "kind": {"type": "string", "enum": ["home", "car"]}, "tags": {"type": "array", "items": {"type": "string"}}}}}},
    "paths": {
        "/items/{id}": {"parameters": [{"name": "id", "in": "path", "schema": {"type": "integer"}}],
                        "get": {"security": [], "parameters": [{"name": "q", "in": "query",
                                                                "schema": {"type": "string", "default": "x"}}]},
                        "delete": {}},
        "/predict": {"post": {"requestBody": {"content": {"application/json": {
            "schema": {"$ref": "#/components/schemas/Loan"}}}}}},
    },
}
SWAGGER2 = {"swagger": "2.0", "basePath": "/api", "paths": {"/echo": {"post": {"parameters": [
    {"in": "body", "name": "b", "schema": {"type": "object", "properties": {"msg": {"type": "string"}}}}]}}}}


def test_parse_and_operations_openapi3() -> None:
    spec = A.parse_spec(json.dumps(OAS3))
    ops = {o.key: o for o in A.operations(spec)}
    assert set(ops) == {"GET /items/{id}", "POST /predict"}  # DELETE is never collected
    get = ops["GET /items/{id}"]
    assert get.url("http://127.0.0.1:1") == "http://127.0.0.1:1/v1/items/1?q=x" and not get.secured
    post = ops["POST /predict"]
    assert post.secured  # global security applies
    assert post.body == {"income": 5000, "name": "test", "kind": "home", "tags": ["test"]}
    assert A.string_fields(post.body) == ["name", "kind"] and A.numeric_fields(post.body) == ["income"]
    assert A.with_value(post.body, "name", "z")["name"] == "z" and post.body["name"] == "test"


def test_swagger2_and_yaml_and_errors() -> None:
    ops = A.operations(A.parse_spec(json.dumps(SWAGGER2)))
    assert [o.key for o in ops] == ["POST /echo"] and ops[0].body == {"msg": "test"} and ops[0].base == "/api"
    assert [o.key for o in A.operations(A.parse_spec(LAB_OPENAPI))][0] == "GET /api/users"
    for bad in ("not: [valid", "{}", json.dumps({"openapi": "1.0", "paths": {}})):
        with pytest.raises(A.SpecError):
            A.parse_spec(bad)


def test_read_spec_file_locations(tmp_path: Path) -> None:
    (tmp_path / "proj" / "api").mkdir(parents=True)
    (tmp_path / "proj" / "api" / "o.yaml").write_text(LAB_OPENAPI, encoding="utf-8")
    (tmp_path / "specs").mkdir()
    (tmp_path / "specs" / "other.json").write_text(json.dumps(OAS3), encoding="utf-8")
    assert A.read_spec_file("api/o.yaml", tmp_path / "proj", [])[1].name == "o.yaml"
    assert A.read_spec_file("other.json", tmp_path / "proj", [tmp_path / "specs"])[1].name == "other.json"
    with pytest.raises(A.SpecError, match="not found"):
        A.read_spec_file("missing.yaml", tmp_path / "proj", [tmp_path / "specs"])


def test_api_scan_finds_lab_issues_and_respects_post_allow_list(tmp_path: Path) -> None:
    (tmp_path / "api").mkdir()
    (tmp_path / "api" / "openapi.yaml").write_text(LAB_OPENAPI, encoding="utf-8")
    app = LabWebApp("vulnerable", "x").start()
    try:
        ex = DastScanner().scan(app.url, tmp_path / "r.json", 120, api={
            "source": "api/openapi.yaml", "post_allowed": ["/api/echo"], "project": tmp_path, "roots": []})
        assert ex.status == "COMPLETED_WITH_FINDINGS", ex.error_message
        got = {(f.rule_id, f.file_path, f.metadata["method"]) for f in ex.findings if f.metadata.get("api")}
        assert {("DAST-SQLI", "/api/users", "GET"), ("DAST-API-AUTH", "/api/admin/stats", "GET"),
                ("DAST-XSS", "/api/echo", "POST"), ("DAST-ERROR-LEAK", "/api/echo", "POST")} <= got
        assert app.state.forbidden_post_hits == 0 and app.state.post_hits == 0 and app.state.api_post_hits > 0
        report = json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))
        assert report["api_post_not_allowed"] == ["POST /api/delete-everything"]
        assert "POST /api/echo" in report["api_operations_tested"]
        # Without the allow list nothing is POSTed at all.
        before = app.state.api_post_hits
        DastScanner().scan(app.url, tmp_path / "r2.json", 120, api={
            "source": "api/openapi.yaml", "post_allowed": [], "project": tmp_path, "roots": []})
        assert app.state.api_post_hits == before and app.state.forbidden_post_hits == 0
    finally:
        app.stop()


def test_missing_api_description_fails_the_web_scan(tmp_path: Path) -> None:
    app = LabWebApp("clean").start()
    try:
        ex = DastScanner().scan(app.url, tmp_path / "r.json", 60, api={"source": "/openapi.json", "post_allowed": [],
                                                                       "project": tmp_path, "roots": []})
        assert ex.status == "FAILED" and "API description not found" in ex.error_message
    finally:
        app.stop()


def test_config_rules() -> None:
    base = {"repository": "x", "url": "http://127.0.0.1:5000/"}
    c = AppConfig.model_validate({"dast": {"targets": [{**base, "openapi": "api/openapi.yaml",
                                                        "api_post_allowed": ["/api/predict", " /api/predict "]}]}})
    assert c.dast.targets[0].api_post_allowed == ["/api/predict"]
    with pytest.raises(Exception, match="start"):
        AppConfig.model_validate({"dast": {"targets": [{**base, "api_post_allowed": ["api/predict"]}]}})
    with pytest.raises(Exception, match="this computer"):
        AppConfig.model_validate({"dast": {"targets": [{**base, "openapi": "http://example.com/openapi.json"}]}})


def test_explanations_exist_for_api_checks() -> None:
    from services.explain import explain

    for rule in ("DAST-API-AUTH", "DAST-API-DOCS"):
        e = explain({"category": "WEB", "rule_id": rule, "severity": "HIGH", "file_path": "/api/x"})
        assert e.topic.startswith("api_") and len(e.fix) >= 2
