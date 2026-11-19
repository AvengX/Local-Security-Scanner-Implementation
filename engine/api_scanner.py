"""API testing for the web scan, driven by an OpenAPI (3.x) or Swagger (2.0) description.

The normal web scan follows links; APIs have none, so their endpoints were never tested. Given the app's API
description (a file in the project, or a path on the running app such as /openapi.json), every documented
operation is called with sensible example values and checked for:
* SQL errors, reflected script (when the answer is HTML) and path traversal through query and JSON fields;
* error details leaking (stack traces) when given input of the wrong type;
* endpoints documented as needing authentication that answer without it;
(and, for every app, a publicly reachable Swagger UI / API description is reported by the main scan).

Safety: GET requests by default. POST is sent only to the paths the user listed in ``api_post_allowed`` (endpoints
that only calculate and store nothing); PUT, PATCH and DELETE are never sent. Requests go through the same
loopback-only client with the same request budget, deadline and cancellation. Response bodies are never stored.
"""

from __future__ import annotations

import json
import re
import secrets
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode, urlsplit

import yaml

MAX_SPEC_BYTES = 2_000_000
MAX_OPERATIONS = 150
MAX_FIELDS = 12
SAFE_METHODS = ("get",)


class SpecError(ValueError):
    pass


def parse_spec(text: str) -> dict[str, Any]:
    try:
        data = json.loads(text)
    except ValueError:
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise SpecError(f"The API description is neither valid JSON nor YAML: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("paths"), dict):
        raise SpecError("The API description has no 'paths' section (is it an OpenAPI / Swagger file?)")
    if not (str(data.get("openapi", "")).startswith("3") or str(data.get("swagger", "")).startswith("2")):
        raise SpecError("Only OpenAPI 3.x and Swagger 2.0 descriptions are supported")
    return data


def read_spec_file(source: str, project: Path | None, extra_roots: list[Path]) -> tuple[str, Path]:
    """Read a local spec file: absolute path, or relative to the project folder, then to the extra roots."""
    p = Path(source).expanduser()
    candidates = [p] if p.is_absolute() else [r / p for r in ([project] if project else []) + extra_roots]
    for c in candidates:
        if c.is_file():
            if c.stat().st_size > MAX_SPEC_BYTES:
                raise SpecError(f"The API description {c} is larger than 2 MB")
            return c.read_text(encoding="utf-8", errors="replace"), c
    raise SpecError(f"API description not found: {source}")


def _resolve(spec: dict[str, Any], node: Any, depth: int = 0) -> Any:
    """Follow local $ref pointers (#/components/schemas/X, #/definitions/X)."""
    while isinstance(node, dict) and "$ref" in node and depth < 20:
        ref = str(node["$ref"])
        if not ref.startswith("#/"):
            return {}
        cur: Any = spec
        for part in ref[2:].split("/"):
            cur = cur.get(part.replace("~1", "/").replace("~0", "~"), {}) if isinstance(cur, dict) else {}
        node, depth = cur, depth + 1
    return node


def example(spec: dict[str, Any], schema: Any, depth: int = 0) -> Any:
    """A plausible value for a schema: example / default / first enum value, else a simple value by type."""
    schema = _resolve(spec, schema)
    if not isinstance(schema, dict) or depth > 4:
        return "test"
    for key in ("example", "default"):
        if key in schema:
            return schema[key]
    if schema.get("enum"):
        return schema["enum"][0]
    for combo in ("allOf", "oneOf", "anyOf"):
        if schema.get(combo):
            if combo == "allOf":
                merged: dict[str, Any] = {}
                for part in schema[combo]:
                    val = example(spec, part, depth + 1)
                    if isinstance(val, dict):
                        merged.update(val)
                return merged
            return example(spec, schema[combo][0], depth + 1)
    t = schema.get("type")
    if t == "integer":
        return int(schema.get("minimum", 1) or 1)
    if t == "number":
        return float(schema.get("minimum", 1.5) or 1.5)
    if t == "boolean":
        return True
    if t == "array":
        return [example(spec, schema.get("items", {}), depth + 1)]
    if t == "object" or "properties" in schema:
        props = schema.get("properties") or {}
        return {k: example(spec, v, depth + 1) for k, v in list(props.items())[:MAX_FIELDS]}
    fmt = schema.get("format")
    return {"email": "test@example.invalid", "date": "2026-01-01", "date-time": "2026-01-01T00:00:00Z",
            "uuid": "00000000-0000-4000-8000-000000000000"}.get(fmt, "test")


class Operation:
    def __init__(self, method: str, path: str, base: str, params: list[dict], body: Any, secured: bool,
                 body_schema: Any) -> None:
        self.method, self.path, self.base = method, path, base
        self.params, self.body, self.secured, self.body_schema = params, body, secured, body_schema

    @property
    def key(self) -> str:
        return f"{self.method.upper()} {self.path}"

    def url(self, origin: str, query: dict[str, Any] | None = None) -> str:
        path = self.path
        for p in self.params:
            if p["in"] == "path":
                path = path.replace("{" + p["name"] + "}", quote(str(p["value"]), safe=""))
        q = query if query is not None else {p["name"]: p["value"] for p in self.params if p["in"] == "query"}
        qs = urlencode({k: (json.dumps(v) if isinstance(v, (dict, list)) else v) for k, v in q.items()})
        return origin + self.base.rstrip("/") + path + (f"?{qs}" if qs else "")


def operations(spec: dict[str, Any]) -> list[Operation]:
    """GET and POST operations (others are never called), with example values filled in."""
    if str(spec.get("swagger", "")).startswith("2"):
        base = str(spec.get("basePath") or "")
    else:
        servers = spec.get("servers") or [{}]
        url = str((servers[0] or {}).get("url") or "") if isinstance(servers, list) else ""
        base = urlsplit(url).path if url else ""
    global_sec = bool(spec.get("security"))
    out: list[Operation] = []
    for path, item in (spec.get("paths") or {}).items():
        item = _resolve(spec, item)
        if not isinstance(item, dict) or not str(path).startswith("/"):
            continue
        shared = [_resolve(spec, p) for p in item.get("parameters") or []]
        for method in ("get", "post"):
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            params, body, body_schema = [], None, None
            for raw in shared + [_resolve(spec, p) for p in op.get("parameters") or []]:
                if not isinstance(raw, dict) or raw.get("in") not in ("query", "path", "body"):
                    continue
                if raw["in"] == "body":  # Swagger 2
                    body_schema = raw.get("schema")
                    body = example(spec, body_schema)
                    continue
                schema = raw.get("schema") if "schema" in raw else {k: raw[k] for k in ("type", "enum", "default",
                                                                                       "format") if k in raw}
                value = raw.get("example", example(spec, schema))
                params.append({"name": str(raw.get("name")), "in": raw["in"], "value": value,
                               "type": (_resolve(spec, schema) or {}).get("type", "string")})
            rb = _resolve(spec, op.get("requestBody") or {})
            content = rb.get("content") if isinstance(rb, dict) else None
            if isinstance(content, dict):
                media = content.get("application/json") or next(iter(content.values()), {})
                media = media if isinstance(media, dict) else {}
                body_schema = media.get("schema")
                body = media.get("example", example(spec, body_schema))
            secured = bool(op["security"]) if "security" in op else global_sec
            out.append(Operation(method, str(path), base, params, body, secured, body_schema))
            if len(out) >= MAX_OPERATIONS:
                return out
    return out


def marker() -> str:
    return "lss" + secrets.token_hex(4)


def string_fields(body: Any, prefix: str = "") -> list[str]:
    """Dotted names of string fields in an example JSON body (top level and one level down)."""
    out: list[str] = []
    if isinstance(body, dict):
        for k, v in body.items():
            name = f"{prefix}{k}"
            if isinstance(v, str):
                out.append(name)
            elif isinstance(v, dict) and not prefix:
                out += string_fields(v, f"{name}.")
    return out[:MAX_FIELDS]


def numeric_fields(body: Any) -> list[str]:
    return [k for k, v in (body.items() if isinstance(body, dict) else []) if isinstance(v, (int, float))
            and not isinstance(v, bool)][:MAX_FIELDS]


def with_value(body: Any, dotted: str, value: Any) -> Any:
    data = json.loads(json.dumps(body))
    cur = data
    parts = dotted.split(".")
    for p in parts[:-1]:
        cur = cur[p]
    cur[parts[-1]] = value
    return data


DOC_PATHS = [("/openapi.json", lambda b: re.search(rb'"(openapi|swagger)"\s*:', b) is not None),
             ("/swagger.json", lambda b: re.search(rb'"(openapi|swagger)"\s*:', b) is not None),
             ("/v3/api-docs", lambda b: re.search(rb'"(openapi|swagger)"\s*:', b) is not None),
             ("/docs", lambda b: b"swagger-ui" in b.lower() or b"redoc" in b.lower()),
             ("/swagger-ui.html", lambda b: b"swagger-ui" in b.lower()),
             ("/swagger-ui/", lambda b: b"swagger-ui" in b.lower()),
             ("/api-docs", lambda b: b"swagger" in b.lower() or b"openapi" in b.lower())]
