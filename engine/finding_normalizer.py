"""Common internal finding model, stable fingerprints and scan-coverage descriptors."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field

from utils.paths import to_posix_rel
from utils.security import redact, sha256_hex
from utils.validators import CATEGORIES, SEVERITIES

SECRET_REMEDIATION = (
    "Treat this credential as compromised if it is real: revoke and rotate it with the issuing provider, "
    "then remove it from the code (and from Git history if needed, after rotation). If it is a confirmed "
    "false positive or test fixture, add a Gitleaks allowlist / .gitleaksignore entry. The scanner never "
    "modifies code or revokes credentials automatically."
)


def normalize_severity(value: str | None) -> str:
    s = (value or "").strip().upper()
    return s if s in SEVERITIES else "UNKNOWN"


def normalize_category(value: str | None) -> str:
    c = (value or "").strip().upper()
    return c if c in CATEGORIES else "OTHER"


def _clip(text: str | None, limit: int) -> str | None:
    if text is None:
        return None
    text = redact(str(text)).strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


@dataclass
class NormalizedFinding:
    scanner: str
    scan_type: str
    category: str
    severity: str
    scan_target: str = "."
    vulnerability_id: str | None = None
    rule_id: str | None = None
    package_name: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    file_path: str | None = None
    line: int | None = None
    title: str | None = None
    description: str | None = None
    remediation: str | None = None
    reference_url: str | None = None
    metadata: dict[str, object] = field(default_factory=dict)
    identity: tuple[object, ...] = ()  # fields defining "the same finding" across scans
    fingerprint: str = ""
    dedup_key: str = ""

    def __post_init__(self) -> None:
        self.severity = normalize_severity(self.severity)
        self.category = normalize_category(self.category)
        self.file_path = to_posix_rel(self.file_path) if self.file_path else None
        self.title = _clip(self.title, 500)
        self.description = _clip(self.description, 4000)
        self.remediation = _clip(self.remediation, 2000)
        if not self.fingerprint:
            ident = self.identity or (self.vulnerability_id, self.rule_id, self.package_name,
                                      self.installed_version, self.file_path, self.line)
            self.fingerprint = sha256_hex(self.scanner, self.scan_type, self.scan_target, self.category, *ident)
        if not self.dedup_key:
            self.dedup_key = self._default_dedup_key()

    def _default_dedup_key(self) -> str:
        if self.category == "SECRET":
            return sha256_hex("SECRET", self.scan_target, self.file_path, self.line,
                              self.metadata.get("commit") or "")
        if self.category == "VULNERABILITY":
            return sha256_hex("VULN", self.scan_target, self.vulnerability_id, self.package_name,
                              self.installed_version, self.file_path)
        if self.category == "MISCONFIGURATION":
            return sha256_hex("MISCONF", self.scan_target, self.rule_id, self.file_path, self.line)
        return self.fingerprint

    def metadata_json(self) -> str:
        return json.dumps(self.metadata, sort_keys=True, default=str)

    def to_dict(self) -> dict[str, object]:
        d = asdict(self)
        d.pop("identity", None)
        return d


@dataclass(frozen=True)
class Coverage:
    """What a successful scan actually inspected. Only covered findings may be resolved by it."""

    scanner: str
    scan_type: str
    scan_target: str
    categories: frozenset[str]
    severities: frozenset[str]
    skip_dirs: frozenset[str] = frozenset()  # folder names the scan did not look inside

    def key(self) -> str:
        parts = [self.scanner, self.scan_type, self.scan_target,
                 ",".join(sorted(self.categories)), ",".join(sorted(self.severities))]
        if self.skip_dirs:
            parts.append(",".join(sorted(self.skip_dirs)))
        return "|".join(parts)

    @classmethod
    def from_key(cls, key: str) -> "Coverage":
        scanner, scan_type, target, cats, sevs, *rest = key.split("|", 5)
        split = lambda v: frozenset(filter(None, v.split(",")))  # noqa: E731
        return cls(scanner, scan_type, target, split(cats), split(sevs), split(rest[0]) if rest else frozenset())

    def covers(self, scanner: str, scan_type: str, scan_target: str, category: str, severity: str,
               file_path: str | None = None) -> bool:
        if not (scanner == self.scanner and scan_type == self.scan_type and scan_target == self.scan_target
                and category in self.categories and severity in self.severities):
            return False
        if file_path and self.skip_dirs:
            segments = set(file_path.replace("\\", "/").split("/")[:-1])
            if segments & self.skip_dirs:
                return False  # the scan did not look inside this folder, so it cannot confirm a fix
        return True


def deduplicate(findings: list[NormalizedFinding]) -> list[NormalizedFinding]:
    """Collapse identical findings (same fingerprint) produced within one report, keeping the worst severity."""
    order = {s: i for i, s in enumerate(SEVERITIES)}
    by_fp: dict[str, NormalizedFinding] = {}
    for f in findings:
        existing = by_fp.get(f.fingerprint)
        if existing is None or order[f.severity] < order[existing.severity]:
            by_fp[f.fingerprint] = f
    return list(by_fp.values())
