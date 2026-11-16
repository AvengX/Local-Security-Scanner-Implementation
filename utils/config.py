"""Application configuration (YAML on disk, validated with Pydantic)."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from utils import validators as v
from utils.paths import EXAMPLE_CONFIG_PATH, config_path, resolve_app_path

DEFAULT_EXCLUDES: list[str] = [
    "node_modules", ".venv", "venv", "dist", "build", ".next", ".nuxt", "__pycache__",
    ".idea", ".vscode", "coverage", "reports", "logs",
]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class PathsConfig(_Strict):
    data_dir: str = "data"
    reports_dir: str = "reports"
    logs_dir: str = "logs"


class ScanConfig(_Strict):
    timeout_seconds: int = Field(1800, ge=30, le=86400)
    concurrency: int = Field(1, ge=1, le=8)
    severities: list[str] = Field(default_factory=lambda: list(v.SEVERITIES))
    offline: bool = False
    db_freshness_hours: int = Field(72, ge=1, le=24 * 90)
    retention_days: int = Field(0, ge=0, le=3650, description="0 keeps history forever")

    @field_validator("severities")
    @classmethod
    def _sev(cls, value: list[str]) -> list[str]:
        return v.validate_severities(value)


class TrivyConfig(_Strict):
    enabled: bool = True
    executable: str | None = None
    cache_dir: str | None = None
    scan_types: list[str] = Field(default_factory=lambda: ["fs"])
    scanners: list[str] = Field(default_factory=lambda: ["vuln", "misconfig", "secret"])
    skip_dirs: list[str] = Field(default_factory=list)
    generate_sbom: bool = False
    images: dict[str, list[str]] = Field(default_factory=dict, description="repo name -> image refs")

    @field_validator("scan_types")
    @classmethod
    def _types(cls, value: list[str]) -> list[str]:
        bad = [t for t in value if t not in v.TRIVY_SCAN_TYPES]
        if bad:
            raise ValueError(f"Unknown Trivy scan types {bad}; allowed {list(v.TRIVY_SCAN_TYPES)}")
        return list(dict.fromkeys(value))

    @field_validator("scanners")
    @classmethod
    def _scanners(cls, value: list[str]) -> list[str]:
        bad = [s for s in value if s not in v.TRIVY_SCANNERS]
        if bad or not value:
            raise ValueError(f"Trivy scanners must be a non-empty subset of {list(v.TRIVY_SCANNERS)}")
        return list(dict.fromkeys(value))

    @field_validator("images")
    @classmethod
    def _images(cls, value: dict[str, list[str]]) -> dict[str, list[str]]:
        from utils.security import is_safe_image_ref

        for repo, refs in value.items():
            v.validate_repo_name(repo)
            for ref in refs:
                if not is_safe_image_ref(ref):
                    raise ValueError(f"Invalid image reference: {ref!r}")
        return value


class GitleaksConfig(_Strict):
    enabled: bool = True
    executable: str | None = None
    modes: list[str] = Field(default_factory=lambda: ["git", "dir"])
    config_path: str | None = None
    log_opts: str | None = Field(None, description="Extra git log options, e.g. --all")
    max_target_megabytes: int | None = Field(None, ge=1, le=10_000)

    @field_validator("modes")
    @classmethod
    def _modes(cls, value: list[str]) -> list[str]:
        bad = [m for m in value if m not in v.GITLEAKS_MODES]
        if bad or not value:
            raise ValueError(f"Gitleaks modes must be a non-empty subset of {list(v.GITLEAKS_MODES)}")
        return list(dict.fromkeys(value))

    @field_validator("config_path")
    @classmethod
    def _cfg(cls, value: str | None) -> str | None:
        if value and not Path(value).is_file():
            raise ValueError(f"Gitleaks config file not found: {value}")
        return value or None


class DashboardConfig(_Strict):
    host: str = "127.0.0.1"
    port: int = Field(8501, ge=1024, le=65535)

    @field_validator("host")
    @classmethod
    def _host(cls, value: str) -> str:
        return v.validate_loopback_host(value)


class ScheduleConfig(_Strict):
    time: str = "02:00"
    weekly_day: Literal["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"] = "SUN"

    @field_validator("time")
    @classmethod
    def _time(cls, value: str) -> str:
        return v.validate_schedule_time(value)


class AppConfig(_Strict):
    repository_roots: list[str] = Field(default_factory=list)
    excluded_dirs: list[str] = Field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    max_depth: int = Field(10, ge=1, le=64)
    follow_symlinks: bool = False
    capture_git_metadata: bool = True
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    paths: PathsConfig = Field(default_factory=PathsConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)
    trivy: TrivyConfig = Field(default_factory=TrivyConfig)
    gitleaks: GitleaksConfig = Field(default_factory=GitleaksConfig)
    dashboard: DashboardConfig = Field(default_factory=DashboardConfig)
    schedule: ScheduleConfig = Field(default_factory=ScheduleConfig)

    @field_validator("repository_roots")
    @classmethod
    def _roots(cls, value: list[str]) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for root in value:
            r = v.validate_root(root)
            if r.lower() not in seen:
                seen.add(r.lower())
                out.append(r)
        return out

    @field_validator("excluded_dirs")
    @classmethod
    def _excl(cls, value: list[str]) -> list[str]:
        return list(dict.fromkeys(v.validate_dir_name(x) for x in value))

    # Resolved locations -------------------------------------------------
    @property
    def data_dir(self) -> Path:
        return resolve_app_path(self.paths.data_dir)

    @property
    def reports_dir(self) -> Path:
        return resolve_app_path(self.paths.reports_dir)

    @property
    def logs_dir(self) -> Path:
        return resolve_app_path(self.paths.logs_dir)

    @property
    def db_path(self) -> Path:
        return self.data_dir / "security_scanner.db"

    def app_dirs(self) -> list[Path]:
        return [self.data_dir, self.reports_dir, self.logs_dir]

    def ensure_dirs(self) -> None:
        for d in self.app_dirs():
            d.mkdir(parents=True, exist_ok=True)


def load_config(path: Path | None = None) -> AppConfig:
    """Load and validate configuration. Falls back to the example file, then to defaults."""
    target = path or config_path()
    source = target if target.exists() else (EXAMPLE_CONFIG_PATH if path is None else None)
    data: dict = {}
    if source and source.exists():
        data = yaml.safe_load(source.read_text(encoding="utf-8")) or {}
    return AppConfig.model_validate(data)


def save_config(cfg: AppConfig, path: Path | None = None) -> Path:
    """Validate and write configuration atomically (temp file + replace)."""
    target = path or config_path()
    AppConfig.model_validate(cfg.model_dump())
    text = "# Local Security Scanner configuration (edited via dashboard or by hand)\n" + yaml.safe_dump(
        cfg.model_dump(), sort_keys=False, allow_unicode=True
    )
    tmp = target.with_suffix(".yaml.tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(target)
    return target
