"""Application configuration (YAML on disk, validated with Pydantic)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from utils import validators as v
from utils.paths import EXAMPLE_CONFIG_PATH, config_path, resolve_app_path

DEFAULT_EXCLUDES: list[str] = [
    "node_modules", ".venv", "venv", "dist", "build", ".next", ".nuxt", "__pycache__",
    ".idea", ".vscode", "coverage", "reports", "logs",
]
# Folders skipped INSIDE repositories while scanning (installed dependencies and caches). These can hold
# tens of thousands of third-party files and make scans take a very long time. Dependencies are still
# assessed from manifests/lockfiles (requirements.txt, package-lock.json, poetry.lock, ...).
DEFAULT_SCAN_SKIP_DIRS: list[str] = [
    ".venv", "venv", "node_modules", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True, hide_input_in_errors=True)  # never echo a mistyped secret


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
    skip_dirs: list[str] = Field(default_factory=lambda: list(DEFAULT_SCAN_SKIP_DIRS),
                                 description="Folder names skipped inside repositories by Trivy, Gitleaks and Bandit")

    @field_validator("skip_dirs")
    @classmethod
    def _skip(cls, value: list[str]) -> list[str]:
        return list(dict.fromkeys(v.validate_dir_name(x) for x in value))

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
    installed_versions: bool = Field(True, description="Also check the exact library versions installed in each "
                                                       "project's .venv / venv / node_modules (metadata only)")

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


class SastConfig(_Strict):
    """Static analysis of the project's own Python code with Bandit (installed with the scanner, runs offline)."""

    enabled: bool = True
    skip_tests: list[str] = Field(default_factory=list,
                                  description="Bandit check IDs to skip everywhere, e.g. ['B101'] for assert")
    other_languages: bool = Field(True, description="Also run the built-in code scan for JavaScript/TypeScript, "
                                                    "HTML templates, PHP, Java, Go and C#")

    @field_validator("skip_tests")
    @classmethod
    def _tests(cls, value: list[str]) -> list[str]:
        cleaned = [x.strip().upper() for x in value if x and x.strip()]
        bad = [x for x in cleaned if not re.fullmatch(r"B\d{3}", x)]
        if bad:
            raise ValueError(f"Bandit check IDs look like B101; invalid: {bad}")
        return list(dict.fromkeys(cleaned))


class DastLogin(_Strict):
    """Optional login so the web scan can also test pages behind a sign-in form.

    Only the NAME of an environment variable holding the password is stored, never the password itself.
    Use a test account: the scan sends one POST (the login form) and otherwise only GET requests."""

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)  # a mistyped password is never echoed

    url: str = Field(description="Address of the login page, on the same app, e.g. http://127.0.0.1:5000/login")
    username: str = Field(description="Test account user name or e-mail")
    password_env: str = Field(description="Name of the environment variable that holds the test password")
    username_field: str = Field("", description="Name of the user-name input; empty = detect automatically")
    password_field: str = Field("", description="Name of the password input; empty = detect automatically")
    logged_in_text: str = Field("", description="Text that only appears when logged in (optional check)")

    @field_validator("url")
    @classmethod
    def _url(cls, value: str) -> str:
        return v.validate_dast_url(value)

    @field_validator("username")
    @classmethod
    def _user(cls, value: str) -> str:
        value = value.strip()
        if not value or len(value) > 200:
            raise ValueError("Login user name is required (max 200 characters)")
        return value

    @field_validator("password_env")
    @classmethod
    def _env(cls, value: str) -> str:
        value = value.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", value):
            raise ValueError("password_env must be an environment variable NAME such as LSS_APP_PASSWORD "
                             "(letters, digits, underscore) - never the password itself")
        return value

    @field_validator("username_field", "password_field")
    @classmethod
    def _field(cls, value: str) -> str:
        value = value.strip()
        if value and not re.fullmatch(r"[\w.\[\]-]{1,100}", value):
            raise ValueError(f"Invalid form field name: {value!r}")
        return value


class DastTarget(_Strict):
    repository: str = Field(description="Name of the project that serves this web app")
    url: str = Field(description="Address of the running app, e.g. http://127.0.0.1:5000/")
    login: DastLogin | None = Field(None, description="Optional test-account login for pages behind sign-in")
    start_command: str = Field("", description="Optional command that starts the app when it is not running, "
                                               "e.g. 'python app.py'; the scanner stops it again afterwards")
    start_dir: str = Field("", description="Folder inside the project to run the start command in (default: "
                                           "the project folder)")
    start_wait: int = Field(60, ge=5, le=600, description="Seconds to wait for the app to answer after starting")
    openapi: str = Field("", description="Optional OpenAPI/Swagger description of the app's API: a file (absolute, or "
                                         "relative to the project or the scanner folder) or a path on the app such "
                                         "as /openapi.json")
    api_post_allowed: list[str] = Field(default_factory=list,
                                        description="API paths that may receive POST test requests because they "
                                                    "only calculate and store nothing, e.g. ['/api/predict']")

    @field_validator("openapi")
    @classmethod
    def _openapi(cls, value: str) -> str:
        value = value.strip()
        if value.startswith(("http://", "https://")):
            return v.validate_dast_url(value)
        if len(value) > 500 or "\n" in value:
            raise ValueError("openapi must be a file path or a path such as /openapi.json")
        return value

    @field_validator("api_post_allowed")
    @classmethod
    def _post(cls, value: list[str]) -> list[str]:
        out = []
        for p in value:
            p = p.strip()
            if not p:
                continue
            if not p.startswith("/") or re.search(r"\s", p) or len(p) > 300:
                raise ValueError(f"POST-allowed entries are API paths starting with /, e.g. /api/predict (got {p!r})")
            out.append(p)
        return list(dict.fromkeys(out))

    @field_validator("start_command")
    @classmethod
    def _cmd(cls, value: str) -> str:
        value = value.strip()
        if len(value) > 500 or "\n" in value or "\r" in value:
            raise ValueError("Start command must be one line (max 500 characters)")
        if re.search(r"[|&;<>`]|\$\(", value):
            raise ValueError("Start command must be one program with arguments (no |, &, ;, <, > or backticks); "
                             "put anything more complex in a script and start that")
        return value

    @field_validator("start_dir")
    @classmethod
    def _dir(cls, value: str) -> str:
        value = value.strip().replace("\\", "/").strip("/")
        if value and (value.startswith(("/", "~")) or ":" in value or ".." in value.split("/")):
            raise ValueError("start_dir must be a folder inside the project, e.g. landing-page")
        return value

    @model_validator(mode="after")
    def _same_app(self) -> "DastTarget":
        if self.login is not None:
            a, b = urlsplit(self.url), urlsplit(self.login.url)
            if (a.scheme, a.netloc) != (b.scheme, b.netloc):
                raise ValueError(f"The login page must be on the same app as {self.url} "
                                 f"(same http/https, host and port)")
        return self

    @field_validator("repository")
    @classmethod
    def _repo(cls, value: str) -> str:
        return v.validate_repo_name(value.strip())

    @field_validator("url")
    @classmethod
    def _url(cls, value: str) -> str:
        return v.validate_dast_url(value)


class DastConfig(_Strict):
    """Built-in dynamic scan (DAST) of the user's own running web apps. Loopback addresses only."""

    enabled: bool = True
    targets: list[DastTarget] = Field(default_factory=list)
    max_pages: int = Field(30, ge=1, le=500, description="Pages followed per address")
    max_requests: int = Field(400, ge=20, le=5000, description="Requests sent per address")
    request_timeout: int = Field(10, ge=1, le=120, description="Seconds to wait for one response")

    @field_validator("targets")
    @classmethod
    def _targets(cls, value: list[DastTarget]) -> list[DastTarget]:
        seen: set[tuple[str, str]] = set()
        out = []
        for t in value:
            key = (t.repository.lower(), t.url)
            if key not in seen:
                seen.add(key)
                out.append(t)
        return out

    def targets_for(self, repository: str) -> list[str]:
        return [t.url for t in self.targets if t.repository == repository]

    def login_for(self, repository: str, url: str) -> DastLogin | None:
        return next((t.login for t in self.targets if t.repository == repository and t.url == url), None)

    def target_for(self, repository: str, url: str) -> "DastTarget | None":
        return next((t for t in self.targets if t.repository == repository and t.url == url), None)


class AlertsConfig(_Strict):
    """Tell someone when a scan finds NEW serious problems (also scheduled scans nobody is watching)."""

    enabled: bool = True
    min_severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = Field(
        "HIGH", description="Alert on new findings of this severity or worse")
    windows_notification: bool = Field(True, description="Show a Windows notification")
    webhook_url: str = Field("", description="Optional https webhook (Teams / Slack / ntfy ...) that receives a short "
                                             "summary: counts, project names, check names - never secret values")

    @field_validator("webhook_url")
    @classmethod
    def _hook(cls, value: str) -> str:
        value = value.strip()
        if value and not re.fullmatch(r"https://[^\s/$.?#][^\s]*", value):
            raise ValueError("The webhook address must start with https://")
        return value


class ReportConfig(_Strict):
    """Branding of the VAPT report (PDF). Keep company logos in git-ignored folders such as the data folder."""

    logo_path: str = Field("", description="Logo shown at the top of every report page (.svg, .png or .jpg). "
                                           "Relative paths are relative to the scanner folder.")
    organisation: str = Field("", max_length=80, description="Name shown next to the logo (optional)")

    @field_validator("logo_path")
    @classmethod
    def _logo(cls, value: str) -> str:
        value = value.strip().strip('"')
        if value and not re.search(r"(?i)\.(svg|png|jpe?g)$", value):
            raise ValueError("The report logo must be an .svg, .png or .jpg file")
        return value

    def logo_file(self) -> "Path | None":
        if not self.logo_path:
            return None
        p = resolve_app_path(self.logo_path)
        return p if p.is_file() else None


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
    sast: SastConfig = Field(default_factory=SastConfig)
    dast: DastConfig = Field(default_factory=DastConfig)
    alerts: AlertsConfig = Field(default_factory=AlertsConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)
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
