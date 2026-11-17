"""'What was checked' coverage: explains empty Vulnerabilities / Misconfigurations pages."""

from __future__ import annotations

from pathlib import Path

from services.coverage_service import inspect_repository, parse_requirements


def test_parse_requirements_counts_exact_pins_only() -> None:
    total, pinned, unpinned = parse_requirements(
        "# comment\nflask==3.1.3\nnumpy>=1.24\npandas\nrequests==2.*\n-r other.txt\n"
        "git+https://github.com/x/models\nurllib3==1.26.4 ; python_version>'3'\n")
    assert (total, pinned) == (6, 2)
    assert "numpy>=1.24" in unpinned and "pandas" in unpinned and "requests==2.*" in unpinned


def test_inspect_repository(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("streamlit\nnumpy\n", encoding="utf-8")
    (tmp_path / "requirements-train.txt").write_text("pandas==2.0.0\n", encoding="utf-8")
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\n", encoding="utf-8")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "requirements.txt").write_text("x==1\n", encoding="utf-8")
    cov = inspect_repository("demo", str(tmp_path), [".venv"])
    by = {d.path: d for d in cov.dependency_files}
    assert set(by) == {"requirements.txt", "requirements-train.txt", "web/package.json"}  # .venv skipped
    assert not by["requirements.txt"].checkable and by["requirements.txt"].total == 2
    assert not by["requirements-train.txt"].checkable                # Trivy reads only 'requirements.txt'
    assert not by["web/package.json"].checkable and "lockfile" in by["web/package.json"].note
    assert cov.config_files == [("Dockerfile", "Dockerfile")]
