"""Repository discovery: normal, nested, worktree, exclusions, missing roots, inaccessible dirs, links."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from conftest import git, make_repo
from database import repositories as dao
from database.db import init_db
from engine.repository_discovery import discover_repositories, git_marker

EXCL = ["node_modules", ".venv", "reports", "logs"]


def names(result) -> set[str]:
    return {r.name for r in result.repositories}


def test_normal_repository_with_metadata(roots: Path) -> None:
    make_repo(roots / "Phoenix")
    res = discover_repositories([str(roots)], EXCL)
    assert names(res) == {"Phoenix"}
    repo = res.repositories[0]
    assert repo.kind == "repository"
    assert repo.current_branch == "main"
    assert repo.current_commit and len(repo.current_commit) == 40


def test_multiple_and_nested_repositories(roots: Path) -> None:
    make_repo(roots / "Phoenix")
    make_repo(roots / "Group" / "Website")
    make_repo(roots / "Phoenix" / "vendor" / "inner")  # nested, not a submodule
    res = discover_repositories([str(roots)], EXCL)
    assert names(res) == {"Phoenix", "Website", "inner"}


def test_worktree_gitfile_detected(roots: Path) -> None:
    main = make_repo(roots / "Main")
    wt = roots / "Main-wt"
    git(main, "worktree", "add", "-q", str(wt), "-b", "feature")
    assert (wt / ".git").is_file()
    res = discover_repositories([str(roots)], EXCL)
    kinds = {r.name: r.kind for r in res.repositories}
    assert kinds["Main"] == "repository"
    assert kinds["Main-wt"] == "worktree_or_submodule"


def test_invalid_gitfile_ignored(roots: Path) -> None:
    d = roots / "notarepo"
    d.mkdir()
    (d / ".git").write_text("garbage", encoding="utf-8")
    assert git_marker(d) is None
    assert discover_repositories([str(roots)], EXCL).repositories == []


def test_excluded_directories_not_traversed(roots: Path) -> None:
    make_repo(roots / "App")
    make_repo(roots / "App" / "node_modules" / "pkg")
    make_repo(roots / "reports" / "x")
    make_repo(roots / "App" / "NODE_MODULES_CASE" / "ok")
    res = discover_repositories([str(roots)], EXCL)
    assert names(res) == {"App", "ok"}


def test_protected_app_dirs_skipped(roots: Path) -> None:
    make_repo(roots / "data_area" / "repo")
    res = discover_repositories([str(roots)], EXCL, protected_dirs=[roots / "data_area"])
    assert res.repositories == []


def test_missing_root_reported(tmp_path: Path, roots: Path) -> None:
    make_repo(roots / "A")
    res = discover_repositories([str(tmp_path / "nope"), str(roots)], EXCL)
    assert names(res) == {"A"}
    assert res.missing_roots == [str(tmp_path / "nope")]
    assert res.errors


def test_duplicate_roots_do_not_duplicate_repos(roots: Path) -> None:
    make_repo(roots / "A")
    res = discover_repositories([str(roots), str(roots).upper(), str(roots / "A")], EXCL)
    assert len(res.repositories) == 1


def test_inaccessible_directory_handled(roots: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    make_repo(roots / "A")
    locked = roots / "locked"
    locked.mkdir()
    real_scandir = os.scandir

    def fake_scandir(path):
        if Path(path) == locked:
            raise PermissionError(13, "Access is denied")
        return real_scandir(path)

    monkeypatch.setattr("engine.repository_discovery.os.scandir", fake_scandir)
    res = discover_repositories([str(roots)], EXCL)
    assert names(res) == {"A"}
    assert any("Permission denied" in e for e in res.errors)


def test_junction_not_followed(tmp_path: Path, roots: Path) -> None:
    outside = tmp_path / "outside"
    make_repo(outside / "Secret")
    link = roots / "link"
    if os.name == "nt":
        r = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(outside)], capture_output=True)
        if r.returncode != 0:
            pytest.skip("Could not create junction")
    else:
        link.symlink_to(outside, target_is_directory=True)
    res = discover_repositories([str(roots)], EXCL)
    assert "Secret" not in names(res)
    assert res.skipped_links == 1


def test_max_depth(roots: Path) -> None:
    make_repo(roots / "a" / "b" / "c" / "deep")
    assert discover_repositories([str(roots)], EXCL, max_depth=2).repositories == []
    assert names(discover_repositories([str(roots)], EXCL, max_depth=4)) == {"deep"}


def test_sync_records_moves_and_deletions(tmp_path: Path, roots: Path) -> None:
    conn = init_db(tmp_path / "db.sqlite")
    a = make_repo(roots / "A")
    make_repo(roots / "B")
    res = discover_repositories([str(roots)], EXCL)
    stats = dao.sync_discovered(conn, res.repositories, [str(roots)])
    assert stats["new"] == 2
    original_id = dao.find_repositories(conn, name="A")[0]["id"]

    # Move A, delete B
    (roots / "moved").mkdir()
    a.rename(roots / "moved" / "A")
    shutil.rmtree(roots / "B", onexc=lambda f, p, e: (os.chmod(p, 0o777), f(p)))
    res = discover_repositories([str(roots)], EXCL)
    stats = dao.sync_discovered(conn, res.repositories, [str(roots)])
    assert stats["moved"] == 1
    assert stats["deactivated"] == 1
    moved = dao.find_repositories(conn, name="A")[0]
    assert moved["id"] == original_id and moved["path"].endswith(os.path.join("moved", "A"))
    assert dao.find_repositories(conn, name="B") == []


def test_sync_deactivates_repos_outside_configured_roots(tmp_path: Path) -> None:
    conn = init_db(tmp_path / "db.sqlite")
    keep_root, drop_root = tmp_path / "keep", tmp_path / "drop"
    make_repo(keep_root / "K")
    make_repo(drop_root / "D")
    res = discover_repositories([str(keep_root), str(drop_root)], EXCL)
    dao.sync_discovered(conn, res.repositories, [str(keep_root), str(drop_root)])
    assert {r["name"] for r in dao.list_repositories(conn)} == {"K", "D"}

    # The "drop" root is removed from the config: D is still on disk but no longer monitored.
    res = discover_repositories([str(keep_root)], EXCL)
    stats = dao.sync_discovered(conn, res.repositories, [str(keep_root)], configured_roots=[str(keep_root)])
    assert stats["deactivated"] == 1
    assert {r["name"] for r in dao.list_repositories(conn)} == {"K"}
    assert len(dao.list_repositories(conn, active_only=False)) == 2  # history kept

    # A configured root that is temporarily missing keeps its repositories active.
    res = discover_repositories([str(keep_root), str(drop_root)], EXCL)
    dao.sync_discovered(conn, res.repositories, [str(keep_root), str(drop_root)],
                        configured_roots=[str(keep_root), str(drop_root)])
    assert {r["name"] for r in dao.list_repositories(conn)} == {"K", "D"}  # re-activated
    missing = str(tmp_path / "unplugged")
    stats = dao.sync_discovered(conn, res.repositories, [str(keep_root), str(drop_root)],
                                configured_roots=[str(keep_root), str(drop_root), missing])
    assert stats["deactivated"] == 0


def test_roots_changed_detects_hand_edited_config(tmp_path: Path, roots: Path) -> None:
    from engine.scan_orchestrator import roots_changed

    conn = init_db(tmp_path / "db.sqlite")
    assert not roots_changed(conn, [str(roots)])  # nothing recorded yet -> no automatic discovery
    from database.db import set_setting
    from engine.scan_orchestrator import DISCOVERY_ROOTS_KEY, roots_signature

    set_setting(conn, DISCOVERY_ROOTS_KEY, roots_signature([str(roots)]))
    assert not roots_changed(conn, [str(roots).upper()])  # case-insensitive on Windows paths
    assert roots_changed(conn, [str(roots), str(tmp_path / "new")])
