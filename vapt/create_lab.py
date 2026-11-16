"""Create a disposable VAPT test lab: Git repositories with KNOWN, intentionally planted weaknesses.

Everything here is a harmless static fixture used to prove the scanner detects what it should:
* outdated dependencies with published CVEs (never installed or executed),
* insecure Dockerfile / Kubernetes / Terraform configuration (never deployed),
* randomly generated fake credentials (syntactically valid, belong to no account),
* a clean repository to check for false positives.

Fake tokens are generated fresh on every run and written to ``lab_secrets.json`` inside the lab so the
test can verify that no secret value ever reaches the database, reports or logs.
"""

from __future__ import annotations

import json
import secrets
import shutil
import stat
import string
import subprocess
from pathlib import Path

BANNER = ("INTENTIONALLY VULNERABLE TEST FIXTURE - created by Local Security Scanner VAPT test.\n"
          "Contains fake credentials and outdated dependencies on purpose. Never deploy or install.\n")


def _rand(alphabet: str, n: int) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


def fake_secrets() -> dict[str, str]:
    up = string.ascii_uppercase
    return {
        "aws_access_key_id": "AKIA" + _rand(up + "234567", 16),
        "aws_secret_access_key": _rand(string.ascii_letters + string.digits + "/+", 40),
        "github_pat_current": "ghp_" + _rand(string.ascii_letters + string.digits, 36),
        "github_pat_history": "ghp_" + _rand(string.ascii_letters + string.digits, 36),
    }


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "user.name=VAPT Lab", "-c", "user.email=vapt-lab@example.invalid",
                    "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main", "-c", "core.autocrlf=false",
                    *args], cwd=cwd, check=True, capture_output=True, text=True)


def _write(repo: Path, files: dict[str, str]) -> None:
    for rel, content in files.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8", newline="\n")


def _new_repo(root: Path, name: str, files: dict[str, str], message: str = "initial commit") -> Path:
    repo = root / name
    repo.mkdir(parents=True)
    _git(repo, "init", "-q")
    _write(repo, {"VAPT_FIXTURE_README.txt": BANNER, **files})
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message)
    return repo


def _rmtree(path: Path) -> None:
    def onexc(func, p, _exc):  # git object files are read-only on Windows
        Path(p).chmod(stat.S_IWRITE)
        func(p)

    if path.exists():
        shutil.rmtree(path, onexc=onexc)


NODE_LOCK = {
    "name": "vuln-node-app", "version": "1.0.0", "lockfileVersion": 3, "requires": True,
    "packages": {
        "": {"name": "vuln-node-app", "version": "1.0.0",
             "dependencies": {"lodash": "4.17.15", "minimist": "1.2.0"}},
        "node_modules/lodash": {"version": "4.17.15",
                                "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz"},
        "node_modules/minimist": {"version": "1.2.0",
                                  "resolved": "https://registry.npmjs.org/minimist/-/minimist-1.2.0.tgz"},
    },
}

DOCKERFILE = """FROM ubuntu:latest
ADD https://example.invalid/tool.tar.gz /opt/tool.tar.gz
RUN apt-get update && apt-get install -y curl
EXPOSE 22
CMD ["/bin/bash"]
"""

K8S = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: insecure-app
spec:
  replicas: 1
  selector:
    matchLabels: {app: insecure-app}
  template:
    metadata:
      labels: {app: insecure-app}
    spec:
      hostNetwork: true
      containers:
        - name: app
          image: nginx:latest
          securityContext:
            privileged: true
            runAsUser: 0
            allowPrivilegeEscalation: true
"""

TERRAFORM = """resource "aws_s3_bucket" "data" {
  bucket = "vapt-lab-insecure-bucket"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_security_group" "ssh_open" {
  name        = "ssh-open"
  description = "SSH open to the world"
  ingress {
    description = "ssh"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""


def create_lab(lab_dir: Path) -> dict[str, object]:
    """(Re)create the lab. Returns metadata including the generated fake secrets."""
    targets = lab_dir / "targets"
    _rmtree(targets)
    targets.mkdir(parents=True)
    s = fake_secrets()

    # 1. Python app: CVEs in pinned deps + secret in working tree + secret only in Git history.
    py = _new_repo(targets, "vuln-python-app", {
        "requirements.txt": "requests==2.25.0\nurllib3==1.26.4\nPyYAML==5.3\nJinja2==2.10\n",
        "app/settings.py": f'GITHUB_TOKEN = "{s["github_pat_history"]}"\nDEBUG = True\n',
    }, "add app")
    _write(py, {"app/settings.py": "import os\nGITHUB_TOKEN = os.environ.get('GITHUB_TOKEN')\nDEBUG = False\n"})
    _git(py, "commit", "-qam", "move token to environment")  # token remains in history only
    _write(py, {"app/aws.py": (f'AWS_ACCESS_KEY_ID = "{s["aws_access_key_id"]}"\n'
                               f'AWS_SECRET_ACCESS_KEY = "{s["aws_secret_access_key"]}"\n'),
                "app/github.py": f'TOKEN = "{s["github_pat_current"]}"\n'})
    _git(py, "add", "-A")
    _git(py, "commit", "-qm", "add cloud client")

    # 2. Node app: vulnerable lodash / minimist in package-lock.json.
    _new_repo(targets, "vuln-node-app", {
        "package.json": json.dumps({"name": "vuln-node-app", "version": "1.0.0",
                                    "dependencies": {"lodash": "4.17.15", "minimist": "1.2.0"}}, indent=2),
        "package-lock.json": json.dumps(NODE_LOCK, indent=2),
    })

    # 3. Infrastructure-as-code misconfigurations.
    _new_repo(targets, "insecure-infra", {
        "Dockerfile": DOCKERFILE, "k8s/deployment.yaml": K8S, "terraform/main.tf": TERRAFORM,
    })

    # 4. Clean control repository (false-positive check).
    _new_repo(targets, "clean-app", {
        "main.py": "def add(a: int, b: int) -> int:\n    return a + b\n",
        "README.md": "# Clean control repository\n",
    })

    meta = {"targets": str(targets), "secrets": s}
    (lab_dir / "lab_secrets.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta


def upgrade_python_dependency(lab_dir: Path) -> None:
    """Simulate remediation: upgrade requests to a fixed version (for the RESOLVED check)."""
    repo = lab_dir / "targets" / "vuln-python-app"
    req = (repo / "requirements.txt").read_text(encoding="utf-8").replace("requests==2.25.0", "requests==2.32.4")
    _write(repo, {"requirements.txt": req})
    _git(repo, "commit", "-qam", "upgrade requests")


if __name__ == "__main__":
    import sys

    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "vapt_lab"
    info = create_lab(target)
    print(f"VAPT lab created in {info['targets']}")
