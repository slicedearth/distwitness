#!/usr/bin/env python3
"""Fail closed on public-tree and workflow contract violations."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml

ACTION_PIN = re.compile(
    r"^\s*uses:\s*[^@\s]+@([0-9a-f]{40})\s+#\s+v[0-9][^\s]*\s*$",
    re.MULTILINE,
)
USES_LINE = re.compile(r"^\s*uses:\s*.+$", re.MULTILINE)
EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
ALLOWED_EMAIL_MARKERS = ("users.noreply.github.com", "example.com", "example.test")
REQUIRED_PUBLIC_DOCS = {
    "CONTRIBUTING.md",
    "DATA_SOURCES.md",
    "LICENSE",
    "PRIVACY.md",
    "README.md",
    "SECURITY.md",
    "THIRD_PARTY_NOTICES.md",
    "docs/ARCHITECTURE.md",
    "docs/OPERATIONS.md",
    "docs/STATE_SCHEMA.md",
    "docs/THREAT_MODEL.md",
    "docs/WATCHLIST_POLICY.md",
}


def audit_repository(root: Path) -> list[str]:
    """Return repository contract violations without mutating the tree."""

    return [
        *_document_contract_problems(root),
        *_workflow_contract_problems(root),
        *_public_text_problems(root),
    ]


def _document_contract_problems(root: Path) -> list[str]:
    problems: list[str] = []
    for relative in sorted(REQUIRED_PUBLIC_DOCS):
        if not (root / relative).is_file():
            problems.append(f"missing required public document: {relative}")
    return problems


def _workflow_contract_problems(root: Path) -> list[str]:
    problems: list[str] = []
    workflows = sorted((root / ".github/workflows").glob("*.yml"))
    if {path.name for path in workflows} != {"ci.yml", "scheduled-scan.yml"}:
        problems.append("expected exactly ci.yml and scheduled-scan.yml workflows")
    for workflow in workflows:
        text = workflow.read_text(encoding="utf-8")
        if "pull_request_target" in text:
            problems.append(f"{workflow}: pull_request_target is prohibited")
        uses_lines = USES_LINE.findall(text)
        pinned_lines = ACTION_PIN.findall(text)
        if len(uses_lines) != len(pinned_lines):
            problems.append(
                f"{workflow}: every Action must use a full SHA plus release-tag comment"
            )
        try:
            yaml.safe_load(text)
        except yaml.YAMLError as exc:
            problems.append(f"{workflow}: invalid YAML: {exc}")

    scheduled = root / ".github/workflows/scheduled-scan.yml"
    scheduled_text = scheduled.read_text(encoding="utf-8")
    for required in ("actions/cache/restore@", "actions/cache/save@"):
        if required not in scheduled_text:
            problems.append(f"{scheduled}: missing workflow state-cache boundary")
    for required in (
        "actions/configure-pages@",
        "actions/upload-pages-artifact@",
        "actions/deploy-pages@",
        "pages: write",
        "id-token: write",
        "name: github-pages",
    ):
        if required not in scheduled_text:
            problems.append(f"{scheduled}: missing Pages deployment boundary")
    for prohibited in (
        "git show FETCH_HEAD:.distwitness-state/state.json",
        "cp state/state.json generated",
        "git push origin gh-pages",
        "contents: write",
    ):
        if prohibited in scheduled_text:
            problems.append(f"{scheduled}: prohibited deployment operation")
    return problems


def _public_text_problems(root: Path) -> list[str]:
    problems: list[str] = []
    for path in _public_text_files(root):
        text = path.read_text(encoding="utf-8", errors="replace")
        for email in EMAIL.findall(text):
            if not any(marker in email.casefold() for marker in ALLOWED_EMAIL_MARKERS):
                problems.append(
                    f"{path}: personal or unexplained email address: {email}"
                )
    return problems


def audit_site(site: Path) -> list[str]:
    """Return violations in an inert generated site tree."""

    problems: list[str] = []
    required = {
        "index.html",
        "feed.xml",
        "data/current.json",
        "data/events.json",
        "data/health.json",
        "reports/latest.md",
        "assets/styles.css",
        "assets/app.js",
        "assets/logo.svg",
    }
    for relative in sorted(required):
        if not (site / relative).is_file():
            problems.append(f"generated site is missing {relative}")
    forbidden_names = {
        ".distwitness-state",
        ".env",
        ".git",
        ".github",
        "pyproject.toml",
        "state.json",
    }
    for path in site.rglob("*"):
        if path.name in forbidden_names or path.suffix == ".py":
            problems.append(f"forbidden generated-tree path: {path}")
    for script in site.rglob("*.js"):
        text = script.read_text(encoding="utf-8", errors="replace")
        for forbidden in ("innerHTML", "fetch(", "XMLHttpRequest", "WebSocket"):
            if forbidden in text:
                problems.append(f"{script}: forbidden browser operation {forbidden}")
    for stylesheet in site.rglob("*.css"):
        text = stylesheet.read_text(encoding="utf-8", errors="replace").casefold()
        if "@import" in text or "url(http://" in text or "url(https://" in text:
            problems.append(f"{stylesheet}: external stylesheet resource")
    for html in site.rglob("*.html"):
        text = html.read_text(encoding="utf-8", errors="replace")
        if re.search(r"<(?:script|img|link)[^>]+(?:src|href)=[\"']https?://", text):
            problems.append(f"{html}: external executable or visual resource")
    return problems


def _public_text_files(root: Path) -> list[Path]:
    candidates = [
        *root.glob("*.md"),
        *root.glob("docs/**/*.md"),
        *root.glob("src/**/*.py"),
        *root.glob("src/**/*.html"),
        *root.glob("src/**/*.css"),
        *root.glob("src/**/*.js"),
        *root.glob(".github/**/*.yml"),
        root / "pyproject.toml",
    ]
    return sorted({path for path in candidates if path.is_file()})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--site", type=Path)
    arguments = parser.parse_args()
    problems = audit_repository(arguments.root.resolve())
    if arguments.site:
        problems.extend(audit_site(arguments.site.resolve()))
    if problems:
        for problem in problems:
            print(f"ERROR: {problem}", file=sys.stderr)
        return 1
    print("Repository and generated public-tree audit passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
