#!/usr/bin/env python3
"""Create Sentinelle's GitHub labels, milestones and issues from docs/backlog-issues.json.

Idempotent: existing labels/milestones/issues (matched by name/title) are skipped.

Usage:
    GITHUB_TOKEN=ghp_xxx python3 scripts/create_github_issues.py --repo kitokoh/sentinelle
    GITHUB_TOKEN=ghp_xxx python3 scripts/create_github_issues.py --repo kitokoh/sentinelle --dry-run
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

API = "https://api.github.com"
BACKLOG = Path(__file__).resolve().parent.parent / "docs" / "backlog-issues.json"


def gh(token: str, method: str, path: str, payload: dict | None = None) -> tuple[int, object]:
    req = urllib.request.Request(
        API + path,
        method=method,
        data=json.dumps(payload).encode() if payload is not None else None,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "User-Agent": "sentinelle-backlog-script",
        },
    )
    try:
        with urllib.request.urlopen(req) as resp:
            body = resp.read()
            return resp.status, (json.loads(body) if body else None)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def gh_all(token: str, path: str) -> list:
    """Paginate a list endpoint."""
    out, page = [], 1
    while True:
        status, data = gh(token, "GET", f"{path}{'&' if '?' in path else '?'}per_page=100&page={page}")
        if status != 200 or not isinstance(data, list):
            return out
        out.extend(data)
        if len(data) < 100:
            return out
        page += 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", required=True, help="owner/name, e.g. kitokoh/sentinelle")
    parser.add_argument("--dry-run", action="store_true", help="print what would be created")
    args = parser.parse_args()

    token = os.environ.get("GITHUB_TOKEN")
    if not token and not args.dry_run:
        sys.exit("ERROR: set GITHUB_TOKEN (scope: repo)")

    backlog = json.loads(BACKLOG.read_text(encoding="utf-8"))
    created = {"labels": 0, "milestones": 0, "issues": 0}

    if args.dry_run:
        print(f"[dry-run] {len(backlog['labels'])} labels, {len(backlog['milestones'])} milestones, {len(backlog['issues'])} issues would be synced to {args.repo}")
        for i in backlog["issues"]:
            print(f"  - [{i['milestone']}] {i['title']}  ({', '.join(i['labels'])})")
        return 0

    # Sanity check
    status, repo = gh(token, "GET", f"/repos/{args.repo}")
    if status != 200:
        sys.exit(f"ERROR: cannot access {args.repo}: {status} {repo}")
    print(f"Repo OK: {repo['html_url']}")

    # Labels (skip existing names)
    existing_labels = {l["name"] for l in gh_all(token, f"/repos/{args.repo}/labels")}
    for label in backlog["labels"]:
        if label["name"] in existing_labels:
            continue
        status, _ = gh(token, "POST", f"/repos/{args.repo}/labels", label)
        if status == 201:
            created["labels"] += 1
        else:
            print(f"  ! label {label['name']}: HTTP {status}")
        time.sleep(0.2)
    print(f"Labels: {created['labels']} created, {len(backlog['labels']) - created['labels']} already existed")

    # Milestones (skip existing titles, open or closed)
    existing_ms = {m["title"]: m["number"] for m in gh_all(token, f"/repos/{args.repo}/milestones?state=all")}
    ms_numbers = dict(existing_ms)
    for ms in backlog["milestones"]:
        if ms["title"] in ms_numbers:
            continue
        status, data = gh(token, "POST", f"/repos/{args.repo}/milestones", ms)
        if status == 201:
            created["milestones"] += 1
            ms_numbers[ms["title"]] = data["number"]
        else:
            print(f"  ! milestone {ms['title']}: HTTP {status}")
        time.sleep(0.2)
    print(f"Milestones: {created['milestones']} created, {len(backlog['milestones']) - created['milestones']} already existed")

    # Issues (skip existing titles, open or closed)
    existing_issues = {i["title"] for i in gh_all(token, f"/repos/{args.repo}/issues?state=all")}
    for issue in backlog["issues"]:
        if issue["title"] in existing_issues:
            continue
        ms_number = ms_numbers.get(issue["milestone"])
        if ms_number is None:
            print(f"  ! skipping '{issue['title']}': milestone '{issue['milestone']}' not found")
            continue
        payload = {
            "title": issue["title"],
            "body": issue["body"],
            "labels": issue["labels"],
            "milestone": ms_number,
        }
        status, data = gh(token, "POST", f"/repos/{args.repo}/issues", payload)
        if status == 201:
            created["issues"] += 1
        else:
            print(f"  ! issue {issue['title']}: HTTP {status} {data}")
        time.sleep(0.3)
    print(f"Issues: {created['issues']} created, {len(backlog['issues']) - created['issues']} already existed")

    print("\nDone. Board: https://github.com/{}/issues".format(args.repo))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
