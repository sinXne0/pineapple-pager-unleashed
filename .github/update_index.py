#!/usr/bin/env python3
"""Auto-update index.json when a payload PR is merged.

Runs from GitHub Actions on `pull_request [closed]` (merged only). Reads the
merged PR's changed files, finds the payload(s) it added under `payloads/`,
and adds/updates the matching `index.json` entry with the PR number, payload
name, title, and category.
"""

import json
import os
import re
import urllib.request

REPO = os.environ["GITHUB_REPOSITORY"]  # owner/repo
PR_NUMBER = os.environ["PR_NUMBER"]
PR_TITLE = os.environ.get("PR_TITLE", "")
TOKEN = os.environ.get("GITHUB_TOKEN", "")


def api(url):
    headers = {
        "User-Agent": "unleashed-index-updater",
        "Accept": "application/vnd.github+json",
    }
    if TOKEN:
        headers["Authorization"] = "token " + TOKEN
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req) as r:
        return json.load(r)


def main():
    files = api(
        "https://api.github.com/repos/%s/pulls/%s/files" % (REPO, PR_NUMBER)
    )

    # Only payload entry points count: payloads/<category>/<name>/payload.sh
    payload_sh = [
        f["filename"]
        for f in files
        if f["filename"].startswith("payloads/")
        and f["filename"].endswith("/payload.sh")
        and f.get("status") != "removed"
    ]
    if not payload_sh:
        print("No payload.sh added in this PR; leaving index.json unchanged.")
        return

    try:
        with open("index.json") as fh:
            idx = json.load(fh)
    except (OSError, json.JSONDecodeError):
        idx = {"repo": REPO, "payloads": []}

    title = re.sub(r"^(add|Add)\s+", "", PR_TITLE).strip()

    for path in payload_sh:
        parts = path.split("/")  # payloads / <category...> / <name> / payload.sh
        name = parts[-2]
        category = "/".join(parts[1:-2])
        entry = {
            "pr": int(PR_NUMBER),
            "name": name,
            "title": title,
            "category": category,
        }
        existing = [e for e in idx["payloads"] if e.get("pr") == int(PR_NUMBER)]
        if existing:
            existing[0].update(entry)
        else:
            idx["payloads"].append(entry)

    idx["payloads"].sort(key=lambda e: e.get("pr", 0))

    with open("index.json", "w") as fh:
        json.dump(idx, fh, indent=2)
        fh.write("\n")

    print("Updated index.json with PR #%s: %s (%s)" % (PR_NUMBER, title, name))


if __name__ == "__main__":
    main()
