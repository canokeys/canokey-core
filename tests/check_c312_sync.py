#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check reviewed C-to-Rust synchronization; the default is a release gate.

Source inventory includes every commit and every diff against every parent.
Merge-result changes therefore cannot disappear behind a merge subject or an
empty combined diff. Inventory generation never creates review dispositions.
No command fetches refs, checks out source, or reads reference/legacy-c.
"""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
DISPOSITIONS = {
    "implemented", "already equivalent", "intentional difference",
    "removed intentional difference", "test/tool-only",
}
REVISION = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class Invalid(ValueError):
    """A synchronization record is inconsistent or not reviewable."""


def require(condition, message):
    if not condition:
        raise Invalid(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def git(repository, *arguments):
    return subprocess.check_output(
        ["git", "-C", str(repository), *arguments], stderr=subprocess.PIPE
    )


def check_revision(value):
    require(isinstance(value, str) and REVISION.fullmatch(value),
            f"expected a pinned full commit, got {value!r}")


def safe_path(root, name):
    require(isinstance(name, str), "path must be text")
    relative = PurePosixPath(name)
    require(name and not relative.is_absolute() and ".." not in relative.parts,
            f"unsafe relative path: {name!r}")
    require(not any(relative.parts[i:i + 2] == ("reference", "legacy-c")
                    for i in range(len(relative.parts))), "legacy C snapshot is forbidden")
    path = root / relative
    require(path.resolve().is_relative_to(root.resolve()), f"path escapes root: {name}")
    return path


def inventory(repository, source):
    """Fingerprint file metadata and zero-context hunks, including deletions."""
    for key in ("from", "to"):
        check_revision(source[key])
        actual = git(repository, "rev-parse", f"{source[key]}^{{commit}}").decode().strip()
        require(actual == source[key], f"source {key} is not the pinned commit")
    subprocess.run(["git", "-C", str(repository), "merge-base", "--is-ancestor",
                    source["from"], source["to"]], check=True, capture_output=True)
    lines = git(repository, "rev-list", "--reverse", "--topo-order", "--parents",
                f'{source["from"]}..{source["to"]}').decode().splitlines()
    commits = []
    for line in lines:
        commit, *parents = line.split()
        changes = []
        for parent in parents:
            paths = git(repository, "diff", "--no-ext-diff", "--no-renames",
                        "--name-only", "-z", parent, commit).split(b"\0")
            for raw_path in filter(None, paths):
                path = raw_path.decode("utf-8")
                safe_path(Path("/inventory"), path)
                patch = git(repository, "-c", "core.quotePath=true", "diff",
                            "--no-ext-diff", "--no-textconv", "--no-renames",
                            "--no-color", "--no-indent-heuristic", "--diff-algorithm=myers",
                            "--src-prefix=a/", "--dst-prefix=b/", "--unified=0", "--binary",
                            "--full-index", "--no-relative", "--submodule=short",
                            parent, commit, "--", f":(literal){path}")
                sections = re.split(br"(?m)(?=^@@ )", patch)
                changes.append({
                    "parent": parent, "path": path, "patch_sha256": sha256(patch),
                    "hunks": [{"header": "file metadata" if i == 0 else
                               section.split(b"\n", 1)[0].decode("utf-8"),
                               "sha256": sha256(section)}
                              for i, section in enumerate(sections)],
                })
        commits.append({"commit": commit, "parents": parents, "changes": changes})
    return {"schema": 1, "source": source, "commits": commits}


def read_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, f"duplicate JSON key {key!r} in {path}")
            result[key] = value
        return result
    return json.loads(path.read_text(), object_pairs_hook=unique)


def artifact(root, record):
    path = safe_path(root, record["path"])
    digest = record["sha256"]
    require(isinstance(digest, str) and DIGEST.fullmatch(digest),
            f"missing SHA256: {record['path']}")
    require(path.is_file(), f"missing artifact: {record['path']}")
    require(sha256(path.read_bytes()) == digest, f"stale artifact: {record['path']}")


def unit_key(commit, parent, path, ordinal):
    return (commit, parent, path, ordinal)


def validate(manifest, root, source_inventory, repository=None):
    require(manifest["schema"] == source_inventory["schema"] == 1, "unsupported schema")
    require(manifest["source"] == source_inventory["source"], "source pins differ")
    require(manifest["source"]["repository"], "missing source repository identity")
    for key in ("from", "to"):
        check_revision(manifest["source"][key])
    if repository is not None:
        require(inventory(repository, manifest["source"]) == source_inventory,
                "source inventory differs from pinned Git history")

    units = {}
    commits = set()
    for entry in source_inventory["commits"]:
        commit = entry["commit"]
        check_revision(commit)
        require(commit not in commits, f"duplicate source commit: {commit}")
        commits.add(commit)
        require(entry["parents"], f"commit without parents: {commit}")
        require(len(entry["parents"]) == len(set(entry["parents"])), "duplicate parent")
        for parent in entry["parents"]:
            check_revision(parent)
        changes = set()
        for change in entry["changes"]:
            parent, path = change["parent"], change["path"]
            require(parent in entry["parents"], f"unknown parent: {parent}")
            safe_path(root, path)
            require((parent, path) not in changes, f"duplicate source file: {path}")
            changes.add((parent, path))
            require(DIGEST.fullmatch(change["patch_sha256"]), "invalid patch fingerprint")
            require(change["hunks"], f"missing metadata/hunks: {path}")
            for ordinal, hunk in enumerate(change["hunks"]):
                require(DIGEST.fullmatch(hunk["sha256"]), "invalid hunk fingerprint")
                require(hunk["header"], "missing hunk header")
                units[unit_key(commit, parent, path, ordinal)] = hunk["sha256"]
    require(len(commits) == manifest["expected_commits"], "source commit count differs")
    require(source_inventory["commits"] and manifest["source"]["to"] in commits,
            "source tip missing from inventory")

    behaviors = {}
    blockers = []
    for record in manifest["behaviors"]:
        identity = record["id"]
        require(identity and identity not in behaviors, f"duplicate behavior: {identity}")
        behaviors[identity] = record
        require(record["behavior"].strip(), f"missing behavior: {identity}")
        require(record["disposition"] in DISPOSITIONS, f"unresolved disposition: {identity}")
        for field in ("targets", "regressions", "evidence"):
            require(record[field], f"{identity}: missing {field}")
            for item in record[field]:
                artifact(root, item)
                if field == "regressions":
                    require(item["id"].strip(), f"{identity}: missing regression ID")
                elif field == "evidence":
                    check_revision(item["revision"])
                    require(item["scope"].strip(), f"{identity}: missing evidence scope")
        require(isinstance(record["remaining"], list), f"{identity}: remaining must be a list")
        blockers.extend(f"{identity}: {reason}" for reason in record["remaining"])
    for identity in manifest["required_behaviors"]:
        require(identity in behaviors, f"required baseline behavior missing: {identity}")

    mapped = set()
    for review in manifest["reviews"]:
        require(review["behaviors"], "review has no behavior disposition")
        for identity in review["behaviors"]:
            require(identity in behaviors, f"unknown review behavior: {identity}")
        require(review["hunks"], "review has no hunks")
        for hunk in review["hunks"]:
            key = unit_key(review["commit"], review["parent"], review["path"], hunk["ordinal"])
            require(key in units, f"review references nonexistent hunk: {key}")
            require(key not in mapped, f"duplicate review: {key}")
            require(units[key] == hunk["sha256"], f"reviewed hunk changed: {key}")
            mapped.add(key)
    require(isinstance(manifest["remaining"], list), "remaining must be a list")
    blockers.extend(manifest["remaining"])
    return {"commits": len(commits), "hunks": len(units), "reviewed": len(mapped),
            "unreviewed": len(units) - len(mapped), "blockers": blockers}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=ROOT / "docs/sync/c312.json")
    parser.add_argument("--target-root", type=Path, default=ROOT)
    parser.add_argument("--source-repository", type=Path,
                        help="local pinned C Git objects; required for the release gate")
    parser.add_argument("--structure-only", action="store_true",
                        help="validate inventory/records, report unfinished work; NOT a release pass")
    parser.add_argument("--write-inventory", action="store_true",
                        help="regenerate source fingerprints only; never approve mappings")
    args = parser.parse_args()
    try:
        manifest = read_json(args.manifest)
        inventory_path = safe_path(args.target_root, manifest["inventory"]["path"])
        if args.write_inventory:
            require(args.source_repository is not None, "inventory generation needs --source-repository")
            data = inventory(args.source_repository, manifest["source"])
            inventory_path.parent.mkdir(parents=True, exist_ok=True)
            inventory_path.write_text(json.dumps(data, indent=2) + "\n")
            print(f"Inventory written; review its fingerprint: {sha256(inventory_path.read_bytes())}")
            return 0
        artifact(args.target_root, manifest["inventory"])
        require(args.structure_only or args.source_repository is not None,
                "release check requires --source-repository (no refs are fetched)")
        result = validate(manifest, args.target_root, read_json(inventory_path), args.source_repository)
        print(json.dumps(result, indent=2))
        if args.structure_only:
            print("Structure checked only; this is NOT release acceptance.")
            return 0
        require(not result["unreviewed"] and not result["blockers"],
                "release synchronization incomplete: unreviewed hunks or open acceptance")
        print("Pinned source synchronization accepted; physical readiness is a separate gate.")
        return 0
    except (Invalid, KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"C 3.1.2 synchronization check failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
