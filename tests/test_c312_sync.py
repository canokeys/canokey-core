#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Synchronization gate regressions with an independent temporary Git graph."""

import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import check_c312_sync as check


class SynchronizationGate(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="c312-gate-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.source = self.root / "source"
        self.source.mkdir()
        subprocess.run(["git", "init", "-q", str(self.source)], check=True)
        check.git(self.source, "config", "user.name", "Fixture")
        check.git(self.source, "config", "user.email", "fixture@example.invalid")
        self.base = self.commit("base\n")
        self.left = self.commit("left\n", self.base)
        self.right = self.commit("right\n", self.base)
        # Unique merge resolution: neither parent's blob is the result.
        self.tip = self.commit("resolved\n", self.left, self.right)
        self.pins = {"repository": "local-fixture", "from": self.base, "to": self.tip}
        self.inventory = check.inventory(self.source, self.pins)
        self.target = self.root / "target"
        self.target.mkdir()
        (self.target / "target.rs").write_text("reviewed target\n")
        (self.target / "regression.rs").write_text("regression input\n")
        (self.target / "evidence.json").write_text('{"scope":"fixture"}\n')
        self.manifest = {
            "schema": 1, "source": self.pins, "expected_commits": 3,
            "required_behaviors": ["G1"], "remaining": [],
            "inventory": {"path": "source.json", "sha256": "0" * 64},
            "behaviors": [{"id": "G1", "behavior": "Fixture reviewed behavior",
                           "disposition": "implemented", "remaining": [],
                           "targets": [self.artifact("target.rs")],
                           "regressions": [{**self.artifact("regression.rs"), "id": "case1"}],
                           "evidence": [{**self.artifact("evidence.json"), "revision": self.tip,
                                         "scope": "temporary graph regression"}]}],
            "reviews": [],
        }
        for commit in self.inventory["commits"]:
            for change in commit["changes"]:
                self.manifest["reviews"].append({
                    "commit": commit["commit"], "parent": change["parent"],
                    "path": change["path"], "behaviors": ["G1"],
                    "hunks": [{"ordinal": i, "sha256": hunk["sha256"]}
                              for i, hunk in enumerate(change["hunks"])],
                })

    def artifact(self, path):
        return {"path": path, "sha256": check.sha256((self.target / path).read_bytes())}

    def commit(self, text, *parents):
        (self.source / "input.c").write_text(text)
        check.git(self.source, "add", "input.c")
        tree = check.git(self.source, "write-tree").decode().strip()
        args = ["commit-tree", tree, "-m", text.strip()]
        for parent in parents:
            args.extend(["-p", parent])
        return check.git(self.source, *args).decode().strip()

    def validate(self, manifest=None, inventory=None, verify=True):
        return check.validate(manifest or self.manifest, self.target,
                              inventory or self.inventory, self.source if verify else None)

    def run_cli(self, *arguments):
        (self.target / "source.json").write_text(json.dumps(self.inventory))
        self.manifest["inventory"] = self.artifact("source.json")
        (self.target / "manifest.json").write_text(json.dumps(self.manifest))
        return subprocess.run([
            "python3", str(Path(check.__file__)), "--manifest", str(self.target / "manifest.json"),
            "--target-root", str(self.target), *arguments,
        ], capture_output=True, text=True)

    def test_complete_inventory_and_review_pass(self):
        result = self.validate()
        self.assertEqual(result["commits"], 3)
        self.assertEqual(result["unreviewed"], 0)
        self.assertFalse(result["blockers"])
        self.assertEqual(self.run_cli("--source-repository", str(self.source)).returncode, 0)

    def test_missing_merge_parent_review_blocks_release(self):
        self.manifest["reviews"] = [r for r in self.manifest["reviews"]
                                    if r["commit"] != self.tip or r["parent"] != self.right]
        self.assertGreater(self.validate()["unreviewed"], 0)
        result = self.run_cli("--source-repository", str(self.source))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("incomplete", result.stderr)
        draft = self.run_cli("--structure-only")
        self.assertEqual(draft.returncode, 0)
        self.assertIn("NOT release acceptance", draft.stdout)

    def test_missing_commit_and_source_hunk_rejected(self):
        missing = copy.deepcopy(self.inventory)
        missing["commits"].pop(0)
        with self.assertRaises(check.Invalid):
            self.validate(inventory=missing)
        missing = copy.deepcopy(self.inventory)
        missing["commits"][-1]["changes"].pop()
        with self.assertRaises(check.Invalid):
            self.validate(inventory=missing)

    def test_changed_pins_rejected(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["source"] = {**self.pins, "to": self.left}
        with self.assertRaisesRegex(check.Invalid, "pins differ"):
            self.validate(manifest=manifest)

    def test_stale_review_and_duplicate_review_rejected(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["reviews"][0]["hunks"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(check.Invalid, "hunk changed"):
            self.validate(manifest=manifest)
        manifest = copy.deepcopy(self.manifest)
        manifest["reviews"].append(manifest["reviews"][0])
        with self.assertRaisesRegex(check.Invalid, "duplicate review"):
            self.validate(manifest=manifest)

    def test_missing_required_behavior_and_evidence_rejected(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["behaviors"].clear()
        with self.assertRaisesRegex(check.Invalid, "baseline behavior missing"):
            self.validate(manifest=manifest)
        (self.target / "evidence.json").unlink()
        with self.assertRaisesRegex(check.Invalid, "missing artifact"):
            self.validate()

    def test_changed_target_and_unsafe_artifact_rejected(self):
        (self.target / "target.rs").write_text("unreviewed modification\n")
        with self.assertRaisesRegex(check.Invalid, "stale artifact"):
            self.validate()
        for path in ("../source/input.c", "/tmp/x", "reference/legacy-c/x"):
            with self.subTest(path=path), self.assertRaises(check.Invalid):
                check.safe_path(self.target, path)
        (self.target / "escape").symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(check.Invalid):
            check.safe_path(self.target, "escape/input.c")

    def test_pending_acceptance_and_no_source_cannot_pass(self):
        self.manifest["behaviors"][0]["remaining"] = ["physical acceptance open"]
        result = self.run_cli("--source-repository", str(self.source))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("physical acceptance open", result.stdout)
        result = self.run_cli()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires --source-repository", result.stderr)

    def test_unresolved_disposition_and_duplicate_json_rejected(self):
        self.manifest["behaviors"][0]["disposition"] = "unreviewed"
        with self.assertRaisesRegex(check.Invalid, "unresolved disposition"):
            self.validate()
        path = self.target / "duplicate.json"
        path.write_text('{"schema":1,"schema":2}')
        with self.assertRaisesRegex(check.Invalid, "duplicate JSON"):
            check.read_json(path)


if __name__ == "__main__":
    unittest.main()
