import argparse
import ast
import datetime as dt
import json
import re
import shlex
import subprocess
import sys
from pathlib import Path


# Phase 1 deliberately covers the test, deploy, and proof roots. Repo-wide
# enumeration was considered: it finds 115 files instead of 31, including 26
# SVG assets accidentally mode 100755, and needs a separate classification.
SCAN_ROOTS = ("cli/tests/", "deploy/", "proofs/")
DISPOSITIONS = {"required", "diagnostic", "retired", "operational", "support"}
PLATFORMS = {"linux", "macos", "windows", "portable"}
TOPOLOGIES = {
    "browser-loopback",
    "deployment-host",
    "linux-netns",
    "local-fixture",
    "model-checker",
    "unit",
}
ISSUE_RE = re.compile(r"https://github\.com/Abdk4Moura/filament/issues/[1-9][0-9]*$")
# A `required` artifact whose path appears in no workflow is not required by
# anything: the entrypoint check below proves only that the command is spelled
# correctly, never that CI invokes it (#249). These 14 predate that check. The
# set may only SHRINK - wire one into CI, or re-disposition it honestly, and
# delete its line. Adding a line is not a fix.
# cli/tests/gates.sh left this set on 2026-08-24: the Gates Core workflow now
# invokes it on every cli/** and backend/** change, and asserts a named
# expected-green set via cli/tests/gates-ratchet.sh rather than a pass count.
UNWIRED_REQUIRED = {
    "cli/tests/l1a/gate1_mutual_key.sh",
    "cli/tests/l1a/gate3_wrongpw_burn.sh",
    "cli/tests/l1a/gate6_downgrade.sh",
    "cli/tests/l1a/gate7_noregression.sh",
    "cli/tests/l1a/gate9_transfer_pake.sh",
    "cli/tests/l1a/gate9b_shared_room.sh",
    "cli/tests/l2-gates.sh",
    "cli/tests/live-pairing-gate.sh",
    "cli/tests/live-wire-check.sh",
    "cli/tests/natprobe-test.sh",
    "cli/tests/ssh-gates.sh",
    "cli/tests/transport-gates.sh",
    "deploy/monitor/test-memory-pressure-monitor.py",
}

RETIRED_TOMBSTONES = {
    "cli/tests/holepunch-gates.sh",
    "cli/tests/livelock-nat-gates.sh",
    "cli/tests/nat-cone-gate.sh",
    "cli/tests/reliability_test.sh",
    "cli/tests/stun-server.py",
}


def source_references(path: Path, target: str) -> bool:
    source = path.read_text(errors="surrogateescape")
    if path.suffix == ".py":
        tree = ast.parse(source)
        docstrings = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if node.body and isinstance(node.body[0], ast.Expr):
                    value = node.body[0].value
                    if isinstance(value, ast.Constant) and isinstance(value.value, str):
                        docstrings.add(id(value))
        return any(
            target in node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and id(node) not in docstrings
        )
    for line in source.splitlines():
        stripped = line.lstrip()
        if stripped.startswith(("#", "//")):
            continue
        if path.suffix == ".sh":
            lexer = shlex.shlex(line, posix=True)
            lexer.whitespace_split = True
            lexer.commenters = "#"
            if any(target in token for token in lexer):
                return True
        elif target in line:
            return True
    return False


def entrypoint_runs(entrypoint: object, path: str) -> bool:
    if not isinstance(entrypoint, str):
        return False
    try:
        tokens = shlex.split(entrypoint, comments=True)
    except ValueError:
        return False
    if tokens and tokens[0] == path:
        return True
    interpreters = {"bash", "sh", "python", "python3", "node"}
    return any(
        token == path and index > 0 and Path(tokens[index - 1]).name in interpreters
        for index, token in enumerate(tokens)
    )


def rust_test_exists(source: str, name: str) -> bool:
    lines = source.splitlines()
    declaration = re.compile(rf"^\s*fn\s+{re.escape(name)}\s*\(")
    test_attribute = re.compile(r"^\s*#\[(?:tokio::)?test(?:\([^]]*\))?\]")
    for index, line in enumerate(lines):
        if declaration.search(line):
            found = False
            cursor = index - 1
            while cursor >= 0:
                candidate = lines[cursor]
                if not candidate.strip():
                    cursor -= 1
                    continue
                if not candidate.lstrip().startswith("#["):
                    break
                found = found or bool(test_attribute.search(candidate))
                cursor -= 1
            return found
    return False


def valid_retirement_reference(reference: object, root: Path) -> bool:
    if not isinstance(reference, str) or not reference:
        return False
    if re.fullmatch(r"PR #[1-9][0-9]*", reference) or ISSUE_RE.fullmatch(reference):
        return True
    raw_path = reference.split("#", 1)[0]
    path = Path(raw_path)
    if not raw_path or path.is_absolute() or ".." in path.parts:
        return False
    candidate = (root / path).resolve()
    return candidate.is_relative_to(root.resolve()) and candidate.is_file()


def tracked_artifacts(root: Path) -> set[str]:
    output = subprocess.run(
        ["git", "ls-files", "--stage", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    ).stdout
    artifacts = set()
    for record in output.split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode = metadata.split(b" ", 1)[0]
        path = raw_path.decode("utf-8", "surrogateescape")
        if not path.startswith(SCAN_ROOTS):
            continue
        if not (root / path).is_file():
            continue
        executable = bool(int(mode, 8) & 0o111)
        with (root / path).open("rb") as source:
            first_line = source.readline(256)
        shebang = first_line.startswith(b"#!") and not first_line.startswith(b"#![")
        if executable or shebang:
            artifacts.add(path)
    return artifacts


def validate_matrix(matrix: object, path: str, errors: list[str]) -> None:
    if not isinstance(matrix, list) or not matrix:
        errors.append(f"{path}: matrix must be a non-empty list")
        return
    for index, row in enumerate(matrix):
        label = f"{path}: matrix[{index}]"
        if not isinstance(row, dict) or set(row) != {"platform", "topology"}:
            errors.append(f"{label} must contain exactly platform and topology")
            continue
        if row["platform"] not in PLATFORMS:
            errors.append(f"{label}: unknown platform {row['platform']!r}")
        if row["topology"] not in TOPOLOGIES:
            errors.append(f"{label}: unknown topology {row['topology']!r}")


def validate(
    registry: object,
    root: Path,
    discovered: set[str],
    today: dt.date,
) -> list[str]:
    errors = []
    if not isinstance(registry, dict) or set(registry) != {
        "version",
        "artifacts",
        "verdict_debt",
    }:
        return ["registry must contain exactly version, artifacts, and verdict_debt"]
    if registry["version"] != 1:
        errors.append("registry version must be 1")
    if not isinstance(registry["artifacts"], list):
        return errors + ["artifacts must be a list"]

    entries = {}
    for index, entry in enumerate(registry["artifacts"]):
        label = f"artifacts[{index}]"
        if not isinstance(entry, dict):
            errors.append(f"{label} must be an object")
            continue
        path = entry.get("path")
        disposition = entry.get("disposition")
        if not isinstance(path, str) or not path:
            errors.append(f"{label}: path must be a non-empty string")
            continue
        if path in entries:
            errors.append(f"{path}: duplicate registry entry")
            continue
        entries[path] = entry
        if disposition not in DISPOSITIONS:
            errors.append(f"{path}: unknown disposition {disposition!r}")
            continue

        expected = {
            "required": {"path", "disposition", "entrypoint", "matrix"},
            "diagnostic": {"path", "disposition", "issue", "owner", "expires"},
            "retired": {"path", "disposition", "reason", "reference"},
            "operational": {
                "path",
                "disposition",
                "entrypoint",
                "matrix",
                "activation",
                "invoked_by",
            },
            "support": {"path", "disposition", "invoked_by"},
        }[disposition]
        if set(entry) != expected:
            missing = sorted(expected - set(entry))
            extra = sorted(set(entry) - expected)
            errors.append(f"{path}: incomplete schema; missing={missing}, extra={extra}")
            continue

        exists = (root / path).is_file()
        if disposition == "retired":
            if exists:
                errors.append(f"{path}: retired artifact still exists")
            if not entry["reason"] or not valid_retirement_reference(entry["reference"], root):
                errors.append(f"{path}: retired reason and durable reference are required")
            continue
        if not exists:
            errors.append(f"{path}: registered artifact does not exist")

        if disposition == "required":
            if not entrypoint_runs(entry["entrypoint"], path):
                errors.append(f"{path}: entrypoint must execute the artifact path")
            validate_matrix(entry["matrix"], path, errors)
        elif disposition == "diagnostic":
            if not ISSUE_RE.fullmatch(entry["issue"]):
                errors.append(f"{path}: diagnostic issue must be a full GitHub issue URL")
            if not entry["owner"]:
                errors.append(f"{path}: diagnostic owner must be non-empty")
            try:
                expiry = dt.date.fromisoformat(entry["expires"])
                if expiry < today:
                    errors.append(f"{path}: diagnostic expired on {expiry.isoformat()}")
            except (TypeError, ValueError):
                errors.append(f"{path}: diagnostic expiry must be YYYY-MM-DD")
        elif disposition == "operational":
            if entry["activation"] not in {"manual", "systemd"}:
                errors.append(f"{path}: operational activation must be manual or systemd")
            if not isinstance(entry["invoked_by"], list):
                errors.append(f"{path}: invoked_by must be a list")
            elif entry["activation"] == "systemd" and not entry["invoked_by"]:
                errors.append(f"{path}: systemd activation requires invoked_by")
            if not entrypoint_runs(entry["entrypoint"], path):
                errors.append(f"{path}: entrypoint must execute the artifact path")
            validate_matrix(entry["matrix"], path, errors)
        elif disposition == "support":
            if not isinstance(entry["invoked_by"], list) or not entry["invoked_by"]:
                errors.append(f"{path}: support requires at least one invoked_by artifact")

    active = {
        path for path, entry in entries.items() if entry.get("disposition") != "retired"
    }
    for path in sorted(discovered - active):
        errors.append(f"{path}: executable artifact is unregistered")
    for path in sorted(active - discovered):
        errors.append(f"{path}: active registry entry is not executable or has no shebang")

    workflows = ""
    wf_dir = root / ".github" / "workflows"
    if wf_dir.is_dir():
        for wf in sorted(wf_dir.glob("*.y*ml")):
            workflows += wf.read_text(encoding="utf-8", errors="replace")
    required = {
        path for path, entry in entries.items() if entry.get("disposition") == "required"
    }
    unwired = {path for path in required if path not in workflows}
    for path in sorted(unwired - UNWIRED_REQUIRED):
        errors.append(
            f"{path}: disposition is 'required' but no workflow references it, "
            "so nothing requires it. Wire it into CI, or use a disposition that "
            "states the truth (see #249)."
        )
    for path in sorted((UNWIRED_REQUIRED & required) - unwired):
        errors.append(
            f"{path}: listed in UNWIRED_REQUIRED but it is now wired or no longer "
            "required. Delete its line; the ratchet may only shrink."
        )

    retired = {
        path for path, entry in entries.items() if entry.get("disposition") == "retired"
    }
    if retired != RETIRED_TOMBSTONES:
        errors.append(
            "retired tombstones differ from validator history: "
            f"expected={sorted(RETIRED_TOMBSTONES)}, actual={sorted(retired)}"
        )

    for path, entry in entries.items():
        if entry.get("disposition") not in {"support", "operational"}:
            continue
        for caller in entry.get("invoked_by", []):
            caller_path = root / caller
            if not caller_path.is_file():
                errors.append(f"{path}: invoked_by target does not exist: {caller}")
                continue
            if caller in entries and entries[caller].get("disposition") == "retired":
                errors.append(f"{path}: invoked_by target is retired: {caller}")
                continue
            if entry["disposition"] == "support" and caller not in active:
                errors.append(f"{path}: support consumer is not an active artifact: {caller}")
                continue
            if not source_references(caller_path, Path(path).name):
                errors.append(f"{path}: declared caller does not reference it: {caller}")

    debts = registry["verdict_debt"]
    if not isinstance(debts, list):
        errors.append("verdict_debt must be a list")
    else:
        seen_debts = set()
        for index, debt in enumerate(debts):
            label = f"verdict_debt[{index}]"
            expected = {"path", "test", "platforms", "behavior"}
            if not isinstance(debt, dict) or set(debt) != expected:
                errors.append(f"{label} must contain exactly path, test, platforms, behavior")
                continue
            key = (debt["path"], debt["test"])
            if key in seen_debts:
                errors.append(f"{label}: duplicate debt {key}")
            seen_debts.add(key)
            if not (root / debt["path"]).is_file():
                errors.append(f"{label}: path does not exist: {debt['path']}")
            if not debt["test"] or not debt["behavior"]:
                errors.append(f"{label}: test and behavior must be non-empty")
            if not isinstance(debt["platforms"], list) or not debt["platforms"]:
                errors.append(f"{label}: platforms must be a non-empty list")
            else:
                unknown = set(debt["platforms"]) - PLATFORMS
                if unknown:
                    errors.append(f"{label}: unknown platforms {sorted(unknown)}")
            source = (root / debt["path"]).read_text(errors="surrogateescape")
            if not rust_test_exists(source, debt["test"]):
                errors.append(f"{label}: attributed test does not exist: {debt['test']}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--registry", default=".github/executable-artifacts.json", type=Path
    )
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    registry_path = args.registry if args.registry.is_absolute() else root / args.registry
    try:
        registry = json.loads(registry_path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        print(f"artifact registry: cannot read {registry_path}: {error}", file=sys.stderr)
        return 1
    errors = validate(registry, root, tracked_artifacts(root), dt.date.today())
    if errors:
        for error in errors:
            print(f"artifact registry: {error}", file=sys.stderr)
        return 1
    counts = {}
    for entry in registry["artifacts"]:
        disposition = entry["disposition"]
        counts[disposition] = counts.get(disposition, 0) + 1
    summary = ", ".join(f"{key}={counts.get(key, 0)}" for key in sorted(DISPOSITIONS))
    print(f"artifact registry: PASS ({summary})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
