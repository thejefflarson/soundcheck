#!/usr/bin/env python3
"""
Cut a coordinated release of soundcheck + soundcheck-action.

Keeps the two repos in lockstep:
  1. Bump version in .claude-plugin/plugin.json and marketplace.json
  2. Refresh the skill count in marketplace.json's plugins[0].description
  3. Commit, tag vX.Y.Z, push
  4. In ../soundcheck-action: bump SOUNDCHECK_SHA in action.yml to the new HEAD
  5. Commit, tag v1.0.N (auto-incremented), move floating v1, push everything

Defaults to dry-run. Pass --push to actually perform writes/commits/pushes.
Refuses to run unless both working trees are clean.

Usage:
    python scripts/release.py 1.8.0                  # dry run
    python scripts/release.py 1.8.0 --push           # for real
    python scripts/release.py 1.8.0 --push --yes     # skip confirmation
    python scripts/release.py 1.8.0 --action-dir /path/to/soundcheck-action
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SOUNDCHECK_DIR = SCRIPT_DIR.parent
DEFAULT_ACTION_DIR = SOUNDCHECK_DIR.parent / "soundcheck-action"

PLUGIN_JSON = SOUNDCHECK_DIR / ".claude-plugin" / "plugin.json"
MARKETPLACE_JSON = SOUNDCHECK_DIR / ".claude-plugin" / "marketplace.json"
SKILLS_DIR = SOUNDCHECK_DIR / ".claude" / "skills"


class ReleaseError(Exception):
    pass


def run(cmd: list[str], cwd: Path, check: bool = True, capture: bool = True) -> str:
    result = subprocess.run(
        cmd, cwd=cwd, check=check, text=True,
        capture_output=capture,
    )
    return (result.stdout or "").strip()


def require_clean_tree(repo: Path) -> None:
    status = run(["git", "status", "--porcelain"], cwd=repo)
    if status:
        raise ReleaseError(
            f"{repo} has uncommitted changes:\n{status}\nCommit or stash first."
        )


def require_valid_plugin_manifest() -> None:
    """Reject the release if `claude plugin validate` errors on plugin.json.

    Catches schema regressions like the v1.12.0 `agents: Invalid input` bug
    (directory path where a file path was required). Run against the file
    directly because the directory form picks marketplace.json over
    plugin.json. Warnings (e.g. the CLAUDE.md hint) are tolerated; only
    errors block.
    """
    import shutil
    if not shutil.which("claude"):
        raise ReleaseError(
            "claude CLI not on PATH; install @anthropic-ai/claude-code or "
            "skip preflight by running with --no-validate (not implemented)."
        )
    r = subprocess.run(
        ["claude", "plugin", "validate", str(PLUGIN_JSON)],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        raise ReleaseError(
            f"`claude plugin validate {PLUGIN_JSON}` failed:\n"
            f"{r.stdout}{r.stderr}"
        )


def require_on_main(repo: Path) -> None:
    branch = run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=repo)
    if branch != "main":
        raise ReleaseError(f"{repo} is on branch {branch!r}, not main")


def require_prerelease_checks() -> None:
    """Run scripts/prerelease-checks.py and reject on any failure.

    Catches README drift (skill count, missing referenced scripts, broken
    doc links) and inherited static-validation problems before the tag
    push. Warnings are surfaced but don't block.
    """
    script = SOUNDCHECK_DIR / "scripts" / "prerelease-checks.py"
    r = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True, text=True,
    )
    # Print stdout so warnings surface in the release plan output.
    if r.stdout.strip():
        print(r.stdout.rstrip())
    if r.returncode != 0:
        raise ReleaseError(
            "Prerelease checks failed (see output above). Fix the "
            "mismatches or run `python scripts/prerelease-checks.py` "
            "directly to debug."
        )


def count_skills() -> int:
    return sum(1 for p in SKILLS_DIR.iterdir() if p.is_dir() and (p / "SKILL.md").exists())


def next_action_version(action_dir: Path) -> str:
    """Find the highest v1.0.N tag in soundcheck-action and return v1.0.(N+1).

    Fetches both local-known tags and the authoritative remote tag list so
    a stale local clone can't pick a patch number that already exists on
    origin.
    """
    try:
        run(["git", "fetch", "--tags", "origin"], cwd=action_dir)
    except subprocess.CalledProcessError as exc:
        raise ReleaseError(
            f"git fetch failed in {action_dir}: {exc.stderr or exc}"
        ) from exc
    local_tags = run(["git", "tag", "-l", "v1.0.*"], cwd=action_dir).splitlines()
    remote_listing = run(
        ["git", "ls-remote", "--tags", "origin", "refs/tags/v1.0.*"],
        cwd=action_dir,
    ).splitlines()
    remote_tags = [
        line.split("refs/tags/")[-1] for line in remote_listing if "refs/tags/" in line
    ]
    patches = []
    for t in list(local_tags) + list(remote_tags):
        m = re.fullmatch(r"v1\.0\.(\d+)", t.strip())
        if m:
            patches.append(int(m.group(1)))
    if not patches:
        raise ReleaseError("No v1.0.* tags found in soundcheck-action")
    return f"v1.0.{max(patches) + 1}"


def verify_remote_has_commit(repo: Path, commit: str) -> None:
    """Fail loudly if `commit` is not reachable from origin.

    Note: this is a check-then-act on mutable remote state.  There is an
    inherent race between the branch-listing RPC here and the subsequent
    tag-move push: a concurrent force-push could in theory remove the commit
    from origin between these two operations.  Git provides no server-side
    atomic lock for this pattern without a custom hook.  The window is
    narrow and the caller (plan_and_apply) also calls verify_v1_ancestor
    immediately before tagging, so the risk is accepted and documented.
    """
    try:
        output = run(
            ["git", "branch", "-r", "--contains", commit], cwd=repo
        )
    except subprocess.CalledProcessError as exc:
        raise ReleaseError(
            f"verifying remote has {commit[:8]} failed: {exc.stderr or exc}"
        ) from exc
    if not any(line.strip().startswith("origin/") for line in output.splitlines()):
        raise ReleaseError(
            f"commit {commit[:8]} is not present on any origin branch — "
            f"refusing to move the v1 tag to an unpushed SHA"
        )


def verify_v1_ancestor(repo: Path, new_sha: str) -> None:
    """Refuse a non-fast-forward move of the floating v1 tag.

    If v1 does not exist yet this is a first-time creation and the check is
    skipped.  Otherwise new_sha must be a descendant of the current v1 commit
    so that all @v1 consumers stay on a linear history rather than being
    silently redirected to a divergent or older commit.
    """
    try:
        current_v1 = run(["git", "rev-list", "-n1", "refs/tags/v1"], cwd=repo)
    except subprocess.CalledProcessError:
        return  # v1 doesn't exist yet; first-time creation is safe
    try:
        run(["git", "merge-base", "--is-ancestor", current_v1, new_sha], cwd=repo)
    except subprocess.CalledProcessError:
        raise ReleaseError(
            f"Current v1 ({current_v1[:8]}) is not an ancestor of new commit "
            f"{new_sha[:8]}; refusing non-fast-forward move of v1. "
            f"All @v1 consumers would be silently redirected to a different history."
        )


def update_plugin_json(version: str) -> tuple[str, str]:
    data = json.loads(PLUGIN_JSON.read_text())
    old = data["version"]
    data["version"] = version
    PLUGIN_JSON.write_text(json.dumps(data, indent=2) + "\n")
    return old, version


def update_marketplace_json(version: str, skill_count: int) -> dict[str, str]:
    data = json.loads(MARKETPLACE_JSON.read_text())
    plugin = data["plugins"][0]
    old_version = plugin["version"]
    old_desc = plugin["description"]
    plugin["version"] = version

    new_desc = re.sub(
        r"^\d+ security skills",
        f"{skill_count} security skills",
        old_desc,
    )
    plugin["description"] = new_desc
    # Pin the marketplace source to the release tag so downstream installs
    # follow maintainer-signed tags rather than main.
    source = plugin.setdefault("source", {})
    old_ref = source.get("ref")
    source["ref"] = f"v{version}"
    MARKETPLACE_JSON.write_text(json.dumps(data, indent=2) + "\n")
    return {
        "old_version": old_version,
        "new_version": version,
        "old_desc": old_desc,
        "new_desc": new_desc,
        "old_ref": old_ref or "(unset)",
        "new_ref": source["ref"],
    }


def update_action_sha(action_dir: Path, new_sha: str) -> tuple[str, str]:
    action_yml = action_dir / "action.yml"
    text = action_yml.read_text()
    m = re.search(r'SOUNDCHECK_SHA="([0-9a-f]{40})"', text)
    if not m:
        raise ReleaseError(f"Could not find SOUNDCHECK_SHA pin in {action_yml}")
    old_sha = m.group(1)
    # Guard against a duplicate SHA in the file silently producing a partial
    # or double substitution that would corrupt action.yml before commit.
    occurrences = text.count(f'SOUNDCHECK_SHA="{old_sha}"')
    if occurrences != 1:
        raise ReleaseError(
            f"Expected exactly 1 occurrence of SOUNDCHECK_SHA=\"{old_sha[:8]}...\" "
            f"in {action_yml}; found {occurrences} — refusing to write"
        )
    new_text = text.replace(
        f'SOUNDCHECK_SHA="{old_sha}"',
        f'SOUNDCHECK_SHA="{new_sha}"',
    )
    action_yml.write_text(new_text)
    return old_sha, new_sha


def plan_and_apply(args: argparse.Namespace) -> int:
    version = args.version
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ReleaseError(f"Version must look like MAJOR.MINOR.PATCH, got {version!r}")

    tag = f"v{version}"
    action_dir = args.action_dir.resolve()

    print(f"=== Release plan: soundcheck {tag} ===\n")

    require_on_main(SOUNDCHECK_DIR)
    require_clean_tree(SOUNDCHECK_DIR)
    require_on_main(action_dir)
    require_clean_tree(action_dir)
    require_valid_plugin_manifest()
    require_prerelease_checks()

    skill_count = count_skills()
    action_tag = next_action_version(action_dir)

    print(f"  soundcheck repo:      {SOUNDCHECK_DIR}")
    print(f"  soundcheck-action:    {action_dir}")
    print(f"  Skills counted:       {skill_count}")
    print(f"  New soundcheck tag:   {tag}")
    print(f"  New action tag:       {action_tag} (+ move v1)")
    print()

    # --- Step 1: edit soundcheck JSON files ---
    print("Step 1: bump plugin.json + marketplace.json")
    if args.push:
        plug_old, plug_new = update_plugin_json(version)
        mkt = update_marketplace_json(version, skill_count)
        print(f"  plugin.json: {plug_old} → {plug_new}")
        print(f"  marketplace.json: {mkt['old_version']} → {mkt['new_version']}")
        if mkt["old_desc"] != mkt["new_desc"]:
            print(f"  description: refreshed skill count to {skill_count}")
    else:
        cur_plug = json.loads(PLUGIN_JSON.read_text())["version"]
        cur_mkt = json.loads(MARKETPLACE_JSON.read_text())["plugins"][0]
        print(f"  plugin.json:      {cur_plug} → {version}")
        print(f"  marketplace.json: {cur_mkt['version']} → {version}")
        if f"{skill_count} security skills" not in cur_mkt["description"]:
            print(f"  description:      refresh skill count to {skill_count}")

    # --- Step 2: commit + tag + push soundcheck ---
    print("\nStep 2: commit, tag, push soundcheck")
    commit_msg = (
        f"Bump plugin + marketplace to v{version}\n\n"
        f"Align .claude-plugin/*.json with the {tag} release."
    )
    print(f"  git add .claude-plugin/plugin.json .claude-plugin/marketplace.json")
    print(f"  git commit -m {commit_msg.splitlines()[0]!r}")
    print(f"  git tag -a {tag}")
    print(f"  git push origin main {tag}")

    soundcheck_sha = None
    if args.push:
        run(
            ["git", "add", ".claude-plugin/plugin.json",
             ".claude-plugin/marketplace.json"],
            cwd=SOUNDCHECK_DIR,
        )
        run(["git", "commit", "-m", commit_msg], cwd=SOUNDCHECK_DIR, capture=False)
        soundcheck_sha = run(["git", "rev-parse", "HEAD"], cwd=SOUNDCHECK_DIR)
        run(
            ["git", "tag", "-a", tag, "-m", f"{tag}", soundcheck_sha],
            cwd=SOUNDCHECK_DIR,
        )
        run(["git", "push", "origin", "main"], cwd=SOUNDCHECK_DIR, capture=False)
        run(["git", "push", "origin", tag], cwd=SOUNDCHECK_DIR, capture=False)
        print(f"  pushed HEAD: {soundcheck_sha}")

    # --- Step 3: update soundcheck-action ---
    print(f"\nStep 3: bump SOUNDCHECK_SHA in {action_dir}/action.yml")
    if args.push:
        # Verify the soundcheck commit we just pushed is actually reachable
        # from origin before moving the floating v1 tag. A push that
        # succeeded locally but got rejected by the remote would otherwise
        # silently point every downstream @v1 consumer at an unreachable
        # SHA.
        verify_remote_has_commit(SOUNDCHECK_DIR, soundcheck_sha)
        old_sha, new_sha = update_action_sha(action_dir, soundcheck_sha)
        print(f"  {old_sha}\n    → {new_sha}")
    else:
        # Preview current pin
        m = re.search(
            r'SOUNDCHECK_SHA="([0-9a-f]{40})"',
            (action_dir / "action.yml").read_text(),
        )
        cur = m.group(1) if m else "?"
        print(f"  {cur}\n    → <new soundcheck HEAD after Step 2 push>")

    # --- Step 4: commit + tag + push soundcheck-action ---
    print("\nStep 4: commit, tag, move v1, push soundcheck-action")
    action_commit_msg = f"Bump soundcheck pin to v{version}"
    print(f"  git add action.yml")
    print(f"  git commit -m {action_commit_msg!r}")
    print(f"  git tag -a {action_tag}")
    print(f"  git tag -s -f v1  (signed; requires GPG key)")
    print(f"  git push origin main {action_tag}")
    print(f"  git push origin v1 --force")

    if args.push:
        run(["git", "add", "action.yml"], cwd=action_dir)
        run(["git", "commit", "-m", action_commit_msg], cwd=action_dir, capture=False)
        action_sha = run(["git", "rev-parse", "HEAD"], cwd=action_dir)
        run(
            ["git", "tag", "-a", action_tag, "-m", action_tag, action_sha],
            cwd=action_dir,
        )
        # Ancestor check: refuse to redirect @v1 consumers to a divergent or
        # older commit (integrity-failures A08:2025).
        verify_v1_ancestor(action_dir, action_sha)
        # Signed tag provides a consumer-visible integrity signal; requires
        # a GPG key configured in git (gpg.signingKey / user.signingKey).
        run(["git", "tag", "-s", "-f", "v1", action_sha, "-m", "v1"], cwd=action_dir)
        run(["git", "push", "origin", "main"], cwd=action_dir, capture=False)
        run(["git", "push", "origin", action_tag], cwd=action_dir, capture=False)
        run(["git", "push", "origin", "v1", "--force"],
            cwd=action_dir, capture=False)
        print(f"  pushed action HEAD: {action_sha}")

    # --- Done ---
    print("\n" + ("=== Released ===" if args.push else "=== Dry run complete ==="))
    if not args.push:
        print("Re-run with --push to apply.")
    else:
        print(f"soundcheck     {tag}")
        print(f"soundcheck-action {action_tag} (v1 → {action_tag})")
        print("\nCreate GitHub releases manually when ready:")
        print(f"  gh release create {tag} --repo thejefflarson/soundcheck "
              f"--title '{tag}' --notes '...'")
        print(f"  gh release create {action_tag} --repo thejefflarson/soundcheck-action "
              f"--title '{action_tag}' --notes '...'")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Cut a coordinated soundcheck release")
    parser.add_argument("version", help="New soundcheck version, e.g. 1.8.0")
    parser.add_argument(
        "--push", action="store_true",
        help="Actually apply edits, commit, tag, and push (default: dry run)",
    )
    parser.add_argument(
        "--action-dir", type=Path, default=DEFAULT_ACTION_DIR,
        help=f"Path to soundcheck-action checkout (default: {DEFAULT_ACTION_DIR})",
    )
    parser.add_argument(
        "--yes", action="store_true",
        help="Skip interactive confirmation before pushing",
    )
    args = parser.parse_args()

    try:
        if args.push and not args.yes:
            print(f"About to release soundcheck v{args.version} "
                  f"and bump soundcheck-action.")
            resp = input("Proceed? [y/N] ").strip().lower()
            if resp != "y":
                print("Aborted.")
                return 1
        return plan_and_apply(args)
    except ReleaseError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as e:
        print(f"ERROR: command failed: {e.cmd}", file=sys.stderr)
        if e.stderr:
            print(e.stderr, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
