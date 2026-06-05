#!/usr/bin/env python3
"""Hermetic end-to-end test of userConfig env-var exports.

The v1.12.3 fix assumes Claude Code exports each userConfig option as
``CLAUDE_PLUGIN_OPTION_<KEY>`` to plugin subprocesses, even when the
user has never explicitly set the option (the schema's ``default``
should fill in). This test verifies that assumption end-to-end by
running a real ``claude -p`` session against a throwaway plugin whose
Stop hook dumps its environment to a file.

Test matrix:

  case A — no settings.json   → assert env var exists, value == default
  case B — autoReview = true   → assert env var value == "true"
  case C — autoReview = false  → assert env var value == "false"

If case A fails, v1.12.3 cannot read the userConfig default at all and
needs another fix. Cases B and C verify the opt-in / opt-out path works
through ``/plugin config`` settings.

Requires either ANTHROPIC_API_KEY in env or 1Password ``op`` on PATH
with an ``ANTHROPIC_API_KEY`` item.

Usage:
    python scripts/test-hook-env.py
    python scripts/test-hook-env.py --verbose
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PLUGIN_NAME = "auto-review-env-test"


def get_api_key() -> str | None:
    if os.environ.get("ANTHROPIC_API_KEY"):
        return os.environ["ANTHROPIC_API_KEY"]
    if not shutil.which("op"):
        return None
    r = subprocess.run(
        ["op", "item", "get", "ANTHROPIC_API_KEY",
         "--reveal", "--fields", "credential"],
        capture_output=True, text=True,
    )
    if r.returncode == 0 and r.stdout.strip():
        return r.stdout.strip()
    return None


def build_temp_plugin(plugin_dir: Path, dump_path: Path) -> None:
    """Minimal plugin: matches soundcheck's userConfig shape, Stop hook
    dumps env to dump_path."""
    (plugin_dir / ".claude-plugin").mkdir(parents=True)
    (plugin_dir / ".claude-plugin" / "plugin.json").write_text(json.dumps({
        "name": PLUGIN_NAME,
        "version": "0.0.1",
        "description": "Test plugin for hook env-var contract",
        "userConfig": {
            "autoReview": {
                "type": "boolean",
                "title": "Auto-review",
                "description": "Test option",
                "default": True,
            }
        },
        "hooks": "./.claude/hooks/hooks.json",
    }, indent=2))
    hooks_dir = plugin_dir / ".claude" / "hooks"
    hooks_dir.mkdir(parents=True)
    (hooks_dir / "hooks.json").write_text(json.dumps({
        "hooks": {
            "Stop": [{
                "hooks": [{
                    "type": "command",
                    "command": f"env > {dump_path}",
                }]
            }]
        }
    }, indent=2))


def write_settings(home: Path, plugin_options: dict | None) -> None:
    """Stage a ~/.claude/settings.json that pre-sets userConfig options.

    A None plugin_options means "no settings.json at all" — exercises the
    cold-install path where the user has never seen the enable prompt.
    """
    claude_dir = home / ".claude"
    claude_dir.mkdir(parents=True, exist_ok=True)
    settings_path = claude_dir / "settings.json"
    if plugin_options is None:
        if settings_path.exists():
            settings_path.unlink()
        return
    settings_path.write_text(json.dumps({
        "pluginConfigs": {
            PLUGIN_NAME: {"options": plugin_options}
        }
    }, indent=2))


def run_claude(plugin_dir: Path, home: Path, api_key: str,
               verbose: bool) -> tuple[int, str, str]:
    env = {
        **os.environ,
        "ANTHROPIC_API_KEY": api_key,
        "HOME": str(home),
    }
    r = subprocess.run(
        ["claude", "-p", "--plugin-dir", str(plugin_dir), "say hi"],
        env=env, capture_output=True, text=True, timeout=180,
    )
    if verbose:
        print(f"    claude exit={r.returncode}")
        if r.stderr:
            print(f"    stderr: {r.stderr.rstrip()[:400]}")
    return r.returncode, r.stdout, r.stderr


def parse_env(dump: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in dump.read_text().splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            out[k] = v
    return out


def find_autoreview_var(env: dict[str, str]) -> tuple[str, str] | None:
    """Return (key, value) for whichever casing/spelling Claude Code uses."""
    needles = ["autoReview", "AUTOREVIEW", "AUTO_REVIEW", "autoreview"]
    for k, v in env.items():
        if not k.startswith("CLAUDE_PLUGIN_OPTION"):
            continue
        for needle in needles:
            if needle in k:
                return k, v
    return None


def run_case(name: str, plugin_options: dict | None, expected_value: str,
             tmp: Path, api_key: str, verbose: bool) -> bool:
    print(f"\n=== {name} ===")
    if plugin_options is None:
        print("    settings.json: <absent>")
    else:
        print(f"    settings.json: pluginConfigs.{PLUGIN_NAME}.options="
              f"{json.dumps(plugin_options)}")

    plugin_dir = tmp / f"plugin-{name}"
    home = tmp / f"home-{name}"
    dump = tmp / f"env-{name}.dump"
    if plugin_dir.exists():
        shutil.rmtree(plugin_dir)
    if home.exists():
        shutil.rmtree(home)
    plugin_dir.mkdir()
    home.mkdir()

    build_temp_plugin(plugin_dir, dump)
    write_settings(home, plugin_options)
    rc, _, stderr = run_claude(plugin_dir, home, api_key, verbose)

    if not dump.exists():
        print(f"    FAIL  Stop hook did not fire (claude exit={rc})")
        if stderr and verbose is False:
            print(f"    stderr tail: {stderr.rstrip()[-300:]}")
        return False

    env = parse_env(dump)
    plugin_opts = {k: v for k, v in env.items()
                   if k.startswith("CLAUDE_PLUGIN_OPTION")}
    if verbose:
        if plugin_opts:
            print("    CLAUDE_PLUGIN_OPTION_* vars seen:")
            for k, v in plugin_opts.items():
                print(f"      {k}={v}")
        else:
            print("    (no CLAUDE_PLUGIN_OPTION_* vars in env)")

    hit = find_autoreview_var(env)
    if hit is None:
        print(f"    FAIL  no CLAUDE_PLUGIN_OPTION_* variant for autoReview")
        return False

    key, value = hit
    if value != expected_value:
        print(f"    FAIL  {key}={value!r}, expected {expected_value!r}")
        return False
    print(f"    PASS  {key}={value!r}")
    return True


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    api_key = get_api_key()
    if not api_key:
        print("ERROR: ANTHROPIC_API_KEY not in env and `op` failed.",
              file=sys.stderr)
        return 2

    tmp = Path(tempfile.mkdtemp(prefix="hook-env-test-"))
    try:
        results = [
            run_case("A_no_settings", None, "true", tmp, api_key, args.verbose),
            run_case("B_explicit_true", {"autoReview": True}, "true", tmp,
                     api_key, args.verbose),
            run_case("C_explicit_false", {"autoReview": False}, "false", tmp,
                     api_key, args.verbose),
        ]
        passed = sum(results)
        total = len(results)
        print()
        print(f"Results: {passed}/{total} cases passed")
        return 0 if passed == total else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
