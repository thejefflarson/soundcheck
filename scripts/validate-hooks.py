#!/usr/bin/env python3
"""
Static validator for plugin hook command substitutions.

Catches the v1.12.0/1/2 class of bug where a hook command references
`${user_config.X}` but the userConfig schema either:
  - doesn't declare X at all, or
  - declares X without a `default` field.

When that happens, Claude Code's hook engine refuses to substitute the
variable and aborts the Stop/PreToolUse/etc. hook with:

    Plugin option "X" isn't set. Open /plugin manage to configure it,
    or check that the plugin's userConfig schema declares "X".

The `default` field is only consulted at enable-time prompts. Users who
installed before the default existed never get it written into their
settings.json. Even users on fresh installs hit the error if the schema
itself is missing the default. The robust fix is either:

  (a) declare every referenced option with a `default`, or
  (b) drop the substitution and read CLAUDE_PLUGIN_OPTION_<KEY> from the
      environment, which Claude Code exports for every option (set or
      not). This validator enforces (a).

Exit 0 = clean. Non-zero = at least one violation.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLUGIN_JSON = ROOT / ".claude-plugin" / "plugin.json"
HOOKS_JSON = ROOT / ".claude" / "hooks" / "hooks.json"

USER_CONFIG_REF = re.compile(r"\$\{user_config\.([A-Za-z_][A-Za-z0-9_]*)\}")


def _walk_commands(node):
    if isinstance(node, dict):
        if isinstance(node.get("command"), str):
            yield node["command"]
        for v in node.values():
            yield from _walk_commands(v)
    elif isinstance(node, list):
        for v in node:
            yield from _walk_commands(v)


def main() -> int:
    if not PLUGIN_JSON.exists():
        print(f"ERROR: {PLUGIN_JSON} not found", file=sys.stderr)
        return 1
    if not HOOKS_JSON.exists():
        print(f"no hook file at {HOOKS_JSON}; nothing to check")
        return 0

    plugin = json.loads(PLUGIN_JSON.read_text())
    hooks = json.loads(HOOKS_JSON.read_text())

    user_config = plugin.get("userConfig") or {}
    commands = list(_walk_commands(hooks))

    refs: dict[str, list[str]] = {}
    for cmd in commands:
        for key in USER_CONFIG_REF.findall(cmd):
            refs.setdefault(key, []).append(cmd)

    violations: list[str] = []
    for key, cmds in refs.items():
        opt = user_config.get(key)
        if not isinstance(opt, dict):
            violations.append(
                f"Hook command references ${{user_config.{key}}} but the "
                f"userConfig schema does not declare {key!r}. Sample: "
                f"{cmds[0]!r}"
            )
            continue
        if "default" not in opt:
            violations.append(
                f"userConfig.{key} has no `default` field. Claude Code's "
                f"hook engine will refuse to substitute "
                f"${{user_config.{key}}} for users who never explicitly "
                f"set it. Add a default to plugin.json, or drop the "
                f"substitution and read CLAUDE_PLUGIN_OPTION_{key} from "
                f"the environment instead. Sample command: {cmds[0]!r}"
            )

    if violations:
        for v in violations:
            print(f"FAIL  {v}", file=sys.stderr)
        return 1

    print(
        f"OK  {len(commands)} hook command(s), "
        f"{len(refs)} unique ${{user_config.*}} reference(s), "
        f"all declared with defaults."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
