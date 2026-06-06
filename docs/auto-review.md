# Auto-Review: Async PR Review on Every Turn

`autoReview` runs Soundcheck's `pr-review` skill against the working-copy
diff after every Claude Code turn, in the background, without blocking
the user. Findings surface as a system reminder on Claude's next
response, so it can fix them or push back. Enabled by default in
Soundcheck v1.12 and later.

Mechanism: a `Stop` hook with `asyncRewake: true` fires `scripts/auto-review.py`
when Claude finishes a turn. The script runs detached; on exit code 2 it
wakes Claude with stderr piped into the conversation as a system
reminder. Exit code 0 stays silent.

## Three stages before a finding reaches Claude

1. **Local file-extension gate (~10ms).** Inspects `git diff HEAD` and
   any untracked files. If no changed file matches the code-file
   allowlist (`.py`, `.go`, `.rs`, `.ts`, …, and config types like
   `.yml`/`.toml`/`.json` that can carry hardcoded secrets), the hook
   exits 0 silently. No LLM call, no cost.
2. **Haiku triage (~2-3s, ~$0.001).** One `claude -p --model haiku`
   call with the diff and a one-sentence instruction asking "does this
   diff plausibly introduce a security vulnerability? Reply YES or NO."
   If the answer is anything but "YES", exit 0 silently. Parse failures
   and timeouts also exit silently — the gate is fail-safe, not
   fail-loud.
3. **Full `pr-review` (~30-60s on haiku).** Only reached on triage YES.
   Spawns `scripts/security-review-action.py --diff-base HEAD`, which
   runs the same skill the soundcheck-action CI job uses. Findings get
   printed to stderr; the hook exits 2; Claude wakes with the table in
   its next-turn context.

Most turns terminate at stage 1 or 2, so the steady-state cost is a
fraction of a cent per turn. The expensive stage only runs when there's
something plausibly worth reviewing.

## Enabling and disabling

Auto-review is **default-on**. To disable, export
`SOUNDCHECK_AUTO_REVIEW=false` in your shell before launching Claude
Code. The hook reads the env var directly and exits silently when it
matches a truthy-false value (`false`, `0`, `no`, `off`).

Earlier versions exposed a `/plugin config soundcheck autoReview=false`
knob via the plugin manifest's `userConfig` block. We removed that path
in v1.12.4 — Claude Code does not export `CLAUDE_PLUGIN_OPTION_*` env
vars to Stop hook subprocesses for default-valued options, so the
toggle didn't work as promised. (Verified empirically with
`scripts/test-hook-env.py`.) The env-var path is deterministic and
honest.

## Cost discipline

Per turn, in the typical case:

| Stage | Latency | Cost (approx) |
|---|---|---|
| 1 — Extension gate | ~10ms | free |
| 2 — Haiku triage | ~3s warm, 30s+ cold start | ~$0.003 |
| 3 — Full pr-review | 30-60s | $0.005-0.02 |

For a session with a dozen turns of code-writing, that's ~$0.04 if
every turn triggers stage 3 — usually far less because most turns are
conversational or non-risky and stop at stage 2 (~$0.03 / 10 turns).

The triage stage's $0.003 cost is dominated by the ~30K-token cached
system prompt that `claude -p` loads on every invocation (your enabled
plugins' skills, agents, CLAUDE.md). The actual question we ask haiku
is a single sentence; the answer is one word. If you set
`ANTHROPIC_API_KEY` and modify `scripts/auto-review.py` to pass
`--bare`, triage drops to ~$0.0001 and <1s, but the OAuth path stops
working — see the auto-review.py docstring for the tradeoff.

The hook runs detached via asyncRewake, so you never wait on it.
Findings arrive a turn later if stage 3 fires; otherwise they arrive in
the same turn that triggered them.

## Testing the wire-up

Two paths:

- **`scripts/test-auto-review.py`** — fixture-based regression test.
  Creates a fresh temp git repo, writes representative diffs (clean,
  markdown-only, benign code, risky code), runs `scripts/auto-review.py
  --triage-only` against each, asserts the expected exit code. ~12s,
  ~$0.005 per run. Use after any change to the hook script or
  `auto-review.py` itself.
- **End-to-end hook lifecycle** — the test script's docstring includes
  a 5-step manual procedure: launch `claude --plugin-dir
  /path/to/soundcheck` in a throwaway repo, ask Claude to write a risky
  handler, watch the next turn for the asyncRewake system reminder.

## When it won't fire

- Working tree is clean (`git diff HEAD` returns nothing)
- No changed file matches the code-file extension allowlist
- `SOUNDCHECK_AUTO_REVIEW=false` in the shell environment
- The triage answers NO (the most common case once stages 1 and 2 pass)
- `claude` CLI is missing from `PATH` (the hook fails closed)
- `git` isn't initialized in the project directory

## Limitations and known false-negatives

- **Cross-file vulnerabilities** — the diff hands the triage only the
  changed lines, not the surrounding callers. A handler that becomes
  vulnerable because of a separate auth-middleware removal may not
  trigger stage 3 unless both edits land in the same turn.
- **Generated code** — large generated payloads (lockfiles excluded by
  extension, but big JSON/YAML configs included) can drown the triage's
  signal. The extension allowlist includes `.json`/`.yml`/`.toml` for
  secret-scanning reasons, but the triage may produce false negatives on
  giant configs.
- **Probabilistic triage** — stage 2 is an LLM call and can vary across
  runs. We accept this tradeoff because the alternative (a hand-rolled
  pattern catalog) drifts and misses novel patterns. The triage prompt
  is biased toward YES on ambiguity.

For deeper or more deterministic review, run `/security-review` manually
(full repo, design-review + attack-chain analysis, ~20 min) or use
`soundcheck-action` in CI for the same gate that runs against every PR.
