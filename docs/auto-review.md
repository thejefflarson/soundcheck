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

Auto-review is **default-on**. To toggle:

- In Claude Code: `/plugin config soundcheck autoReview=false`
- Per session: export `SOUNDCHECK_AUTO_REVIEW=false` before launching
  Claude Code. The hook honors the env var directly.

The toggle is exposed via the plugin manifest's `userConfig` block, so
the value persists across sessions once set.

## Cost discipline

Per turn, in the worst case:

| Stage | Latency | Cost (approx) |
|---|---|---|
| 1 — Extension gate | ~10ms | free |
| 2 — Haiku triage | 2-3s | ~$0.001 |
| 3 — Full pr-review | 30-60s | $0.005-0.02 |

For a session with a dozen turns of code-writing, that's $0.01-0.05
end-to-end if every turn triggers stage 3 — typically far less because
most turns are conversational or non-risky and stop at stage 2.

The hook runs detached, so the user doesn't wait. Findings arrive a turn
later if stage 3 fires; otherwise they arrive in the same turn that
triggered them.

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
- `SOUNDCHECK_AUTO_REVIEW=false` or `autoReview=false` in plugin config
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
