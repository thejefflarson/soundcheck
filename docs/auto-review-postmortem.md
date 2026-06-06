# Auto-Review Postmortem (v1.12.0 → v1.12.8)

Soundcheck's async auto-review hook took **eight releases** to actually deliver a
single finding to Claude. Every individual fix was small. The cumulative debugging
loop was not. This document captures what each bug was, how we found it, and why
we didn't catch it sooner — institutional memory for the next time we ship a hook.

## What we were building

A Stop hook that fires after every Claude Code turn, runs the `pr-review` skill
against the working-copy diff in the background, and surfaces findings as a system
reminder on the next user turn — without blocking the user. Mechanism: Claude
Code's `asyncRewake: true` hook field. On exit code 2, the hook's stderr surfaces
as a system reminder.

The pipeline as designed:

1. **Stage 1 — local file-extension gate.** `git diff HEAD` + `ls-files --others`,
   filter by code-file extension. ~10ms.
2. **Stage 2 — haiku triage.** One `claude -p --model haiku` call asking "does
   this diff need a security review?" (~3s warm). Single-word YES/NO answer.
3. **Stage 3 — full pr-review.** On YES, spawn `security-review-action.py` against
   the file list. ~30-60s.
4. **Surface.** On findings, print to stderr + exit 2 → asyncRewake wakes Claude.

Reality vs. design: every single layer broke, and most failures were silent.

## The bugs, in order shipped

### v1.12.0 → v1.12.1 — `agents` manifest field shape

**Symptom.** `/plugin` rejected the manifest with `Plugin … has an invalid manifest
file`. Plugin wouldn't load at all.

**Cause.** `plugin.json` declared `"agents": "./.claude/agents"` (a directory path).
The schema accepts only file paths or arrays of file paths — `agents` *replaces*
the default `agents/` folder, unlike `skills` which *adds to* it.

**How we missed it.** `claude plugin validate` against the directory containing
both `plugin.json` and `marketplace.json` validates `marketplace.json` and silently
skips the plugin manifest. Only pointing the validator at `plugin.json` directly
surfaces the error.

**Lesson.** Validators that pick which file to check based on directory contents
are an attractive nuisance. We later added `Dockerfile.plugin-test` to run
validation in a hermetic container as a CI gate.

### v1.12.2 → v1.12.4 — `userConfig` schema didn't do what we thought

**Symptom.** Stop hook errored on every turn with
`Plugin option "autoReview" isn't set`.

**Cause chain.** Three releases in three iterations of getting this wrong:

1. **v1.12.2** added `"default": true` to the `autoReview` userConfig entry.
   Assumed (from the docs) that `default` would populate the option for users
   who hadn't been prompted. It doesn't — `default` only applies *during* the
   enable-time prompt. Users who installed earlier still had nothing in
   `settings.json`.
2. **v1.12.3** removed the `${user_config.autoReview}` substitution from the
   hook command, switched the script to read `CLAUDE_PLUGIN_OPTION_autoReview`
   from the environment. Documented as "Claude Code exports every option as
   an env var to plugin subprocesses."
3. **v1.12.4** — empirical test (`scripts/test-hook-env.py`) ran a real
   `claude -p` session against a throwaway plugin and dumped the Stop hook's
   env. Only `CLAUDE_PLUGIN_ROOT` and `CLAUDE_PLUGIN_DATA` are exported.
   `CLAUDE_PLUGIN_OPTION_*` is **not** populated for default-valued options.
   The docs are misleading. Removed the `userConfig` block entirely;
   `SOUNDCHECK_AUTO_REVIEW=false` in the shell is now the only disable knob.

**How we missed it.** We trusted the docs without empirically testing the
contract. The test we eventually wrote (`scripts/test-hook-env.py`) is now part
of the repo and can be re-run if Claude Code's contract changes.

**Lesson.** When a feature requires multiple subsystem behaviors to compose
(prompt-time default → settings.json persistence → subprocess env export), build
a real end-to-end test before shipping.

### v1.12.5 — Triage timeout too tight

**Symptom.** Three sessions, dozens of hook fires, zero findings. The script
exited 0 silently every time.

**Cause.** `auto-review.py._triage()` had a 60s timeout on the `claude -p` call.
Live measurement showed `claude -p --model haiku` takes **30-110s on cold start**
in a fully-plugged Claude Code session (10+ plugins, ~30K cached tokens of system
prompt). Every triage call hit the deadline and returned False (fail-safe).
Script returned 0 silently. Cumulative: 75 firings across one session, no
findings.

**Why claude -p is so slow.** Stream-json output revealed each call costs
~$0.003 warm and ~$0.017 cold, with 30K input tokens dominated by plugin /
skill / CLAUDE.md context that gets reloaded every invocation. The `--bare`
flag bypasses plugin sync but requires `ANTHROPIC_API_KEY` (the OAuth path is
not read in bare mode) — a non-starter for default-on behavior.

**How we missed it.** We benchmarked `claude -p` against a clean prompt before
shipping. We did not benchmark it from inside a Stop hook subprocess in a
fully-plugged session. The cold-start cost only manifests in the production
shape.

**Lesson.** Benchmark in the shape the code will actually run, not in the
shape that's easy to measure. Removed the timeout entirely — asyncRewake runs
the script detached, so a slow triage cannot block the user. If `claude -p`
hangs forever, the kernel still releases resources when the session exits.

### v1.12.6 — Three bugs in one release

After v1.12.5 the hook was loaded into a fresh session and finally produced
real-world telemetry. Three problems stacked:

#### Bug 6a — `--diff-base HEAD` excludes untracked files

**Symptom.** Stage 3 spawned, ran for milliseconds, printed
`"No changed files. Nothing to review."` Always.

**Cause.** `security-review-action.py` resolves files via `git diff --name-only
--diff-filter=ACMR HEAD`, which lists modified/added/copied/renamed tracked
files. **Untracked files are not in `git diff HEAD`.** Most of what Claude
writes — brand-new files — never reached pr-review. The hook was structurally
incapable of reviewing new files.

**Fix.** Added `--files PATH...` to `security-review-action.py` as an
alternative to `--diff-base`. `auto-review.py` now passes the file list it
gathered during Stage 1 (modified + untracked, identified at hook-fire time)
directly to pr-review. No git-state mutation. No race against the working tree
changing mid-review.

**Considered and rejected.** First attempt was `git add -N` to mark untracked
files as intent-to-add before invoking pr-review, then `git reset HEAD` after.
That would have raced against any concurrent git operation in the user's
session. The `--files` mode is race-free.

#### Bug 6b — No debounce, process explosion

**Symptom.** User killed "a ton of claude instances" mid-session. `pgrep`
showed five concurrent `auto-review.py` processes, each holding a hung
`claude -p` triage call.

**Cause.** asyncRewake fires the hook on **every Stop** with no deduplication.
A fast conversation (many short turns) stacks N concurrent triage chains
competing for the same rate limit. Slow triage calls don't time out (we
removed the timeout in v1.12.5) so they accumulate.

**Fix.** Single-flight `fcntl.flock(EX|NB)` lock per project under
`$CLAUDE_PLUGIN_DATA/auto-review-<project-hash>.lock`. If another fire for the
same project is in flight, the new one exits 0 silently. Lock release is
belt-and-suspenders:

- Normal/exception path: `try/finally` calls `LOCK_UN` + `close`.
- Crash/SIGKILL: kernel closes FDs during teardown → flock auto-releases.
- Reboot: in-memory lock table is gone; the on-disk file is harmless.

**Considered and rejected.** Using Python GC to release the lock. Decided that
explicit `try/finally` is the right default — GC ordering is not part of the
contract, and the lock is a system resource.

#### Bug 6c — Same diff reviewed repeatedly

**Symptom.** Stop fires after a turn where Claude wrote nothing new, but the
hook ran the full pipeline anyway. Wasted ~$0.02 per redundant fire.

**Fix.** Diff-state cache. Hash `(sorted(files) + "\n---\n" + content)`,
store in `$CLAUDE_PLUGIN_DATA/auto-review-<project-hash>.state.json` with a
timestamp. Skip if the same hash has been reviewed within 24h. Record after
any of: triage NO, pr-review with no findings, pr-review with findings.
Prune entries older than TTL on every write.

### v1.12.7 — `security-review-action.py` preflight timeout

**Symptom.** v1.12.6 fixed three real bugs, the chain finally ran end-to-end…
and still produced no findings.

Direct invocation:

```
rc=2 wallclock=30s
ERROR: claude preflight failed for model='haiku': claude timed out after 30s
```

**Cause.** `security-review-action.py` runs a 30s "liveness" preflight call
(`preflight_claude` in `_claude_cli.py`) before the real review. It was added
to fast-fail on misconfigured Bedrock/Vertex setups in CI. From inside the
auto-review subprocess, the preflight hits cold-start plugin load (same
30-110s as the triage in v1.12.5) and times out. The script exits 2 without
printing `<soundcheck-findings>`, `auto-review.py` captures empty stdout,
returns 0 silently.

**Fix.** Added `--no-preflight` to `security-review-action.py`. The
auto-review hook passes it. CI callers still get fast-fail preflight; the hook
opts out because it already verified the CLI works seconds earlier (the
triage call itself was a successful `claude -p` invocation).

**How we missed it.** Preflight was added defensively for a different
deployment scenario (CI on Bedrock/Vertex). We didn't think to test whether
the timeout was sane from inside another Claude Code subprocess. The same
plugin-load latency that bit us in v1.12.5 bit us again here through a
different code path.

**Lesson.** "Add a defensive check" is a common reflex but the timeouts and
fallbacks need to be sized for the actual call shape. A 30s preflight is
plenty for the originally-intended use (CI startup); it's catastrophic from
inside a hook in a fully-plugged session.

### v1.12.8 — Hidden contract: `<soundcheck-findings>` tag

**Symptom.** v1.12.7 fixed the preflight. The chain ran end-to-end. Direct
invocation showed `security-review-action.py` returning a beautiful Markdown
findings table for a Critical shell-injection at `app.py:11`. `rc=1` (the
documented "Critical/High findings" exit code). Still no asyncRewake
delivered.

**Cause.** `auto-review.py` was scraping stdout for a `<soundcheck-findings>`
machine-readable tag that the current pr-review skill no longer emits. The
check was:

```python
if "<soundcheck-findings>[]" in out or "<soundcheck-findings>" not in out:
    return 0
```

So whether the output had `[]` (empty findings) or no tag at all (parse
failure), the script returned 0 silently. Real findings, never the tag, always
silent exit.

**Fix.** Trust the documented exit-code contract of `security-review-action.py`:

| rc | meaning |
|----|---------|
| 0  | clean (no Critical/High findings) |
| 1  | Critical/High findings present |
| 2  | infrastructure error |

`auto-review.py` now checks `proc.returncode == 1`. Full Markdown findings
table from stdout still goes to stderr for Claude to read on the asyncRewake
wake-up.

**How we missed it.** When the pipeline shipped, the pr-review skill emitted
both a human-readable table and a `<soundcheck-findings>` JSON block. The
block was removed in a later skill revision because nothing was parsing it.
`auto-review.py` was written assuming the block existed. The two sides drifted
without anyone connecting them.

**Lesson.** Hidden contracts between sibling components are time bombs.
Either codify the contract (a test that asserts the format) or remove the
dependency (use the documented public surface — in this case, the exit code).

## Aggregate lessons

1. **Validate end-to-end early.** We could have caught most of v1.12.0–v1.12.4
   with a single test that installed the plugin in a hermetic container and
   verified the hook fires + delivers a finding for a known-vulnerable fixture.
2. **Measure in the shape of production.** Cold-start `claude -p` latency from
   inside a fully-plugged subprocess is fundamentally different from clean
   measurement, and most of our bugs reduced to this asymmetry.
3. **Silent failures are worse than loud failures.** Every release shipped a
   path that returned 0 on a failure mode we didn't know existed. If
   `auto-review.py` had logged a single line "no findings tag in output"
   when it hit that branch, v1.12.8 would have been v1.12.0.5.
4. **asyncRewake hides bugs by design.** The whole point is "don't bother the
   user." That makes the failure mode invisible to the user too. Add
   observability *for the maintainer* (a debug log, a counter, anything) on
   any background hook.
5. **Hidden contracts are the most expensive bugs.** v1.12.8 was a single line.
   The bug existed because two sibling files made compatible assumptions
   nobody had written down. The fix was to remove the assumption entirely
   and lean on a documented contract (exit code).

## Current state (v1.12.8)

The pipeline is correct end-to-end. The script:

1. Acquires a per-project flock or exits 0.
2. Gathers modified + untracked code files. Hashes content. Skips if cached.
3. Runs `claude -p --model haiku` triage. Silent on NO.
4. Runs `security-review-action.py --files X --no-preflight --model haiku`.
5. Records the content hash regardless of outcome.
6. If `rc == 1`, surfaces the Markdown findings table to stderr and exits 2;
   asyncRewake wakes Claude with the table as a system reminder.

The remaining structural limitations are documented in
`docs/auto-review.md`:

- Cold-start latency dominates (~30-110s first triage per session). The
  `--bare` + `ANTHROPIC_API_KEY` mitigation is not default because it breaks
  OAuth.
- Per-call cost is ~$0.003 warm, ~$0.017 cold — about 17× our original docs
  claim before measurement.
- No diff-state tracking *across* projects; each repo has its own cache.
