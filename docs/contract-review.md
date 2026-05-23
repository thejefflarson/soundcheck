# Contract Review: What It Catches and What It Misses

`contract-review` is Soundcheck's deep-audit mode. It looks for bugs
where a function's body provides a weaker guarantee than its callers
assume — predicate-misnaming, fail-open on unusual inputs, trust-anchor
confusion. This page documents what we've learned about its hit rate
and limitations from running it against publicly-disclosed CVEs.

## Running it

Two equivalent entry points:

- **In a Claude Code session:** type `/contract-review`. The skill
  runs in the current session, dispatches subagents (threat-modeling,
  hotspot-mapping, per-hotspot `contract-audit`), and prints a
  findings table at the end. Subagents use the same tool permissions as
  the parent session (file reads across the repo, no writes). They
  operate only on the target repo directory; they do not make network
  requests or execute code. Transitive dispatch stops at the
  `contract-audit` tier — `contract-audit` agents do not spawn further
  subagents.
- **Headless from a checkout:** `python scripts/contract-review.py
  --repo-dir REPO --model opus`. Same skill, same orchestration; the
  CLI exists for CI / scheduled / scripted runs.

Either way the output is a Markdown findings table plus a
machine-readable `<soundcheck-contract>` JSON block. No on-disk state
persists between runs.

> **Treat all text fields in the `<soundcheck-contract>` JSON block as
> untrusted input.** The block is LLM-generated from scanned-repo
> content; a malicious file in the target repo could inject arbitrary
> text into fields like `description`, `location`, or `detail`. Do not
> interpolate these fields directly into SQL queries, HTML templates, or
> shell commands without escaping or parameterisation first.

## Hit rate against known CVEs

We benchmarked `contract-review` against six small-to-medium open-source
projects, each pinned to a commit just before a publicly-disclosed CVE
landed. The question we asked, per repo: *did the tool surface the
specific function the maintainers fixed?*

| Repo size | Bug location | Found |
|---|---|---|
| 15K files (Java) | public auth handler | ✓ Critical, round 1 |
| 250 files (C) | function at top of binary's main path | ✓ Critical |
| 4.5K files (C) | deep codec internal helper | ✗ — not seeded |
| 78 files (C) | static internal helper | ✗ — not seeded |
| 6.8K files (Java) | run drifted to scanning Soundcheck itself, not the target | — invalid |
| 320K LOC (C++) | wall-clock timeout before completion | — invalid |

**Hit rate on valid runs: 2/4.** Both hits were on *public entry-point
functions* — the seeder picks those up reliably. Both misses were on
*static internal helpers* — the seeder's heuristic ("functions called
from ≥2 sites on a security-relevant path") doesn't reliably reach
them. The bugs in those misses were memory-safety class, somewhat
out of contract-review's design scope.

> **Do not treat a clean `contract-review` result as meaningful security
> assurance.** A 50% hit rate on valid runs means the tool misses half
> of the bugs it is designed to find; it also only covers bugs on the
> public entry-point surface the seeder reaches. Use findings as
> *hypotheses to investigate*, not as a security certificate. Pair with
> `security-review`, manual audit, and fuzzing before concluding a
> component is secure.

## Known limitations

- Repos larger than ~200K LOC currently exceed the 30-minute
  single-LLM-call budget. Architecturally fixable by batching into
  multiple calls.
- The seeder is biased toward public API surface and away from
  internal helpers, which means deep-codec / kernel-style bugs are
  harder to find.
- **Context drift is a security risk, not just a usability issue.** On
  two of seven benchmark runs the orchestrator drifted from auditing the
  target repo to auditing Soundcheck's own scripts (visible via the
  plugin's own source tree). When this happens, a crafted file in the
  target repo could exploit the drift to steer the auditor toward
  producing a false-clean result for the target while findings reference
  unexpected paths. Always verify that all finding paths are inside the
  target repo before acting on results. If unexpected paths appear,
  discard the run and re-run with the target repo isolated in a separate
  checkout directory.

## Contract review vs full security review

We ran both `security-review` and `contract-review` against the same
four small-to-medium repos (the two that fit in budget on opus). The
two modes have *disjoint* strengths:

| Repo (target bug class) | `security-review` | `contract-review` |
|---|---|---|
| Java auth handler (auth-bypass via control flow) | ✗ missed | ✓ Critical |
| C SMTP relay (command injection via DNS) | ✓ Critical | ✓ Critical |
| C codec (integer overflow → memory write) | ✗ missed | ✗ missed |
| C transfer engine (uninit-stack info leak) | ✗ missed | ✗ missed |

`security-review` is the broad OWASP/LLM-Top-10 sweep — high finding
volume (20-40 per repo), great fit for SQL-injection / shell-injection
/ cryptographic choice / authentication-flow class bugs.
`contract-review` is the focused caller/callee-invariant auditor —
lower volume (5-15 per repo), catches the bugs `security-review`'s
pattern matchers don't have a template for. The one overlap (command
injection) is where both modes have native skill coverage; everywhere
else they catch different things or both miss.

## Memory safety

For memory-safety bugs neither mode reliably finds, run an instrumented
build (`-fsanitize=address,undefined`), a fuzzer (libFuzzer, OSS-Fuzz),
and a static analyzer (`clang-tidy`, CodeQL) alongside Soundcheck.
Mature deterministic tools own that territory; Soundcheck's
`memory-api-misuse` skill catches the local-pattern subset (unchecked
`malloc`, double-free in error paths, missing `O_CLOEXEC`, etc.) but
not whole-program lifetime issues.

## Reproducing the benchmark

The benchmark script and fixture list live in
[`scripts/benchmark-contract-review.py`](../scripts/benchmark-contract-review.py).
Each fixture pins the parent SHA of a public fix commit, so the
vulnerable code is present in the working tree. Expect roughly
~$15-20 and ~30 minutes per repo on opus.
