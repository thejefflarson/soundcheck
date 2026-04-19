# Smoke-Test Methodology (paired plugin vs. bare)

This doc records the design and statistical choices for
`scripts/smoke-test-skills.py`. Update it when the test changes.

## What the test measures

For each `(skill, test-case)` pair the harness runs **two** reviews of
the same intentionally-vulnerable fixture:

- **Plugin arm** — the skill's `SKILL.md` is loaded as the review
  system prompt. Simulates "Soundcheck is loaded and the skill is
  active."
- **Bare arm** — a neutral security-reviewer system prompt (no skill
  content). Simulates "Claude is doing a security review without
  Soundcheck's guidance."

A judge (Claude, sonnet by default for quality, haiku available for
speed) scores each review against the skill's `## Verification` criteria,
returning a per-criterion pass/fail. The per-arm score for a row is the
**count of criteria satisfied** (ordinal, not binary).

## Why ordinal, not binary

An earlier design ran plugin vs. bare on fresh coding tasks, with the
judge returning a binary safe/unsafe verdict. Problems:

- **Ceiling effect.** Modern Claude writes reasonably secure fresh code
  without the plugin, so most rows ended up both-safe or both-unsafe —
  very few discordant pairs, low statistical power.
- **Inconclusive dilution.** 25–30% of rows produced non-code output
  (clarifying questions, prose walkthroughs), forcing a hard "skip"
  verdict and wasting sample budget.
- **Binary is lossy.** A row where plugin caught 4/5 criteria and bare
  caught 2/5 collapses to "both unsafe" under a pass-all-or-fail binary,
  erasing a real effect.

Ordinal scoring on pre-defined criteria fixes all three: every row
contributes the same fixture-shape signal regardless of base-model
strength, every row's judgment is conditional on criteria that already
exist in the skill, and small differences accumulate into a distribution
that can be tested.

## Statistical tests

### Paired Wilcoxon signed-rank (primary inference)

For each row we compute `delta = plugin_score − bare_score`. Under H0
(no effect of the skill on criterion coverage), the distribution of
deltas is symmetric around 0. The Wilcoxon signed-rank test ranks the
non-zero `|delta_i|`, signs the ranks, and tests whether the summed
signed ranks depart from 0 more than chance.

For `n >= 10` (n = non-zero-delta rows), we use the normal
approximation with continuity correction:

```
mean = n(n+1)/4
var  = n(n+1)(2n+1)/24
z    = (|W − mean| − 0.5) / sqrt(var)
p    = 2 * (1 − Φ(z))
```

For `n < 10` we enumerate all `2^n` sign assignments and compute the
exact two-sided p-value.

### Why Wilcoxon, not t-test or McNemar

- **t-test** requires approximate normality of the delta distribution.
  Integer criterion counts on 3–5-criterion scales don't qualify.
- **McNemar** (from the old A/B design) needs binary outcomes. We have
  ordinal.
- **Sign test** on the direction of delta is simpler but throws away the
  magnitude of each difference, losing power. Wilcoxon keeps the ranks
  of the absolute differences — more sensitive when a few rows show
  big deltas and many show small ones.

### Per-row full-pass rate (descriptive)

We also report `plugin_pass / n` and `bare_pass / n`, where a row
"passes" iff **every** criterion is satisfied. This is a stricter view
than criterion-count and tracks the original smoke-test semantic. It
gives a "bar-clearing" rate rather than a "partial credit" rate.

## What we deliberately do *not* do

- **Aggregate across skills with different numbers of criteria.** Skills
  with 6 criteria produce deltas up to ±6; skills with 3 criteria cap at
  ±3. We rank absolute deltas within the Wilcoxon, which implicitly
  handles scale but doesn't explicitly normalize. Future: report a
  standardized per-skill effect size too.
- **Judge replication.** One judge call per review. Known label noise.
  A future pass could sample the judge 3× and take majority; triples
  cost, roughly halves variance.
- **Per-skill significance with multiple-comparison correction.** Each
  skill has 1–5 test cases, too few to test individually. Per-skill
  deltas are exploratory; overall test is the inferential claim.

## Inconclusive / non-code outputs

If the model returns prose instead of code or runs the CLI into an
error, the judge still scores against the criteria — a pure-prose
response generally fails most criteria, producing a legitimate low
score rather than an inconclusive skip. This is a feature: we don't
throw away rows where the skill failed to produce a meaningful review.

The only rows the harness skips from the paired comparison are
infrastructure errors (CLI crashes with no output), which abort the run
after five consecutive occurrences.

## Rerun cadence

Rerun whenever:
- A skill's `SKILL.md` is modified (especially `## Verification`).
- A test-case fixture is added or meaningfully changed.
- The `BARE_SYSTEM` prompt is changed (re-baseline).

One full run on haiku is ~2–3 hours for ~130 cases × 2 arms × 2 judge
calls. Output goes to the stdout table plus
`/tmp/soundcheck-runs/smoke-results.jsonl` (one row per test case, with
per-arm criterion lists) for post-hoc analysis.

## References

- Wilcoxon, F. (1945), *Individual comparisons by ranking methods*,
  *Biometrics Bulletin*.
- Agresti, *Categorical Data Analysis* (3rd ed.), §10 (paired ordinal
  data).
- Conover, *Practical Nonparametric Statistics* (3rd ed.), §5.7
  (Wilcoxon signed-rank).
