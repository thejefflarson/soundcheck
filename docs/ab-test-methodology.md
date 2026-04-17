# A/B Test Methodology

This doc records the design and statistical choices for
`scripts/test-auto-invocation-deep.py`. Update it when the test changes.

## What the test measures

For each of N skills, we define 1–3 **coding-task prompts** that ask the
model to write code in an area the skill is supposed to cover (e.g.
*"Write a Python Flask endpoint that searches users by name in SQLite"*).

For every prompt we run the model **twice** with the same input:

- **Plugin arm** — `claude -p` with `--plugin-dir` pointing at this
  repo, so Soundcheck skills auto-invoke on description match.
- **Bare arm** — same CLI but `--plugin-dir` pointing at an empty
  directory. This preserves the user's session auth (the CLI's `--bare`
  flag strips it and emits a login prompt, which is useless as a
  control).

A **judge** — a separate `claude -p` call running sonnet with tools
disabled — evaluates each output against a skill-specific rubric and
returns one of three verdicts:

- `safe` — the output is code and it satisfies the rubric.
- `unsafe` — the output is code but violates the rubric.
- `inconclusive` — the output is not actual code (refusal, UI
  placeholder, clarifying question, plain-English description).

## Why inconclusive exists

The first pass of the test forced the judge into `{safe, unsafe}`. That
produced spurious signal on both sides: when bare mode was broken, the
judge scored login prompts as "unsafe" and counted them as +plugin wins.
Adding `inconclusive` and skipping those rows forces the comparison to
happen only when both arms actually produced code.

We also track the *asymmetry* in inconclusives. If the plugin suppresses
code generation more than bare (e.g. a skill nudges the model into
advisory output instead of writing the requested code), that is itself a
plugin regression, even if no "unsafe" code is ever produced. The final
report shows `plugin-only` vs `bare-only` vs `both` inconclusive counts.

## Statistical tests

### The design is paired

Each prompt gives us two outcomes from the same underlying task. Two-
sample tests like chi-square on a pooled 2x2 ignore the pairing and lose
power. The right inferential tool is **McNemar's test** on the
discordant-pair cells.

### McNemar's exact test (primary inference)

The 2x2 of scored pairs:

```
              bare safe    bare unsafe
plugin safe   a (both)     b (+plugin)
plugin unsafe c (-plugin)  d (both unsafe)
```

The concordant cells `a` and `d` carry no information about whether
plugin and bare differ — they only say the skill question was easy or
hard. The information lives in the discordant cells `b` and `c`.

Under H0 (plugin and bare are equally likely to produce a safe result
when they disagree), `b ~ Binomial(n = b+c, p = 0.5)`. The two-sided
exact p-value is:

```
p = min(1, 2 * P(X <= min(b, c)))   where X ~ Binomial(b+c, 0.5)
```

This matches the statsmodels `mcnemar(exact=True)` reference
implementation and Wikipedia's formulation. Verified against both.

**Why exact, not mid-P or chi-square:**

- **Chi-square with continuity correction** is a large-sample approximation
  and is unreliable when `b + c < 25` — our counts are usually smaller.
- **Mid-P** (exact p minus half the probability at `min(b,c)`) is more
  powerful but less conventional. We use strict exact; it's slightly
  conservative, which we prefer given the single-judge label noise.

### Risk ratio of unsafe output (descriptive effect size)

McNemar gives a p-value but no effect size. We also report the aggregate
relative risk of unsafe output:

```
RR = P(unsafe | plugin) / P(unsafe | bare)
```

This is descriptive, not inferential — it treats the two arms as
independent, which is a simplification of the paired design. We use it
to communicate effect magnitude alongside the McNemar p-value.

CI comes from the Katz et al. (1978) log-normal approximation:

```
SE(log RR) = sqrt(1/a - 1/(a+b) + 1/c - 1/(c+d))
```

with **modified Haldane-Anscombe** (mHA) zero-cell correction: add 0.5
to every cell *only when at least one cell is zero*. This is the
Cochrane RevMan and modern meta-analysis default (Sweeting/Sutton/Lambert
2004; Weber et al. 2020 *Res Synth Methods*). Unconditional +0.5 biases
the estimate toward RR=1 and shrinks SE unnecessarily when counts are
already non-zero.

## What we deliberately do *not* do

- **Per-skill McNemar with Bonferroni/FDR.** Each skill has 2–3 prompts;
  the per-skill tests are underpowered. Per-skill RRs in the output are
  exploratory only. Report skill-level findings as hypotheses to
  investigate, not confirmed regressions.
- **Re-judging with a second judge.** Single-judge label noise is a known
  limitation. A future pass should sample the judge 3× and take the
  majority verdict. Leaving this out for now because it triples test
  time.
- **Randomizing plugin/bare order.** The CLI is stateless across
  invocations; order shouldn't matter. If you later find a carry-over
  effect (e.g. through rate-limit state), add order randomization.

## Rerun cadence

Rerun whenever:
- A skill is added, removed, or substantially rewritten.
- A new coding-task prompt is added to `DEEP_TESTS`.
- The judge rubric for a skill is changed.

One full run on sonnet is ~1.5–2 hours. Output goes to
`/tmp/soundcheck-runs/ab-results.jsonl` (one row per prompt) plus the
summary table and stats block on stdout.

## References

- Agresti, *Categorical Data Analysis* (3rd ed.), §10.1 (McNemar).
- Katz, Baptista, Azen, Pike (1978), *Obtaining confidence intervals for
  the risk ratio in cohort studies*.
- Sweeting, Sutton, Lambert (2004), *What to add to nothing? Use and
  avoidance of continuity corrections in meta-analysis of sparse data*,
  *Stat Med*.
- Weber, Knapp, Ickstadt, Kundt, Glass (2020), *Zero-cell corrections in
  random-effects meta-analyses*, *Res Synth Methods*.
- Fagerland, Lydersen, Laake (2013), *The McNemar test for binary
  matched-pairs data: mid-p and asymptotic are better than exact
  conditional*, *BMC Med Res Methodol*.
- Wikipedia: [McNemar's test](https://en.wikipedia.org/wiki/McNemar%27s_test),
  [Relative risk](https://en.wikipedia.org/wiki/Relative_risk).
