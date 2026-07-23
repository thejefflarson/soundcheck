# Privacy

**Soundcheck does not collect any data.**

The plugin runs entirely inside your own Claude Code session or your
own CI. It has no telemetry, no crash reporting, no analytics. It does
not phone home.

## Where model calls go

Soundcheck shells out to your locally-installed `claude` CLI to invoke
Anthropic's model. That traffic is between you and Anthropic and is
governed by [Anthropic's privacy
policy](https://www.anthropic.com/legal/privacy). Soundcheck neither
proxies nor observes that traffic.

## What Soundcheck writes to disk

Only to paths inside your own repo:

- CI action audit logs and summaries (at paths you specify on the
  command line or in the workflow inputs)
- Cached benchmark data under `.securityeval-cache/`,
  `.realworld-cache/`, and `.juiceshop-benchmark/` when a maintainer
  runs the benchmark harness — all gitignored

Nothing is sent off-machine.

## When Soundcheck runs as a GitHub Action

The `soundcheck-action` GitHub Action makes outbound calls to exactly
two services:

- Anthropic's API (via `claude -p`), using the `anthropic-api-key`
  secret you provide
- GitHub's API, using the `github-token` you provide

Both are transports for behavior you explicitly configured in the
workflow. Soundcheck does not send data to any third party.

## Questions

Open an issue at
<https://github.com/thejefflarson/soundcheck/issues>.
