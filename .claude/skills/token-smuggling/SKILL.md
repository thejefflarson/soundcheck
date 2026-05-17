---
name: token-smuggling
description: Detects user input passed to LLMs without Unicode normalization, allowing RTL
  overrides, zero-width joiners, and homoglyph attacks. Use when writing code
  that passes user-supplied strings to an LLM, constructs prompts from
  external data, or processes text that may contain Unicode control
  characters, homoglyphs, or invisible formatting characters.
---

# Token Smuggling / Unicode Injection (LLM01:2025)

## What this checks

Detects user input passed to LLMs without Unicode normalization. Attackers embed RTL
override characters, zero-width joiners, or homoglyphs to manipulate prompt structure,
bypass keyword filters, or make malicious instructions appear legitimate.

## Vulnerable patterns

- `f"Summarize this review: {user_review}"` — review may contain `\u202e` (RTL override) that reorders displayed instruction text
- Homoglyph bypass: `"раypal.com"` (Cyrillic 'р') passes a blocklist that checks for `"paypal.com"`
- Zero-width characters (`\u200b`, `\u200c`) hidden in user input that split tokens and evade content filters

## Fix immediately

Flag the vulnerable code and explain the risk. Then suggest a fix that establishes
these properties:

1. **User input is NFKC-normalized before it reaches any prompt or blocklist
   comparison.** NFKC collapses compatibility forms and canonical equivalents,
   so Cyrillic homoglyphs, fullwidth digits, and ligatures fold to their ASCII
   counterparts. Normalization runs once, at the trust boundary — not scattered
   per call site.
2. **Unicode control and invisible formatting characters are stripped after
   normalization.** Bidirectional overrides (`\u202a`–`\u202e`), zero-width
   space/joiner (`\u200b`–`\u200d`), word joiner (`\u2060`), and BOM (`\ufeff`)
   don't survive into the prompt. These are the tokens attackers use to hide
   instructions or split keywords.
3. **Security-sensitive comparisons (blocklists, keyword filters, domain
   allowlists) run on normalized input**, not on the raw bytes. A filter that
   checks for `"paypal.com"` but the comparison runs on pre-normalized text
   lets `раypal.com` pass.
4. **The same helper runs on every ingress path** — direct user input,
   retrieved RAG content, tool outputs. Attackers move the payload wherever the
   sanitizer doesn't run.

Anchor — shape, not implementation:

```
def sanitize(text):
    text = unicode_normalize(text, "NFKC")              # fold homoglyphs
    text = strip(text, BIDI_AND_INVISIBLE_RANGES)        # drop zero-width, RTL
    return text

safe = sanitize(user_input)                              # before prompt / filter
```

## Verification

- [ ] User input is normalized with NFKC before inclusion in any LLM prompt
- [ ] Unicode control and invisible formatting characters are stripped before prompt construction
- [ ] Security-sensitive string comparisons (blocklists, keyword filters) run on normalized input

## References

- CWE-116 ([Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html))
- CWE-20 ([Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html))
- [OWASP LLM01:2025 Prompt Injection](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
