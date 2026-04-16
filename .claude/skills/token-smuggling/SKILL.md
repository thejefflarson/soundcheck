---
name: token-smuggling
description: Use when writing code that passes user-supplied strings to an LLM,
  constructs prompts from external data, or processes text that may contain Unicode
  control characters, homoglyphs, or invisible formatting characters.
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

Normalize and strip control characters before including user input in any prompt or
security-sensitive comparison:

```python
import unicodedata, re

def sanitize_for_prompt(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)  # resolve homoglyphs
    text = re.sub(                               # strip control/formatting chars
        r"[\u0000-\u0008\u000b\u000c\u000e-\u001f"
        r"\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]",
        "", text,
    )
    return text
```

```javascript
function sanitizeForPrompt(text) {
    return text.normalize('NFKC')
        .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]/g, '');
}
```

Rewrite the vulnerable call site in place, explain what changed, then continue.

## Verification

- [ ] User input is normalized with NFKC before inclusion in any LLM prompt
- [ ] Unicode control and invisible formatting characters are stripped before prompt construction
- [ ] Security-sensitive string comparisons (blocklists, keyword filters) run on normalized input

## References

- CWE-116 ([Improper Encoding or Escaping of Output](https://cwe.mitre.org/data/definitions/116.html))
- CWE-20 ([Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html))
- [OWASP LLM01:2025 Prompt Injection](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
