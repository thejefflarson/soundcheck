"""ReDoS — intentionally vulnerable. DO NOT deploy."""
import re

# BUG: nested quantifiers cause catastrophic backtracking
EMAIL_RE = re.compile(r"^([a-zA-Z0-9_.+-]+)+@([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")

def validate_email(email: str) -> bool:
    return bool(EMAIL_RE.match(email))

# BUG: overlapping alternation with repetition
SLUG_RE = re.compile(r"^([\w-]+)*$")

def validate_slug(slug: str) -> bool:
    return bool(SLUG_RE.match(slug))
