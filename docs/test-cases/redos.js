// ReDoS — intentionally vulnerable. DO NOT deploy.

// BUG: nested quantifiers cause catastrophic backtracking
const EMAIL_RE = /^([a-zA-Z0-9_.+-]+)+@([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/;

// BUG: overlapping alternation
const SLUG_RE = /^([\w-]+)*$/;

function validateEmail(input) {
  return EMAIL_RE.test(input); // hangs on "aaa...@" with no domain
}

function validateSlug(input) {
  return SLUG_RE.test(input); // hangs on "aaa...!"
}

module.exports = { validateEmail, validateSlug };
