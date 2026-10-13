# Security Policy

## Supported versions

This is a small educational project. Only the latest code on the `main`
branch receives security fixes.

| Version | Supported |
|---|---|
| `main` (latest) | ✅ |
| Older commits | ❌ |

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, report them privately through GitHub's
[private vulnerability reporting](https://github.com/kellenjones0505/password-strength-checker/security/advisories/new)
(the **Security** tab → **Report a vulnerability**).

Please include:

- A description of the issue and its potential impact
- Steps to reproduce it (with made-up test passwords, never real ones)
- The commit or version you tested
- Any suggested fix, if you have one

## What to expect

This project is maintained by one person, so response times are best-effort:

- **Acknowledgement:** within 7 days
- **Assessment and plan:** within 14 days
- **Fix:** depends on severity; you'll be kept updated in the private report

You'll be credited in the fix unless you'd prefer to stay anonymous.

## Scope

**In scope**, for example:

- Passwords being displayed, logged, saved to disk, or otherwise leaked
- Passwords passed or exposed in ways the README says they aren't
- Vulnerabilities in dependencies (`bcrypt`) or in the CI workflow

**Out of scope** (intentional and documented):

- The use of SHA-256 on passwords in `hashing.py`. This is a deliberate
  demonstration of why fast hashes are unsuitable for password storage,
  shown alongside bcrypt.
- Limitations already listed in the README (rule-based scoring, the small
  bundled wordlist, Python's inability to wipe strings from memory).
