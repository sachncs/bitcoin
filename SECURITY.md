# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this library, please report it
privately **before** disclosing it publicly.

**Do not open a public GitHub issue.** Instead, send a description of the
vulnerability (including steps to reproduce, affected versions, and any
proof-of-concept) to:

- **Primary contact:** chakravarthy1393966@gmail.com
- **Alternative:** Open a [GitHub Security Advisory][gh-advisory]

You should receive a response within **72 hours**. If you do not, please follow
up.

## What to expect

1. **Acknowledgement** — We will confirm receipt within 3 business days.
2. **Assessment** — We will triage and determine impact and priority.
3. **Fix** — A fix will be developed and tested, typically within 14 days for
   high-severity issues.
4. **Release** — A patched version will be published to PyPI.
5. **Disclosure** — We will publish a security advisory on GitHub after the fix
   is released.

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.4.x   | :white_check_mark: |
| < 0.4.0 | :x:                |

## Scope

This policy covers the `bitcoin` Python package (PyPI: [`bitcoin`][pypi]).
Vulnerabilities in **transitive dependencies** should be reported to their
respective maintainers.

[gh-advisory]: https://github.com/sachn-cs/bitcoin/security/advisories/new
[pypi]: https://pypi.org/project/bitcoin/
