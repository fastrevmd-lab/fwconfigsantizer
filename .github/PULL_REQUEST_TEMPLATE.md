## Summary

<!-- What does this PR do, and why? -->

## Changes

<!-- Bullet list of what changed -->

## Verification

<!-- Exact steps you ran and what you observed. "Should work" is not verification.
There is no automated test suite for this project — testing is manual in a browser
(vendor/format used, categories toggled, what you checked). If you used any tooling
(a lint script, etc.), list the exact commands too. -->

## Checklist

- [ ] Tested manually in a browser (steps above) — sanitize and, if relevant, restore, for the affected vendor(s)
- [ ] No regressions in existing sanitization categories (verified against a sample config)
- [ ] No secrets, credentials, real hostnames, serials, or real device configs in code, fixtures, or this description
- [ ] This change does **not** add any network call (`fetch`, `XMLHttpRequest`, `WebSocket`, a beacon, a form POST, a redirect, a CDN/font/script include, etc.) or any other outbound dependency. If it does, say so explicitly above — this is a design change, not a routine one, and needs explicit sign-off in review, not just a passing check.
- [ ] If this changes what a sanitization category does, the README's category table is updated to match

## Anything you're unsure about

<!-- Flag it here rather than hoping review catches it -->
