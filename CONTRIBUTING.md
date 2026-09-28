# Contributing to Firewall Config Sanitizer

Thanks for your interest in contributing! This project is a single-file, browser-based tool with no build step or external dependencies — the entire app lives in `index.html`.

## Before you start

- Check open issues and PRs first — someone may already be working on it.
- For anything larger than a small fix, open an issue to discuss the approach before writing code.

## Running it locally

There is no build step and no package manager. To work on the app:

1. Clone or fork the repo.
2. Open `index.html` directly in a browser (double-click it, or open it via `file://` — no local server, no `npm install`, nothing to compile).
3. Edit `index.html` and reload the browser to see your change.

## The invariant this tool exists to guarantee

This tool's entire value proposition is that firewall config sanitization happens **100% client-side** — nothing you paste, upload, or generate here ever leaves the browser. Concretely, that means:

- No `fetch`, `XMLHttpRequest`, `WebSocket`, `sendBeacon`, or any other network call.
- No CDN-hosted scripts, fonts, or stylesheets — everything the page needs ships inline in `index.html`.
- No analytics, telemetry, or "phone home" of any kind, however well-intentioned.

**Any PR that adds a network call of any kind is a design change, not a routine change**, and must call that out explicitly in the PR description so it gets flagged in review rather than slipping through as an incidental diff. In practice this project does not expect to ever accept such a PR, but the rule exists so it gets a real conversation instead of a rubber stamp.

## Reporting bugs

Open a [GitHub Issue](../../issues) using the bug report template, with:

- Steps to reproduce
- Expected vs actual behavior
- Firewall vendor/format (ASA, FTD, FortiGate, PAN-OS, SRX, Check Point)
- Browser and OS

**Do not paste real firewall configs, hostnames, IPs, or credentials.** Use sanitized or fabricated examples.

If you've found a security vulnerability, see [Reporting a vulnerability](#reporting-a-vulnerability) below instead — do not open a public issue for it.

## Submitting pull requests

1. Fork the repo and create a feature branch from `main`.
2. Make your changes in `index.html` (the entire app lives in this single file).
3. Test manually — see [Testing](#testing) below.
4. Fill out the PR template, including what you changed and exactly how you tested it.
5. Open a PR against `main`. All contributions land as a pull request for human review; there is no direct-push path to `main`.

Unless explicitly stated otherwise, contributions submitted for inclusion in this project are licensed under the [MIT License](LICENSE).

## Review process

Every pull request goes through a security review and a code review, then an independent test run, before anything merges. Only a maintainer merges — contributors, including anyone with write access, should not merge their own PR. Deterministic code decides what gets redacted and how; nothing here should route a model's output directly into the sanitized output or the mapping file.

## Architecture notes

- **Single HTML file** — all HTML, CSS, and JS live in `index.html`. No frameworks, no bundler, no npm.
- **Client-side only** — no data leaves the browser. Keep it that way (see the invariant above).
- **No external requests** — do not add CDN links, analytics, fonts, or any network calls.

## Code style

- Use `const` over `let` when the variable is not reassigned.
- Prefer early returns over nested `if`/`else`.
- Use descriptive variable names (no single-letter variables outside loops).
- Add JSDoc comments on exported/public functions.
- Keep regex patterns well-commented — sanitization logic is inherently dense.

## Testing

There is no automated test suite; testing is manual:

1. Open `index.html` in a browser.
2. Paste or upload a sample config for the vendor you're targeting.
3. Enable/disable relevant sanitization categories.
4. Click **Sanitize** and verify replacements are correct.
5. Check the mapping file contains all expected entries.
6. Test the **Restore** flow with the mapping file.
7. Verify no validation warnings appear for items that should have been caught.

Include the exact steps you ran (vendor, categories toggled, what you checked) in the PR's Verification section — "should work" isn't verification.

## Reporting a vulnerability

Please don't open a public issue for a security vulnerability — see [SECURITY.md](SECURITY.md) for how to report one privately.

## Fixtures and test data

Never commit real device configs, hostnames, serial numbers, or credentials — synthetic or fabricated fixtures only. If you find real data already committed anywhere in this repo, don't add to it — report it privately instead (see [SECURITY.md](SECURITY.md)).
