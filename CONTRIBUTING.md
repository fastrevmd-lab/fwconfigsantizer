# Contributing to Firewall Config Sanitizer

Thanks for your interest in contributing! This project is a single-file, browser-based tool with no build step or external dependencies.

## Reporting Bugs

Open a [GitHub Issue](../../issues) with:

- Steps to reproduce
- Expected vs actual behavior
- Firewall vendor/format (ASA, FTD, FortiGate, PAN-OS, SRX)
- Browser and OS

**Do not paste real firewall configs.** Use sanitized or fabricated examples.

## Submitting Pull Requests

1. Fork the repo and create a feature branch from `main`
2. Make your changes in `index.html` (the entire app lives in this single file)
3. Test manually: open `index.html` in a browser and verify sanitization works for affected vendors
4. Ensure no regressions in existing categories (paste a sample config, check output)
5. Open a PR against `main` with a clear description of what changed and why

Unless explicitly stated otherwise, contributions submitted for inclusion in this project are licensed under the [MIT License](LICENSE).

## Architecture Notes

- **Single HTML file** — all HTML, CSS, and JS live in `index.html`. No frameworks, no bundler, no npm.
- **Client-side only** — no data leaves the browser. Keep it that way.
- **No external requests** — do not add CDN links, analytics, or any network calls.

## Code Style

- Use `const` over `let` when the variable is not reassigned
- Prefer early returns over nested `if/else`
- Use descriptive variable names (no single-letter variables outside loops)
- Add JSDoc comments on exported/public functions
- Keep regex patterns well-commented — sanitization logic is inherently dense

## Testing

`test/` holds a Node regression suite that extracts the sanitizer engine from
`index.html` (unmodified) and runs it against 100 synthetic fixtures. It has
no dependencies beyond Node itself:

```
node test/run.js
```

The suite records each case's known status in `test/cases.js`; it fails the
job only when a case's actual result no longer matches that record (a
regression, or an undocumented fix that should update the record), not on
every currently-known gap. `test/` is dev tooling only — it doesn't change
`index.html` or introduce a build step for the app itself.

Beyond that, testing is manual:

1. Open `index.html` in a browser
2. Paste or upload a sample config for the vendor you're targeting
3. Enable/disable relevant sanitization categories
4. Click **Sanitize** and verify replacements are correct
5. Check the mapping file contains all expected entries
6. Test the **Restore** flow with the mapping file
7. Verify no validation warnings appear for items that should have been caught

## Security

If you find a security vulnerability (e.g., data leaking from the browser, XSS, or sensitive data persisting unexpectedly), please open a GitHub Issue or contact the maintainers directly.
