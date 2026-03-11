# Firewall Config Sanitizer

## Project Overview
Single-file browser-based tool that sanitizes firewall configurations by replacing
sensitive/identifiable information with safe placeholders. Produces two files:
1. Sanitized config - safe to share
2. Mapping file (JSON) - used to restore original values

## Architecture
- **Single HTML file** (`index.html`) - no dependencies, no build tools
- Runs entirely client-side in the browser
- No data leaves the user's machine
- Supports: ASA, FTD, FortiGate, Palo Alto (PAN-OS), Juniper SRX

## Sanitization Categories
| Category | Replacement Style |
|----------|------------------|
| Public IPs | RFC 5737 documentation IPs (192.0.2.x, 198.51.100.x, 203.0.113.x) |
| Private IPs | Synthetic 10.x.x.x IPs |
| Zone names | zone-0, zone-1, ... |
| Object/group names | obj-0, obj-1, ... |
| Passwords/hashes | REDACTED_HASH_N |
| Pre-shared keys | REDACTED_KEY_N |
| Usernames | user-0, user-1, ... |
| SNMP communities | REDACTED_COMMUNITY_N |
| Certificates | REDACTED_CERT_N |
| BGP AS numbers | REDACTED_BGP_N |
| Server hostnames | host-N.example.net |
| System hostname | sanitized-fw |
| Descriptions/comments | (removed) |
| Domain names | example-N.net |