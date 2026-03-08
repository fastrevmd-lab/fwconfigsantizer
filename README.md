# Firewall Config Sanitizer

A portable, browser-based tool that sanitizes firewall configurations by replacing sensitive and identifiable information with safe placeholders. Runs 100% client-side — no data leaves your machine.

## Usage

1. Download `index.html`
2. Open it in any modern browser
3. Accept the risk disclaimer
4. Paste, upload, or drag-and-drop a firewall config
5. Toggle sanitization categories on/off as needed
6. Optionally set a **salt** for deterministic output and/or add **custom sensitive words**
7. Click **Sanitize**
8. Review the **validation warnings** for any potentially missed items
9. Use the **Diff** view to compare original vs sanitized side-by-side
10. Download the **sanitized config** (safe to share) and the **mapping file** (to restore later)

## What Gets Sanitized

Each category can be individually enabled or disabled via checkboxes before sanitizing.

| Category | Replacement |
|----------|-------------|
| Public IPs | RFC 5737 documentation IPs (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`) |
| Private IPs | Prefix-preserving `10.x.x.x` addresses |
| IPv6 addresses | RFC 3849 documentation prefix (`2001:db8::`) |
| Zone names | `zone-0`, `zone-1`, ... |
| Object / group names | `obj-0`, `obj-1`, ... |
| Passwords & hashes | `REDACTED_HASH_N` |
| Pre-shared / API keys | `REDACTED_KEY_N` |
| Usernames | `user-0`, `user-1`, ... |
| SNMP communities | `REDACTED_COMMUNITY_N` |
| Certificates | `REDACTED_CERT_N` |
| BGP AS numbers | `REDACTED_BGP_N` |
| Server hostnames | `host-N.example.net` |
| Device hostname | `sanitized-fw` |
| Domain names (FQDNs) | `example-N.net` |
| Email addresses | `user-N@example.net` |
| URLs | Domain replaced with `example-N.net`, path preserved |
| Descriptions & comments | `(sanitized)` |
| Custom words | `REDACTED_WORD_N` |

CIDR prefix lengths (e.g. `/24`, `/32`) are preserved alongside their replaced IP addresses.

## Features

- **Prefix-preserving IP anonymization** — IPs sharing a subnet stay in the same subnet after anonymization (e.g. two hosts on the same /24 remain on the same /24)
- **Deterministic salt** — provide an optional salt so the same config always produces the same output; enables processing HA pairs separately with compatible results
- **Custom sensitive word list** — add comma-separated org-specific terms (company name, city codes, project names) to redact globally
- **Drag-and-drop upload** — drop a config file directly onto the text area
- **URL sanitization** — HTTP/HTTPS/LDAP/FTP URLs have their domain replaced while preserving path and port
- **Selective sanitization** — toggle each category on/off via checkboxes
- **Diff view** — side-by-side comparison of original vs sanitized config with changed lines highlighted
- **Validation warnings** — post-sanitize scan flags potential missed items (unsanitized IPs, emails, FQDNs, password hashes)
- **Config size indicator** — shows line/size count, warns if config appears incomplete
- **Light/dark mode** — toggle in the upper right, preference persisted
- **Restore** — upload a sanitized config + mapping file to reconstruct the original

## Supported Vendors

- Cisco ASA / FTD
- Fortinet FortiGate (FortiOS)
- Palo Alto PAN-OS / Panorama
- Juniper SRX (Junos)

## Restoring a Config

1. Switch to the **Restore** tab
2. Upload the sanitized config and its `.mapping.json` file
3. Click **Restore Original Config**
4. Download the restored config

## Mapping File

The mapping file is a JSON document containing every replacement made during sanitization. Keep it secure — it contains the original sensitive values needed to reverse the sanitization. If a salt was used, it is recorded in the mapping file metadata.
