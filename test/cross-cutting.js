'use strict';
// Cross-cutting (property) cases 95-100 from the MEC-6 fixture suite. Unlike
// cases 1-94, these don't check for a single leaked token: each exercises a
// property of the engine (or, for #98, of the app code that calls it).
//
// Every case returns { id, group, description, expected, actualStatus, detail }.

const path = require('node:path');
const fs = require('node:fs');

const DEFAULT_SALT = 'h3a-fixture-salt';

function makeCrossCuttingCases(engine) {
  return [
    case95(engine),
    case96(engine),
    case97(engine),
    case98(engine),
    case99(),
    // case 100 (residual-original check) is computed separately in run.js,
    // since it spans the whole corpus rather than a single fixture.
  ];
}

// 95. The batch salt can't be recovered from the 127.0.0.1 mapping within 1e6 candidates.
//
// Batch mode falls back to `'batch-' + Date.now().toString(36)` when no salt
// is supplied (index.html ~3681). fnv1a is unsalted-strength: an attacker who
// knows roughly when a batch ran can brute-force every candidate timestamp in
// a window and recompute anonymizeIP('127.0.0.1', candidate, true) until it
// matches the mapping's known-plaintext (127.0.0.1 is present in nearly every
// firewall config).
function case95(engine) {
  const secretTimestamp = Date.now() - 90_000; // "unknown" run time, within the search window
  const secretSalt = 'batch-' + secretTimestamp.toString(36);
  const target = engine.anonymizeIP('127.0.0.1', secretSalt, true);

  const BUDGET = 1_000_000;
  const halfWindowMs = Math.floor(BUDGET / 2);
  let found = -1;
  for (let delta = 0; delta <= halfWindowMs && found === -1; delta++) {
    for (const candidateTs of [secretTimestamp + delta, secretTimestamp - delta]) {
      const candidateSalt = 'batch-' + candidateTs.toString(36);
      if (engine.anonymizeIP('127.0.0.1', candidateSalt, true) === target) {
        found = Math.abs(delta) * 2; // approx candidates tried
        break;
      }
    }
  }

  const recovered = found !== -1 && found <= BUDGET;
  return {
    id: 95, group: 'cross-cutting', expected: 'FAIL',
    description: "The batch salt can't be recovered from the 127.0.0.1 mapping within 1e6 candidates",
    // Property under test is "cannot be recovered"; recovered=true means the property is violated.
    actualStatus: recovered ? 'FAIL' : 'PASS',
    detail: recovered ? `recovered within ~${found} candidates` : 'not recovered within budget',
  };
}

// 96. 254 distinct public IPs -> 254 distinct placeholders.
function case96(engine) {
  const N = 254;
  const lines = [];
  for (let i = 1; i <= N; i++) {
    lines.push(`set FAKE-HOST-${i} address 192.0.2.${i}`);
  }
  // Force vendor 'unknown' (no vendor markers) so the generic IPv4 rule runs
  // regardless of vendor gating.
  const result = engine.sanitizeConfig(lines.join('\n') + '\n', {}, DEFAULT_SALT, []);
  const placeholders = new Set(
    result.replacements.filter((r) => r.type === 'public_ip').map((r) => r.placeholder)
  );
  const distinct = placeholders.size;
  const ok = distinct === N;
  return {
    id: 96, group: 'cross-cutting', expected: 'FAIL',
    description: '254 distinct public IPs -> 254 distinct placeholders',
    actualStatus: ok ? 'PASS' : 'FAIL',
    detail: `${distinct} distinct placeholders for ${N} distinct input IPs`,
  };
}

// 97. A domain and an unrelated URL host get distinct placeholders.
// `domains` and `urls` both mint `example-N.net` placeholders but from two
// independent counters (counter.domain vs counter.url), so an unrelated
// domain and URL host can collide on the same placeholder text.
function case97(engine) {
  const input = 'set fqdn "fakeorg97a.example.org"\nset url "https://fakeorg97b.example.com/path"\n';
  const result = engine.sanitizeConfig(input, {}, DEFAULT_SALT, []);
  const domainEntry = result.replacements.find((r) => r.type === 'domain');
  const urlEntry = result.replacements.find((r) => r.type === 'url');
  const distinct = Boolean(domainEntry) && Boolean(urlEntry) && domainEntry.placeholder !== urlEntry.placeholder;
  return {
    id: 97, group: 'cross-cutting', expected: 'FAIL',
    description: 'A domain and an unrelated URL host get distinct placeholders',
    actualStatus: distinct ? 'PASS' : 'FAIL',
    detail: `domain -> ${domainEntry && domainEntry.placeholder}, url -> ${urlEntry && urlEntry.placeholder}`,
  };
}

// 98. Batch mode produces validation warnings.
// The batch handler (index.html, $('#batchSanitizeBtn') listener) calls only
// sanitizeConfig per file; it never calls validateSanitized. We mirror that
// exact call shape here (per-file sanitizeConfig, nothing else) using only
// the extracted engine, and assert the aggregate batch result carries
// warnings.
function case98(engine) {
  const files = [
    { name: 'fake-batch-98a.cfg', content: 'set snmp community FAKECOMM98A\n192.0.2.201 public leftover\n' },
    { name: 'fake-batch-98b.cfg', content: '203.0.113.201 another public leftover\n' },
  ];
  const options = {};
  const batchSalt = 'batch-fixture-98';
  const batchResults = files.map((f) => ({
    name: f.name,
    result: engine.sanitizeConfig(f.content, options, batchSalt, []),
  }));
  const anyWarnings = batchResults.some(
    (r) => Array.isArray(r.result.warnings) && r.result.warnings.length > 0
  );
  return {
    id: 98, group: 'cross-cutting', expected: 'FAIL',
    description: 'Batch mode produces validation warnings',
    actualStatus: anyWarnings ? 'PASS' : 'FAIL',
    detail: anyWarnings ? 'warnings present on batch results' : 'sanitizeConfig result carries no warnings field; batch handler never calls validateSanitized',
  };
}

// 99. The output filename doesn't contain the input base name.
// Mirrors the exact derivation at index.html's dlSanitized/batch download
// handlers: `${baseName}.sanitized.${ext}` where baseName is the loaded
// filename minus its extension.
function case99() {
  const loadedFilename = 'FAKEHOST-fw01-99.cfg';
  const ext = loadedFilename.split('.').pop();
  const baseName = loadedFilename.replace(/\.[^.]+$/, '');
  const outputFilename = `${baseName}.sanitized.${ext}`;
  const leaksBaseName = outputFilename.includes(baseName);
  return {
    id: 99, group: 'cross-cutting', expected: 'FAIL',
    description: "The output filename doesn't contain the input base name",
    actualStatus: leaksBaseName ? 'FAIL' : 'PASS',
    detail: `"${loadedFilename}" -> "${outputFilename}"`,
  };
}

module.exports = { makeCrossCuttingCases, DEFAULT_SALT };
