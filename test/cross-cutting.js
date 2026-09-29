'use strict';
// Cross-cutting (property) cases 95-100 from the MEC-6 fixture suite. Unlike
// cases 1-94, these don't check for a single leaked token: each exercises a
// property of the engine (or, for #99, of the app code that calls it, in
// index.html's UI Logic block outside the extracted engine range).
//
// Case 99 pulls the real output-filename template out of index.html via
// regex (see extractOutputFilenameTemplate() below) instead of hardcoding a
// second copy of it. A hardcoded copy re-tests itself, not the app: a
// regression in the real code wouldn't change what the case computes, so
// it'd stay PASS forever and the suite couldn't catch a regression. Reading
// the source at run time means a real change to the template changes the
// case's outcome, and a renamed/moved handler fails the extraction loudly
// instead of silently keeping the case green.
//
// Every case returns { id, group, description, expected, actualStatus, detail }.

const path = require('node:path');
const fs = require('node:fs');
const vm = require('node:vm');

const { INDEX_HTML_PATH } = require('./extract-engine');

const DEFAULT_SALT = 'h3a-fixture-salt';

function extractOutputFilenameTemplate(indexHtmlSource) {
  const m = indexHtmlSource.match(/download\(`([^`]+)`,\s*currentResult\.sanitizedText\)/);
  if (!m) {
    throw new Error(
      'case99: could not find the #dlSanitized output filename template in index.html; ' +
      'the download handler moved or was renamed -- update this extraction.'
    );
  }
  return m[1];
}

async function makeCrossCuttingCases(engine) {
  const indexHtmlSource = fs.readFileSync(INDEX_HTML_PATH, 'utf8');
  return [
    await case95(engine),
    await case96(engine),
    await case97(engine),
    await case98(engine),
    case99(indexHtmlSource),
    // case 100 (residual-original check) is computed separately in run.js,
    // since it spans the whole corpus rather than a single fixture.
  ];
}

// 95. The batch salt can't be recovered from a known-plaintext mapping entry
// within 1e6 candidates.
//
// Before this fix, batch mode fell back to `'batch-' + Date.now().toString(36)`
// and anonymizeIP was keyed by unsalted-strength FNV-1a: an attacker who knew
// roughly when a batch ran could brute-force every candidate timestamp in a
// window and recompute anonymizeIP('127.0.0.1', candidate, true) until it
// matched the mapping's known-plaintext (127.0.0.1 is present in nearly every
// firewall config). Two independent fixes close this off, and this case
// checks both:
//   (a) loopback/link-local/multicast addresses are now passed through
//       unchanged (isPassthroughIPv4), so 127.0.0.1 never appears in the
//       mapping as a known-plaintext pair at all;
//   (b) the salt itself is 32 CSPRNG bytes (randomSalt), not a narrow,
//       guessable timestamp window, and is stretched via PBKDF2 (100k
//       iterations) before use, so even a non-loopback known-plaintext pair
//       costs real, measured work per candidate rather than one cheap
//       FNV-1a evaluation.
// We don't actually run 1e6 real PBKDF2 derivations here (100k iterations
// each would take the suite well past CI's timeout) - instead we benchmark a
// small number of genuine deriveHmacKey() calls through the real engine and
// extrapolate, which is the same argument an attacker's cost model would use.
async function case95(engine) {
  // (a) loopback is a known-plaintext lever only if it survives into the map.
  const passthroughOk = engine.isPassthroughIPv4('127.0.0.1') === true;

  // (b) the salt is CSPRNG-derived, not a guessable timestamp.
  const secretSalt = engine.randomSalt();
  const saltFormatOk = /^batch-[0-9a-f]{64}$/.test(secretSalt);
  const secondSalt = engine.randomSalt();
  const distinctSalts = secretSalt !== secondSalt;

  // Benchmark real per-candidate cost (genuine PBKDF2-100000 + HMAC-SHA-256
  // through the extracted engine, no shortcuts) against a non-passthrough
  // known-plaintext IP, mirroring the review's attack shape.
  const targetIp = '203.0.113.77';
  const targetKey = await engine.deriveHmacKey(secretSalt);
  const target = await engine.anonymizeIP(targetIp, targetKey, true);

  const SAMPLE = 8;
  const oldStyleCandidates = Array.from({ length: SAMPLE }, (_, i) =>
    'batch-' + (Date.now() - i * 1000).toString(36) // the old, now-defunct guess shape
  );
  const start = process.hrtime.bigint();
  let recoveredBySample = false;
  for (const candidateSalt of oldStyleCandidates) {
    const candidateKey = await engine.deriveHmacKey(candidateSalt);
    const candidateOut = await engine.anonymizeIP(targetIp, candidateKey, true);
    if (candidateOut === target) recoveredBySample = true;
  }
  const elapsedMs = Number(process.hrtime.bigint() - start) / 1e6;
  const msPerCandidate = elapsedMs / SAMPLE;

  const BUDGET = 1_000_000;
  const extrapolatedSeconds = (msPerCandidate * BUDGET) / 1000;
  // A real attacker's 1e6-candidate sweep must take long enough to be
  // infeasible; an hour is a conservative bar given PBKDF2-100000 costs
  // roughly a handful of milliseconds per candidate on commodity hardware.
  const infeasibleWithinBudget = extrapolatedSeconds > 3600;

  const ok = passthroughOk && saltFormatOk && distinctSalts && !recoveredBySample && infeasibleWithinBudget;
  return {
    id: 95, group: 'cross-cutting', expected: 'PASS', // fixed (H3c)
    description: "The batch salt can't be recovered from a known-plaintext mapping entry within 1e6 candidates",
    actualStatus: ok ? 'PASS' : 'FAIL',
    detail: ok
      ? `loopback passthrough=${passthroughOk}, salt format=${saltFormatOk}, ~${msPerCandidate.toFixed(2)}ms/candidate -> ~${extrapolatedSeconds.toFixed(0)}s for 1e6 candidates`
      : `passthrough=${passthroughOk} saltFormat=${saltFormatOk} distinctSalts=${distinctSalts} recoveredBySample=${recoveredBySample} extrapolatedSeconds=${extrapolatedSeconds.toFixed(2)}`,
  };
}

// 96. 254 distinct public IPs -> 254 distinct placeholders.
async function case96(engine) {
  const N = 254;
  const lines = [];
  for (let i = 1; i <= N; i++) {
    // Avoid RFC 5737 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and
    // RFC 2544 (198.18.0.0/15): the engine intentionally passes those through
    // unredacted for idempotency. 100.64.0.0/10 (RFC 6598 shared address
    // space) is reserved/non-routable but not in that passthrough list, so
    // it still exercises the real distinct-placeholder path.
    lines.push(`set FAKE-HOST-${i} address 100.64.1.${i}`);
  }
  // Force vendor 'unknown' (no vendor markers) so the generic IPv4 rule runs
  // regardless of vendor gating.
  const result = await engine.sanitizeConfig(lines.join('\n') + '\n', {}, DEFAULT_SALT, []);
  const placeholders = new Set(
    result.replacements.filter((r) => r.type === 'public_ip').map((r) => r.placeholder)
  );
  const distinct = placeholders.size;
  const ok = distinct === N;
  return {
    id: 96, group: 'cross-cutting', expected: 'PASS', // fixed (H3c)
    description: '254 distinct public IPs -> 254 distinct placeholders',
    actualStatus: ok ? 'PASS' : 'FAIL',
    detail: `${distinct} distinct placeholders for ${N} distinct input IPs`,
  };
}

// 97. A domain and an unrelated URL host get distinct placeholders.
// `domains` and `urls` both mint `example-N.net`-shaped placeholders but from
// two independent, now-namespaced counters (counter.domain vs counter.url),
// so an unrelated domain and URL host can no longer collide on the same
// placeholder text.
async function case97(engine) {
  const input = 'set fqdn "fakeorg97a.example.org"\nset url "https://fakeorg97b.example.com/path"\n';
  const result = await engine.sanitizeConfig(input, {}, DEFAULT_SALT, []);
  const domainEntry = result.replacements.find((r) => r.type === 'domain');
  const urlEntry = result.replacements.find((r) => r.type === 'url');
  const distinct = Boolean(domainEntry) && Boolean(urlEntry) && domainEntry.placeholder !== urlEntry.placeholder;
  return {
    id: 97, group: 'cross-cutting', expected: 'PASS', // fixed (H3c)
    description: 'A domain and an unrelated URL host get distinct placeholders',
    actualStatus: distinct ? 'PASS' : 'FAIL',
    detail: `domain -> ${domainEntry && domainEntry.placeholder}, url -> ${urlEntry && urlEntry.placeholder}`,
  };
}

// 98. Batch mode produces validation warnings.
// sanitizeConfig now runs the validator unconditionally and returns its
// warnings on every result (single-file and batch alike), so the batch
// handler no longer has to remember to call validateSanitized separately.
// We mirror the batch handler's call shape here (per-file sanitizeConfig,
// nothing else) using only the extracted engine, and assert the aggregate
// batch result carries warnings.
async function case98(engine) {
  // The named-hash text below sits in a plain comment line, a shape none of
  // sanitizeConfig's redaction rules target (they match directive context
  // like `password "..."`, not freeform remarks), so it survives into the
  // output and validateSanitized's named-hash check should flag it.
  const files = [
    { name: 'fake-batch-98a.cfg', content: 'set snmp community FAKECOMM98A\n! residual note: $sha512$fakesalt98a$fakehash98a$\n' },
    { name: 'fake-batch-98b.cfg', content: '! residual note: $sha512$fakesalt98b$fakehash98b$\n' },
  ];
  const options = {};
  const batchSalt = 'batch-fixture-98';
  const batchResults = [];
  for (const f of files) {
    batchResults.push({ name: f.name, result: await engine.sanitizeConfig(f.content, options, batchSalt, []) });
  }
  const anyWarnings = batchResults.some(
    (r) => Array.isArray(r.result.warnings) && r.result.warnings.length > 0
  );
  return {
    id: 98, group: 'cross-cutting', expected: 'PASS', // fixed (H3c)
    description: 'Batch mode produces validation warnings',
    actualStatus: anyWarnings ? 'PASS' : 'FAIL',
    detail: anyWarnings ? 'warnings present on batch results' : 'sanitizeConfig result carries no warnings field; batch handler never calls validateSanitized',
  };
}

// 99. The output filename doesn't contain the input base name.
// Evaluates the actual filename template from index.html's #dlSanitized
// download handler (currently `config-1.sanitized.${ext}`, which
// deliberately drops the loaded filename's base name -- it's often
// identifying: hostname, site code, customer name) rather than a hardcoded
// copy, so a regression in the naming scheme changes this case's result
// instead of leaving it PASS forever.
function case99(indexHtmlSource) {
  const template = extractOutputFilenameTemplate(indexHtmlSource);
  const loadedFilename = 'FAKEHOST-fw01-99.cfg';
  const baseName = loadedFilename.replace(/\.[^.]+$/, '');
  const ext = (loadedFilename.split('.').pop() || 'txt').replace(/[^a-zA-Z0-9]/g, '') || 'txt';
  // Renders the actual template string extracted from index.html in an empty
  // vm context, with only baseName/ext in scope.
  const outputFilename = vm.runInNewContext(`\`${template}\``, { baseName, ext });
  const leaksBaseName = outputFilename.includes(baseName);
  return {
    id: 99, group: 'cross-cutting', expected: 'PASS', // fixed (H3c)
    description: "The output filename doesn't contain the input base name",
    actualStatus: leaksBaseName ? 'FAIL' : 'PASS',
    detail: `"${loadedFilename}" -> "${outputFilename}" (template from index.html: \`${template}\`)`,
  };
}

module.exports = { makeCrossCuttingCases, DEFAULT_SALT };
