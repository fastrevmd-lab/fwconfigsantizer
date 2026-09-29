'use strict';
// Cross-cutting (property) cases 95-100 from the MEC-6 fixture suite. Unlike
// cases 1-94, these don't check for a single leaked token: each exercises a
// property of the engine (or, for #95/#98/#99, of the app code that calls
// it, in index.html's UI Logic block outside the extracted engine range).
//
// Cases 95, 98 and 99 pull the real expression/handler text they exercise
// out of index.html via regex (see extract*() below) instead of hardcoding
// a second copy of it. A hardcoded copy re-tests itself, not the app: an
// H3b/H3c fix to the real code wouldn't change what these cases compute, so
// they'd stay FAIL forever and the suite couldn't measure the fix. Reading
// the source at run time means a real fix changes the case's outcome, and a
// renamed/moved expression fails the extraction loudly instead of silently
// keeping the case FAIL.
//
// Every case returns { id, group, description, expected, actualStatus, detail }.

const path = require('node:path');
const fs = require('node:fs');
const vm = require('node:vm');

const DEFAULT_SALT = 'h3a-fixture-salt';

function extractBatchSaltExpr(indexHtmlSource) {
  const m = indexHtmlSource.match(/const batchSalt = salt \|\| (.+?);/);
  if (!m) {
    throw new Error(
      'case95: could not find "const batchSalt = salt || ...;" in index.html; ' +
      'the batch-mode salt fallback moved or was renamed -- update this extraction.'
    );
  }
  return m[1];
}

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

function extractBatchHandlerBody(indexHtmlSource) {
  const m = indexHtmlSource.match(/\$\('#batchSanitizeBtn'\)\.addEventListener\('click', \(\) => \{([\s\S]*?)\n\}\);/);
  if (!m) {
    throw new Error(
      'case98: could not find the #batchSanitizeBtn click handler body in index.html; ' +
      'the batch handler moved or was renamed -- update this extraction.'
    );
  }
  return m[1];
}

function makeCrossCuttingCases(engine, indexHtmlSource) {
  return [
    case95(engine, indexHtmlSource),
    case96(engine),
    case97(engine),
    case98(indexHtmlSource),
    case99(indexHtmlSource),
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
function case95(engine, indexHtmlSource) {
  const saltExpr = extractBatchSaltExpr(indexHtmlSource);
  // Evaluates the actual fallback expression pulled from index.html (with
  // `Date` shadowed by a candidate timestamp) in an empty vm context, not the
  // main realm -- consistent with how the extracted engine itself runs, with
  // no `process`/`fetch`/`globalThis` in scope. A real fix to the formula
  // changes what this brute-force targets, instead of always attacking a
  // hardcoded copy of the old weak formula.
  const saltForTimestamp = (ts) =>
    vm.runInNewContext(`(${saltExpr})`, { Date: { now: () => ts } });

  const secretTimestamp = Date.now() - 90_000; // "unknown" run time, within the search window
  const secretSalt = saltForTimestamp(secretTimestamp);
  const target = engine.anonymizeIP('127.0.0.1', secretSalt, true);

  const BUDGET = 1_000_000;
  const halfWindowMs = Math.floor(BUDGET / 2);
  let found = -1;
  for (let delta = 0; delta <= halfWindowMs && found === -1; delta++) {
    for (const candidateTs of [secretTimestamp + delta, secretTimestamp - delta]) {
      const candidateSalt = saltForTimestamp(candidateTs);
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
    detail: recovered
      ? `recovered within ~${found} candidates (salt expr from index.html: ${saltExpr})`
      : `not recovered within budget (salt expr from index.html: ${saltExpr})`,
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
    id: 97, group: 'cross-cutting', expected: 'PASS',
    description: 'A domain and an unrelated URL host get distinct placeholders',
    actualStatus: distinct ? 'PASS' : 'FAIL',
    detail: `domain -> ${domainEntry && domainEntry.placeholder}, url -> ${urlEntry && urlEntry.placeholder}`,
  };
}

// 98. Batch mode produces validation warnings.
// The batch handler (index.html, $('#batchSanitizeBtn') listener) calls only
// sanitizeConfig per file; it never calls validateSanitized. The likely fix
// is adding that call inside the handler -- code in index.html's UI Logic
// block, outside the extracted engine range, so the harness can't exercise
// it by calling the engine. Instead we check the handler's own source: does
// its body call validateSanitized(...) at all?
function case98(indexHtmlSource) {
  const handlerBody = extractBatchHandlerBody(indexHtmlSource);
  const callsValidate = /\bvalidateSanitized\s*\(/.test(handlerBody);
  return {
    id: 98, group: 'cross-cutting', expected: 'FAIL',
    description: 'Batch mode produces validation warnings',
    actualStatus: callsValidate ? 'PASS' : 'FAIL',
    detail: callsValidate
      ? 'the #batchSanitizeBtn handler body now calls validateSanitized(...)'
      : 'the #batchSanitizeBtn handler body has no validateSanitized(...) call',
  };
}

// 99. The output filename doesn't contain the input base name.
// Evaluates the actual filename template from index.html's #dlSanitized
// download handler (currently `${baseName}.sanitized.${ext}`) rather than a
// hardcoded copy, so a real fix to the naming scheme changes this case's
// result instead of leaving it FAIL forever.
function case99(indexHtmlSource) {
  const template = extractOutputFilenameTemplate(indexHtmlSource);
  const loadedFilename = 'FAKEHOST-fw01-99.cfg';
  const ext = loadedFilename.split('.').pop();
  const baseName = loadedFilename.replace(/\.[^.]+$/, '');
  // Renders the actual template string extracted from index.html in an empty
  // vm context, with only baseName/ext in scope.
  const outputFilename = vm.runInNewContext(`\`${template}\``, { baseName, ext });
  const leaksBaseName = outputFilename.includes(baseName);
  return {
    id: 99, group: 'cross-cutting', expected: 'FAIL',
    description: "The output filename doesn't contain the input base name",
    actualStatus: leaksBaseName ? 'FAIL' : 'PASS',
    detail: `"${loadedFilename}" -> "${outputFilename}" (template from index.html: \`${template}\`)`,
  };
}

module.exports = { makeCrossCuttingCases, DEFAULT_SALT };
