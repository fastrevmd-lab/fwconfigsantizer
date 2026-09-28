'use strict';
// Extracts the sanitizer engine from index.html and loads it into an isolated
// vm context, without modifying index.html. The engine block is plain
// functions with no DOM/browser globals, so it can run unmodified under
// Node's vm module.
//
// The line range is re-derived from the marker comments every run so that if
// the engine ever moves, extraction fails loudly instead of silently slicing
// the wrong text.

const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const INDEX_HTML_PATH = path.join(__dirname, '..', 'index.html');

const ENGINE_START_MARKER = 'Firewall Config Sanitizer - Engine';
const ENGINE_END_MARKER = 'UI Logic';

function loadEngineSource() {
  const html = fs.readFileSync(INDEX_HTML_PATH, 'utf8');
  const lines = html.split('\n');

  const startIdx = lines.findIndex((l) => l.includes(ENGINE_START_MARKER));
  const endIdx = lines.findIndex((l, i) => i > startIdx && l.includes(ENGINE_END_MARKER));
  const endMarkerCount = lines.filter((l) => l.includes(ENGINE_END_MARKER)).length;
  if (startIdx === -1 || endIdx === -1 || endIdx <= startIdx || endMarkerCount !== 1) {
    throw new Error(
      `Could not locate engine markers in index.html (start=${startIdx}, end=${endIdx}, ` +
      `endMarkerCount=${endMarkerCount}). The engine block markers may have moved, been ` +
      'renamed, or become ambiguous.'
    );
  }

  // The comment block containing ENGINE_START_MARKER opens a few lines above
  // the first function; back up to the nearest preceding "<script>" line, and
  // stop a few lines above ENGINE_END_MARKER at the nearest blank line, so we
  // capture exactly the engine code and nothing from the surrounding <script>
  // tag or the UI logic block.
  const scriptOpenIdx = lines.lastIndexOf('<script>', startIdx);
  if (scriptOpenIdx === -1) {
    throw new Error('Could not find <script> tag preceding the engine block.');
  }

  // endIdx points at the "UI Logic" comment line; the engine code ends at the
  // blank line immediately before the "/* ====... UI Logic" comment block.
  let engineEndIdx = endIdx;
  while (engineEndIdx > 0 && lines[engineEndIdx - 1].trim() !== '') {
    engineEndIdx--;
  }
  // Back up past the comment-open line ("/* ===...") too.
  while (engineEndIdx > 0 && lines[engineEndIdx - 1].trim().startsWith('/*')) {
    engineEndIdx--;
  }

  const engineLines = lines.slice(scriptOpenIdx + 1, engineEndIdx);
  const startLineNo = scriptOpenIdx + 2; // 1-indexed line of first engine line
  const endLineNo = scriptOpenIdx + engineLines.length + 1;

  return {
    source: engineLines.join('\n'),
    startLineNo,
    endLineNo,
  };
}

/**
 * Loads the extracted engine into a fresh vm context and returns the
 * top-level functions it declares (sanitizeConfig, validateSanitized,
 * detectVendor, anonymizeIP, fnv1a, restoreConfig, ...).
 */
function loadEngine() {
  const { source, startLineNo, endLineNo } = loadEngineSource();

  const sandbox = {};
  vm.createContext(sandbox);
  const script = new vm.Script(source, { filename: 'index.html (extracted engine)' });
  script.runInContext(sandbox);

  const required = ['sanitizeConfig', 'validateSanitized', 'detectVendor', 'anonymizeIP', 'fnv1a'];
  for (const name of required) {
    if (typeof sandbox[name] !== 'function') {
      throw new Error(`Expected engine to export function "${name}", got ${typeof sandbox[name]}`);
    }
  }

  return { engine: sandbox, startLineNo, endLineNo, source };
}

module.exports = { loadEngine, loadEngineSource, INDEX_HTML_PATH };
