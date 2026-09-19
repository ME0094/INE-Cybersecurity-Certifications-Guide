#!/usr/bin/env node
// check-code.mjs — repository self-check.
//
// The failure modes this guards against are the ones a flag checker cannot see, because no
// command is involved:
//   1. a fenced block that is never closed, which silently swallows the rest of the document
//      (this repository shipped one: `labs/challenge-solutions.md` lost its last third and
//      grew two headings that belonged to a template);
//   2. a `python` block that does not parse — a lab the reader is told to run;
//   3. a `js`/`javascript` block that does not parse (a Frida hook with `function (x, ...)`
//      was shipped this way);
//   4. a standalone `.py` or `.mjs`/`.js` file that does not parse, including this repository's
//      own scripts.
//
// What it does NOT do: execute anything. Python is parsed with `ast.parse`, JavaScript with
// `new vm.Script`, so no import-time side effect of any snippet can run here.
//
// Usage:
//   node scripts/utilities/check-code.mjs [root] [--verbose]
//
// Exit codes: 0 clean, 1 problems found, 2 usage/IO error.
// Dependencies: none. Python 3 is used when it is on PATH; when it is missing, Python blocks
// are reported as skipped, never as passing.

import { readFileSync, readdirSync, existsSync, statSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join, resolve, relative, sep, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import vm from 'node:vm';

const argv = process.argv.slice(2);
const flags = new Set(argv.filter((a) => a.startsWith('--')));
const positional = argv.filter((a) => !a.startsWith('--'));
const ROOT = resolve(positional[0] ?? '.');
const VERBOSE = flags.has('--verbose');

const IGNORED_DIRS = new Set(['.git', 'node_modules', '.vscode', 'dist', 'build']);
const PY_LANGS = new Set(['python', 'py', 'python3']);
const JS_LANGS = new Set(['javascript', 'js', 'node', 'typescript', 'ts']);
// A block that is a module fragment is not a script: `import`/`export` at the top level would
// make vm.Script report a syntax error that is not one.
const ESM_HINT = /^\s*(import|export)\s/m;

if (!existsSync(ROOT) || !statSync(ROOT).isDirectory()) {
  console.error(`check-code: not a directory: ${ROOT}`);
  process.exit(2);
}

// ── Python availability ───────────────────────────────────────────────────────────────
function pythonCommand() {
  for (const candidate of ['python3', 'python']) {
    const probe = spawnSync(candidate, ['-c', 'print(1)'], { encoding: 'utf8' });
    if (!probe.error && probe.status === 0) return candidate;
  }
  return null;
}
const PYTHON = pythonCommand();

// ── walk ──────────────────────────────────────────────────────────────────────────────
function walk(dir, out = []) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!IGNORED_DIRS.has(entry.name)) walk(join(dir, entry.name), out);
    } else if (entry.isFile()) {
      out.push(join(dir, entry.name));
    }
  }
  return out;
}

const files = walk(ROOT);
const mdFiles = files.filter((f) => f.toLowerCase().endsWith('.md'));
const codeFiles = files.filter((f) => /\.(py|mjs|js|cjs)$/i.test(f));

const problems = [];
const skipped = [];
let blocksChecked = 0;
let filesChecked = 0;

// ── Markdown: fences ──────────────────────────────────────────────────────────────────
function fencedBlocks(text) {
  const lines = text.split('\n');
  const out = [];
  let lang = null;
  let code = [];
  let start = 0;
  lines.forEach((line, index) => {
    const fence = line.match(/^\s*```+\s*([A-Za-z0-9_+-]*)\s*$/);
    if (fence) {
      if (lang === null) {
        lang = (fence[1] ?? '').toLowerCase();
        code = [];
        start = index + 2; // 1-based, first line after the fence
      } else {
        out.push({ lang, code: code.join('\n'), line: start });
        lang = null;
      }
      return;
    }
    if (lang !== null) code.push(line);
  });
  return { blocks: out, unclosed: lang !== null ? start : null };
}

function pythonParses(code) {
  // A directory is created so several blocks can be checked without touching the repository.
  const file = join(PY_TMP, 'block.py');
  writeFileSync(file, code, 'utf8');
  const res = spawnSync(PYTHON, ['-c',
    'import ast,sys; ast.parse(open(sys.argv[1], encoding="utf-8").read())', file],
    { encoding: 'utf8' });
  if (res.error) return { ok: false, message: `could not run ${PYTHON}: ${res.error.message}` };
  if (res.status === 0) return { ok: true };
  const message = (res.stderr || '').trim().split('\n').filter(Boolean).pop() ?? 'parse error';
  return { ok: false, message };
}

const PY_TMP = PYTHON ? mkdtempSync(join(tmpdir(), 'check-code-')) : null;

for (const file of mdFiles) {
  const rel = relative(ROOT, file).split(sep).join('/');
  const text = readFileSync(file, 'utf8');
  const { blocks, unclosed } = fencedBlocks(text);
  filesChecked++;
  if (unclosed !== null) {
    problems.push(`${rel}:${unclosed} — fenced block is never closed (it swallows the rest of the file)`);
  }
  for (const block of blocks) {
    if (!block.code.trim()) continue;
    if (PY_LANGS.has(block.lang)) {
      if (!PYTHON) { skipped.push(`${rel}:${block.line} (python)`); continue; }
      blocksChecked++;
      const res = pythonParses(block.code);
      if (!res.ok) problems.push(`${rel}:${block.line} — python block does not parse: ${res.message}`);
      else if (VERBOSE) console.log(`  ok  ${rel}:${block.line} python`);
    } else if (JS_LANGS.has(block.lang)) {
      if (ESM_HINT.test(block.code)) { skipped.push(`${rel}:${block.line} (js module fragment)`); continue; }
      blocksChecked++;
      try {
        new vm.Script(block.code, { filename: `${rel}:${block.line}` });
        if (VERBOSE) console.log(`  ok  ${rel}:${block.line} js`);
      } catch (err) {
        problems.push(`${rel}:${block.line} — js block does not parse: ${err.message}`);
      }
    }
  }
}

// ── Standalone scripts ────────────────────────────────────────────────────────────────
for (const file of codeFiles) {
  const rel = relative(ROOT, file).split(sep).join('/');
  filesChecked++;
  if (/\.py$/i.test(file)) {
    if (!PYTHON) { skipped.push(`${rel} (python)`); continue; }
    blocksChecked++;
    const res = pythonParses(readFileSync(file, 'utf8'));
    if (!res.ok) problems.push(`${rel} — does not parse: ${res.message}`);
    else if (VERBOSE) console.log(`  ok  ${rel}`);
  } else {
    // ESM/CJS files: `--check` reads the file without executing it.
    const res = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' });
    if (res.error) { skipped.push(`${rel} (node --check unavailable: ${res.error.code ?? res.error.message})`); continue; }
    blocksChecked++;
    if (res.status !== 0) {
      const message = (res.stderr || '').trim().split('\n').filter(Boolean).slice(-2).join(' ') || 'syntax error';
      problems.push(`${rel} — does not parse: ${message}`);
    } else if (VERBOSE) {
      console.log(`  ok  ${rel}`);
    }
  }
}

if (PY_TMP) rmSync(PY_TMP, { recursive: true, force: true });

console.log(
  `check-code: ${mdFiles.length} Markdown file(s) and ${codeFiles.length} script(s) inspected, ` +
    `${blocksChecked} block(s) or file(s) parsed` +
    (PYTHON ? '' : ' (Python not on PATH: python blocks skipped, not passed)'),
);
if (skipped.length > 0 && VERBOSE) {
  console.log(`Skipped (${skipped.length}):`);
  for (const s of skipped) console.log(`  ${s}`);
}
if (problems.length > 0) {
  console.error(`\nDOES NOT PARSE OR IS UNCLOSED (${problems.length}):`);
  for (const p of problems) console.error(`  ${p}`);
  process.exit(1);
}
console.log('check-code: OK — every fenced code block is closed and every block and script parses.');
