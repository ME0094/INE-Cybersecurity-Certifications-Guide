#!/usr/bin/env node
// check-commands.mjs — validate the flags, subcommands and plugins used in the guides
// against catalogues downloaded from each tool's own documentation.
//
// Why this exists: the audit of 18 Sep 2026 found 21 blocking defects in this repository
// and nearly all of them were commands that cannot run — `nmap -oJ`, `lynis show warnings`,
// `SharpHound --ldapuser`, `frida --no-pause`, `oscap xccdf generate tailoring-file`,
// `vol … windows.memdump`. None of those are visible to a link checker or a proofreader.
// They are visible to a tool's own `--help`.
//
// What it validates
//   1. flags      — every -f / --flag token, against the tool's catalogue.
//   2. subcommands— the leading verbs of tools that have them (spec.maxPositionals).
//   3. plugins    — dotted or `!`-prefixed names for tools that dispatch on them
//                   (Volatility plugins, KAPE modules).
//
// What it deliberately does NOT do
//   - It does not check flag *arity*: `ils -m /mount` passes here, because `-m` exists and
//     the error is that it takes no argument. That class needs a per-flag arity field the
//     catalogues do not carry yet. Stated rather than implied.
//   - It does not judge semantics: a real flag used for the wrong purpose is invisible.
//   - It never invents a catalogue. A tool with no spec file is reported as uncovered.
//
// Design rule: the catalogue errs toward *permissive*, because a false positive makes the
// checker untrustworthy and an untrusted checker gets switched off. Missed detections are
// the acceptable failure; invented ones are not.
//
// Usage:
//   node scripts/utilities/check-commands.mjs [root] [--verbose] [--list-uncovered]
//
// Exit codes: 0 clean, 1 unknown flag/subcommand/plugin found, 2 usage error.

import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import { join, resolve, relative, sep, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const SPEC_DIR = join(HERE, 'tool-specs');

const argv = process.argv.slice(2);
const flagsOn = new Set(argv.filter((a) => a.startsWith('--')));
const positional = argv.filter((a) => !a.startsWith('--'));
const ROOT = resolve(positional[0] ?? '.');
const VERBOSE = flagsOn.has('--verbose');
const LIST_UNCOVERED = flagsOn.has('--list-uncovered');
const REQUIRE_RECORD = flagsOn.has('--require-verification');

const IGNORED_DIRS = new Set(['.git', 'node_modules', '.vscode', 'dist', 'build']);

// ── catalogues ────────────────────────────────────────────────────────────────────────
function loadSpecs() {
  if (!existsSync(SPEC_DIR)) return new Map();
  const byAlias = new Map();
  for (const file of readdirSync(SPEC_DIR)) {
    if (!file.endsWith('.json')) continue;
    const spec = JSON.parse(readFileSync(join(SPEC_DIR, file), 'utf8'));
    for (const alias of spec.aliases ?? [spec.tool]) byAlias.set(alias.toLowerCase(), spec);
    byAlias.set(spec.tool.toLowerCase(), spec);
  }
  return byAlias;
}

// ── markdown ──────────────────────────────────────────────────────────────────────────
// Only fenced blocks that plausibly hold shell commands are read; a YAML rule or an HTTP
// transcript is not a command line and must not be guessed at.
const SHELL_LANGS = new Set(['', 'bash', 'sh', 'shell', 'console', 'powershell', 'ps1', 'cmd', 'dos', 'text', 'plaintext', 'zsh']);

function commandsIn(file) {
  const lines = readFileSync(file, 'utf8').split('\n');
  const out = [];
  let inFence = false;
  let info = '';
  let buffer = null;
  let startLine = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const fence = line.match(/^\s*```+\s*(\S*)/);
    if (fence) {
      if (!inFence) {
        inFence = true;
        info = (fence[1] ?? '').toLowerCase();
      } else {
        inFence = false;
        info = '';
      }
      buffer = null;
      continue;
    }
    if (!inFence || !SHELL_LANGS.has(info)) continue;
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    // A line ending in a shell continuation is joined with the next one.
    if (buffer !== null) {
      buffer.text += ` ${trimmed}`;
      if (!/[\\`]$/.test(trimmed)) {
        out.push({ text: buffer.text, line: startLine });
        buffer = null;
      }
      continue;
    }
    if (/[\\`]$/.test(trimmed)) {
      buffer = { text: trimmed.replace(/[\\`]$/, '').trim() };
      startLine = i + 1;
      continue;
    }
    out.push({ text: trimmed, line: i + 1 });
  }
  return out;
}

// ── command parsing ───────────────────────────────────────────────────────────────────
// Wrappers that are not the tool: skip them and keep looking.
const WRAPPERS = new Set([
  'sudo', 'doas', 'time', 'env', 'nohup', 'timeout', 'nice', 'watch', 'xargs', 'command',
  'python', 'python3', 'python2', 'py', 'pip', 'pip3', 'pipx', 'uv', 'perl', 'ruby', 'node',
  'bash', 'sh', 'zsh', 'pwsh', 'powershell', 'cmd', 'cmd.exe', './',
]);

function toolOf(text, specs) {
  // Strip prompt markers, `$`, and command substitutions at the head.
  let cleaned = text.replace(/^\s*(\$|PS[^>]*>|#|>)\s*/, '');
  const parts = cleaned.split(/\s+/).filter(Boolean);
  for (let i = 0; i < parts.length && i < 4; i++) {
    let token = parts[i];
    if (token.includes('=') && !token.startsWith('-')) continue; // VAR=value prefix
    const base = token.split(/[\\/]/).pop().replace(/\.(exe|py|pl|sh|ps1|bat|cmd)$/i, '');
    if (WRAPPERS.has(token.toLowerCase()) || WRAPPERS.has(base.toLowerCase())) continue;
    // A command line carries a flag or a path/URL after the tool name. Prose inside a shell
    // fence — "Which of the following is true" — carries neither, and treating it as a
    // command turned the uncovered-tool report into a thousand lines of English words.
    const rest = parts.slice(i + 1).join(' ');
    // The flag must start at a token boundary: prose with hyphenated words
    // ("one-paragraph") is not a command line, and treating it as one is how the
    // uncovered-tool report filled up with English.
    const hasFlag = /(^|\s)-{1,2}[A-Za-z][\w-]*/.test(rest);
    if (!hasFlag && !/[\\/]|https?:/.test(rest)) return null;
    if (specs.has(base.toLowerCase())) return { spec: specs.get(base.toLowerCase()), tokens: parts.slice(i + 1), tool: base };
    // A tool we have no catalogue for: report the gap, do not guess.
    if (/^[A-Za-z][\w.-]*$/.test(base) && !base.startsWith('-')) return { spec: null, tokens: parts.slice(i + 1), tool: base };
  }
  return null;
}

const PATHLIKE = /[\\/]|\.(xml|json|ya?ml|txt|csv|evtx|raw|dd|img|log|conf|pem|key|hprof|ab|apk|ipa|db|sqlite|yar|yarac|zip|gz|tar|md|py|ps1|sh|exe|dll|pf|hve|lnk|dat|bin)$/i;

function looksLikeValue(token) {
  return token.includes('<') || token.includes('>') || token.includes('$') || PATHLIKE.test(token) || /^["']/.test(token);
}

function validateFlags(tokens, spec) {
  const long = new Set(spec.longFlags ?? []);
  const short = new Set(spec.shortFlags ?? []);
  const unknown = [];
  for (const raw of tokens) {
    const bare = raw.replace(/^["'(]+|["'),;]+$/g, '');
    if (!bare.startsWith('-') || bare === '-' || bare === '--') continue;
    if (bare.includes('<') || bare.includes('$')) continue; // placeholder
    // `--level=3`, `--file-read=/etc/passwd`, `--script=default`: the value is glued to the
    // flag with `=`, so the flag is the stem. Missed this on the first full run and produced
    // sixteen false reports; the checker was wrong, not the guides.
    const token = bare.startsWith('--') && bare.includes('=') ? bare.slice(0, bare.indexOf('=')) : bare;
    if (long.has(token) || short.has(token)) continue;
    // `-T4`, `-p80`: a known short flag with its value attached.
    if (/^-[A-Za-z]/.test(token) && !token.startsWith('--')) {
      let ok = false;
      for (let len = Math.min(token.length - 1, 5); len >= 2; len--) {
        if (short.has(token.slice(0, len))) { ok = true; break; }
      }
      if (ok) continue;
      // `-la`: a bundle of single-character flags.
      const chars = token.slice(1).split('');
      if (chars.length > 1 && chars.every((c) => short.has(`-${c}`))) continue;
    }
    unknown.push(token);
  }
  return unknown;
}

function validatePositionals(tokens, spec) {
  const problems = [];
  const subs = spec.subcommands;
  if (!Array.isArray(subs) || subs.length === 0) return problems;
  const known = new Set(subs.map((s) => String(s).toLowerCase()));
  const words = tokens.filter((t) => !t.startsWith('-') && !looksLikeValue(t));

  if (spec.dottedPositionals) {
    for (const t of words) {
      const dotted = /^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)+$/.test(t) || /^![A-Za-z0-9_]+$/.test(t);
      if (dotted && !known.has(t.toLowerCase())) problems.push(t);
    }
    return problems;
  }
  const max = Number(spec.maxPositionals ?? 0);
  for (const t of words.slice(0, max)) {
    if (!known.has(t.toLowerCase())) problems.push(t);
  }
  return problems;
}

// ── walk ──────────────────────────────────────────────────────────────────────────────
function walk(dir, out = []) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!IGNORED_DIRS.has(entry.name)) walk(join(dir, entry.name), out);
    } else if (entry.isFile() && entry.name.toLowerCase().endsWith('.md')) {
      out.push(join(dir, entry.name));
    }
  }
  return out;
}

if (!existsSync(ROOT) || !statSync(ROOT).isDirectory()) {
  console.error(`check-commands: not a directory: ${ROOT}`);
  process.exit(2);
}

const specs = loadSpecs();
if (specs.size === 0) {
  console.error(`check-commands: no catalogues found in ${SPEC_DIR}`);
  console.error('Build them with: node scripts/utilities/fetch-tool-spec.mjs --tool <name> --url <docs>');
  process.exit(2);
}

const uncovered = new Map();
const problems = [];
let commandLines = 0;
let checkedLines = 0;
let filesWithCommands = 0;
let filesWithRecord = 0;
const missingRecord = [];

// A verification record says what was actually done with the examples in a file:
//   > **Verification:** executed against <tool> <version> on <date>
//   > **Verification:** checked against <source> on <date>
//   > **Verification:** unverified syntax references — not run
// It is measured, not enforced, until the convention has spread: a check that fails on
// 183 files on day one is a check nobody adopts.
const RECORD = /^\s*>\s*\*\*Verification:\*\*/im;

for (const file of walk(ROOT).sort()) {
  const rel = relative(ROOT, file).split(sep).join('/');
  const source = readFileSync(file, 'utf8');
  const hasRecord = RECORD.test(source);
  let fileCommands = 0;
  for (const { text, line } of commandsIn(file)) {
    commandLines++;
    fileCommands++;
    const found = toolOf(text, specs);
    if (!found) continue;
    if (!found.spec) {
      uncovered.set(found.tool, (uncovered.get(found.tool) ?? 0) + 1);
      continue;
    }
    checkedLines++;
    const badFlags = validateFlags(found.tokens, found.spec);
    const badSubs = validatePositionals(found.tokens, found.spec);
    for (const f of badFlags) {
      problems.push(`${rel}:${line} — ${found.tool}: unknown flag ${f} (catalogue: ${found.spec.provenance?.source ?? 'unknown'})`);
    }
    for (const s of badSubs) {
      problems.push(`${rel}:${line} — ${found.tool}: unknown subcommand/plugin ${s} (catalogue: ${found.spec.provenance?.source ?? 'unknown'})`);
    }
    if (VERBOSE && badFlags.length === 0 && badSubs.length === 0) {
      console.log(`  ok  ${rel}:${line} — ${found.tool}`);
    }
  }
  if (fileCommands > 0) {
    filesWithCommands++;
    if (hasRecord) filesWithRecord++;
    else missingRecord.push(rel);
  }
}

console.log(
  `check-commands: ${specs.size} catalogues, ${commandLines} command line(s) seen, ` +
    `${checkedLines} checked against a catalogue, ${uncovered.size} tool(s) uncovered`,
);
if (filesWithCommands > 0) {
  const pct = Math.round((filesWithRecord / filesWithCommands) * 100);
  console.log(
    `check-commands: verification records — ${filesWithRecord}/${filesWithCommands} files with ` +
      `commands declare one (${pct}%)`
      + (REQUIRE_RECORD ? '' : ' [measured, not enforced: pass --require-verification to fail on it]'),
  );
  if (REQUIRE_RECORD) {
    for (const rel of missingRecord) {
      problems.push(`${rel} — contains commands but declares no > **Verification:** record`);
    }
  }
}
if (LIST_UNCOVERED && uncovered.size > 0) {
  console.log('Uncovered tools (no catalogue — nothing was checked):');
  for (const [tool, count] of [...uncovered].sort((a, b) => b[1] - a[1])) {
    console.log(`  ${String(count).padStart(4)}  ${tool}`);
  }
}
if (problems.length > 0) {
  console.error(`\nUNKNOWN FLAGS OR SUBCOMMANDS (${problems.length}):`);
  for (const p of problems.slice(0, 60)) console.error(`  ${p}`);
  if (problems.length > 60) console.error(`  … and ${problems.length - 60} more`);
  process.exit(1);
}
console.log('check-commands: OK — every flag and subcommand of a covered tool exists in its catalogue.');
