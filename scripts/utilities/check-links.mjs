#!/usr/bin/env node
// check-links.mjs — repository self-check.
//
// Verifies that every relative link in every Markdown file resolves to a path that
// exists, and that in-repo anchors (#fragment) point at a heading that actually exists
// in the target file. Optionally checks external URLs over the network.
//
// Usage:
//   node scripts/utilities/check-links.mjs [root] [--verbose] [--external]
//
// Exit codes: 0 = clean, 1 = broken links or anchors found, 2 = usage/IO error.
// Dependencies: none (Node stdlib only). Fenced code blocks are ignored so that a
// command shown inside a code sample is never mistaken for a link.

import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, dirname, resolve, relative, sep } from 'node:path';
import { stripFences, slugify } from './markdown.mjs';

const argv = process.argv.slice(2);
const flags = new Set(argv.filter((a) => a.startsWith('--')));
const positional = argv.filter((a) => !a.startsWith('--'));
const ROOT = resolve(positional[0] ?? '.');
const VERBOSE = flags.has('--verbose');
const CHECK_EXTERNAL = flags.has('--external');

const IGNORED_DIRS = new Set(['.git', 'node_modules', '.vscode', 'dist', 'build']);

// Bare filenames that are NOT repository notes: these are files the guides tell the
// *reader* to create in their own lab (a personal answer key, a per-project env file).
// They are not promises made by this repository, so they must not fail the check.
const READER_ARTIFACTS = new Set(['answer-key.md', 'env.md', 'notes.md', 'notes.txt']);

function walk(dir, out = []) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (IGNORED_DIRS.has(entry.name)) continue;
      walk(join(dir, entry.name), out);
    } else if (entry.isFile() && entry.name.toLowerCase().endsWith('.md')) {
      out.push(join(dir, entry.name));
    }
  }
  return out;
}

function lineOf(text, index) {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text[i] === '\n') line++;
  return line;
}

const headingCache = new Map();

function headingsOf(file) {
  if (headingCache.has(file)) return headingCache.get(file);
  const text = stripFences(readFileSync(file, 'utf8'));
  const slugs = new Set();
  const seen = new Map();
  for (const line of text.split('\n')) {
    const m = line.match(/^(#{1,6})\s+(.*?)\s*#*\s*$/);
    if (!m) continue;
    const base = slugify(m[2]);
    if (!base) continue;
    const n = seen.get(base) ?? 0;
    seen.set(base, n + 1);
    slugs.add(n === 0 ? base : `${base}-${n}`);
  }
  headingCache.set(file, slugs);
  return slugs;
}

function collectLinks(text) {
  const links = [];
  // Link syntax written *inside* inline code is documentation about links, not a link:
  // this file's own audit notes say "the checker collects only `[](...)` and `<...>`",
  // and that literal must not be reported as a broken target.
  const codeRanges = [];
  for (const m of text.matchAll(/`[^`\n]*`/g)) codeRanges.push([m.index, m.index + m[0].length]);
  const inCode = (index) => codeRanges.some(([start, end]) => index > start && index < end);

  const inline = /\[[^\]]*\]\(\s*<?([^)>\s]+)>?(?:\s+"[^"]*")?\s*\)/g;
  for (const m of text.matchAll(inline)) {
    if (!inCode(m.index)) links.push({ target: m[1], index: m.index });
  }
  const autolink = /<((?:https?:\/\/|mailto:)[^>\s]+)>/g;
  for (const m of text.matchAll(autolink)) {
    if (!inCode(m.index)) links.push({ target: m[1], index: m.index });
  }
  // Inline code that is explicitly relative — `../labs/a-lab.md` — is a promise to the
  // reader even though Markdown will not render it as a link. Only spans starting with
  // ./ or ../ are checked, so prose like `01-reconnaissance.md` (a file that lives in
  // another folder) cannot produce a false positive.
  const codeSpan = /`([^`\n]+)`/g;
  for (const m of text.matchAll(codeSpan)) {
    const value = m[1].trim();
    if (!/^\.\.?\//.test(value)) continue;
    if (/\s/.test(value)) continue;
    if (!/\.(md|ya?ml|py|sh|txt|json)$/i.test(value)) continue;
    links.push({ target: value, index: m.index, promised: true });
  }
  // A bare `sibling-note.md` cannot be resolved without guessing the folder, so it is
  // checked differently: the name must exist *somewhere* in the repository. That catches
  // "this file is covered in `automation-and-soar.md`" when no such file was ever written,
  // without flagging legitimate cross-folder mentions.
  for (const m of text.matchAll(codeSpan)) {
    const value = m[1].trim();
    if (!/^[A-Za-z0-9._-]+\.md$/i.test(value)) continue;
    links.push({ target: value, index: m.index, bare: true });
  }
  // URLs written as plain text — not a markdown link, not in angle brackets — are still
  // claims about the network, and the repository writes several that way (the entry points
  // in resources/official-links.md, for instance). Collected last so the richer forms above
  // win; duplicates are deduplicated by the caller.
  const bareUrl = /(^|[\s("'`>])(https?:\/\/[^\s<>()"'`]+)/g;
  for (const m of text.matchAll(bareUrl)) {
    links.push({ target: m[2].replace(/[.,;:]+$/, ''), index: m.index });
  }
  return links;
}

// A URL that cannot answer from a CI runner, or that is not really a public address:
// loopback, RFC 1918, link-local, and single-label hosts such as the `http://lab/login`
// of the lab guides. The weekly sweep must not go red on the reader's own lab.
function isUnroutable(url) {
  let host;
  try {
    host = new URL(url).hostname.toLowerCase().replace(/^\[|\]$/g, '');
  } catch {
    return true;
  }
  if (!host.includes('.')) return true; // single label: lab, dvwa, collector…
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local')) return true;
  if (host === '::1' || host.startsWith('fe80:')) return true;
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  const a = Number(m[1]);
  const b = Number(m[2]);
  return (
    a === 127 || // loopback
    a === 10 || // private
    (a === 192 && b === 168) || // private
    (a === 172 && b >= 16 && b <= 31) || // private
    (a === 169 && b === 254) // link-local
  );
}

async function checkExternalUrl(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15000);
  try {
    let res = await fetch(url, { method: 'HEAD', redirect: 'follow', signal: controller.signal });
    // A 4xx/5xx from HEAD says nothing on its own: many hosts answer 404 to HEAD while
    // serving the page to GET (PortSwigger, for one). Any failure is retried as a real
    // request before the link is called dead.
    if (res.status >= 400) {
      res = await fetch(url, { method: 'GET', redirect: 'follow', signal: controller.signal });
    }
    // 403/429 usually mean bot protection, not a dead link: report, do not fail.
    if (res.status >= 400 && res.status !== 403 && res.status !== 429 && res.status !== 999) {
      return `HTTP ${res.status}`;
    }
    return null;
  } catch (err) {
    return `no response (${err.name === 'AbortError' ? 'timeout' : err.message})`;
  } finally {
    clearTimeout(timer);
  }
}

if (!existsSync(ROOT) || !statSync(ROOT).isDirectory()) {
  console.error(`check-links: not a directory: ${ROOT}`);
  process.exit(2);
}

const files = walk(ROOT).sort();
const mdBasenames = new Set(files.map((f) => f.split(sep).pop().toLowerCase()));
const broken = [];
const external = new Map();
let checked = 0;
let anchors = 0;
let bareChecked = 0;
let skippedLocal = 0;

for (const file of files) {
  const raw = readFileSync(file, 'utf8');
  const text = stripFences(raw);
  for (const { target, index, bare } of collectLinks(text)) {
    const line = lineOf(text, index);
    const where = `${relative(ROOT, file).split(sep).join('/')}:${line}`;

    if (bare) {
      if (READER_ARTIFACTS.has(target.toLowerCase())) continue;
      bareChecked++;
      if (!mdBasenames.has(target.toLowerCase())) {
        broken.push(`${where} -> \`${target}\` (promised file exists nowhere in the repository)`);
      }
      continue;
    }

    if (/^(https?:|mailto:|tel:)/i.test(target)) {
      if (CHECK_EXTERNAL) {
        const key = target.replace(/[.,;]$/, '');
        if (isUnroutable(key)) {
          skippedLocal++;
        } else if (!external.has(key)) {
          external.set(key, null);
        }
      }
      continue;
    }
    if (target.startsWith('#')) {
      anchors++;
      const slug = decodeURIComponent(target.slice(1)).toLowerCase();
      if (!headingsOf(file).has(slug)) broken.push(`${where} -> ${target} (no such heading in this file)`);
      continue;
    }

    const [rawPath, rawAnchor] = target.split('#');
    if (!rawPath) continue;
    if (/[<>{}*]/.test(rawPath)) continue; // template placeholder, not a real path
    checked++;
    const path = decodeURIComponent(rawPath);
    const abs = resolve(dirname(file), path);
    if (!existsSync(abs)) {
      broken.push(`${where} -> ${target} (no such path)`);
      continue;
    }
    if (rawAnchor && statSync(abs).isFile() && abs.toLowerCase().endsWith('.md')) {
      anchors++;
      const slug = decodeURIComponent(rawAnchor).toLowerCase();
      if (!headingsOf(abs).has(slug)) {
        broken.push(`${where} -> ${target} (no such heading in target)`);
      }
    }
  }
}

if (CHECK_EXTERNAL && external.size > 0) {
  console.log(`Checking ${external.size} external URL(s)…`);
  const urls = [...external.keys()];
  const concurrency = 8;
  for (let i = 0; i < urls.length; i += concurrency) {
    const batch = urls.slice(i, i + concurrency);
    const results = await Promise.all(batch.map((u) => checkExternalUrl(u)));
    results.forEach((problem, k) => {
      const url = batch[k];
      if (problem) {
        external.set(url, problem);
        broken.push(`external -> ${url} (${problem})`);
      } else if (VERBOSE) {
        console.log(`  ok  ${url}`);
      }
    });
  }
}

console.log(
  `check-links: ${files.length} Markdown files, ${checked} relative link(s), ` +
    `${anchors} anchor check(s)` +
    (CHECK_EXTERNAL
      ? `, ${external.size} external URL(s), ${skippedLocal} lab-local URL(s) skipped`
      : ''),
);
if (broken.length > 0) {
  console.error(`\nBROKEN (${broken.length}):`);
  for (const b of broken) console.error(`  ${b}`);
  process.exit(1);
}
console.log('check-links: OK — every relative link and in-repo anchor resolves.');
