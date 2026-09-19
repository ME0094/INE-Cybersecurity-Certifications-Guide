#!/usr/bin/env node
// fetch-tool-spec.mjs — build a tool's flag catalogue from its own documentation.
//
// The point of this script is that a checker is only as good as its catalogue, and a
// catalogue written from memory is exactly the defect this repository is trying to remove.
// So the catalogue is *downloaded*, and each spec records where it came from, when, and
// which version the page described. Nothing here is typed by hand.
//
// Usage:
//   node scripts/utilities/fetch-tool-spec.mjs --tool nmap \
//        --url https://nmap.org/book/man.html \
//        --aliases nmap --version 7.95 \
//        [--subcommands-from-url <url>] [--out <path>]
//
// Design rule, deliberately chosen: **the catalogue errs toward permissive.** A spec that
// contains a flag that does not really exist costs a missed detection; a spec that is
// missing a real flag makes the checker cry wolf, and a checker that cries wolf gets
// switched off. Over-extraction is the safe failure.
//
// Exit codes: 0 written, 1 the page could not be fetched, 2 bad usage.

import { writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

const args = process.argv.slice(2);
function arg(name, fallback = null) {
  const i = args.indexOf(`--${name}`);
  return i >= 0 && args[i + 1] ? args[i + 1] : fallback;
}

const tool = arg('tool');
const url = arg('url');
const version = arg('version', 'unspecified');
const aliases = (arg('aliases') ?? tool ?? '').split(',').map((s) => s.trim()).filter(Boolean);
const subcommandsFromUrl = arg('subcommands-from-url');
if (!tool || !url) {
  console.error('usage: fetch-tool-spec.mjs --tool <name> --url <docs-url> [--aliases a,b] [--version x] [--subcommands-from-url url]');
  process.exit(2);
}

async function get(target) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 30000);
  try {
    const res = await fetch(target, {
      redirect: 'follow',
      headers: { 'user-agent': 'INE-Cybersecurity-Certifications-Guide spec builder' },
      signal: controller.signal,
    });
    return { status: res.status, body: await res.text() };
  } catch (err) {
    return { status: 0, body: `ERR ${err.message}` };
  } finally {
    clearTimeout(timer);
  }
}

function toText(body) {
  // Only strip markup when the source is actually markup. A C file or a man page has
  // `<` characters that are code, not tags, and eating them destroys flags like `-p<ports>`.
  const isMarkup = /<\s*(html|div|body|head|p|span|pre|table)\b/i.test(body);
  if (!isMarkup) return body.replace(/\s+/g, ' ');
  return body
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&#x27;|&#39;/g, "'")
    .replace(/&quot;/g, '"')
    .replace(/\s+/g, ' ');
}

const page = await get(url);
if (page.status === 0 || page.status >= 400) {
  console.error(`could not fetch ${url} (${page.status || 'no response'})`);
  process.exit(1);
}
const text = toText(page.body);

// Flags as they appear in a manual: -sS, --script, -T<0-5> (the placeholder is trimmed).
const longFlags = new Set();
const shortFlags = new Set();
for (const m of text.matchAll(/(^|[\s(,])(--[A-Za-z][A-Za-z0-9-]{1,40})/g)) longFlags.add(m[2]);
for (const m of text.matchAll(/(^|[\s(,])(-[A-Za-z][A-Za-z0-9]{0,5})(?=[\s,)<\/|]|$)/g)) {
  if (m[2].startsWith('--')) continue;
  shortFlags.add(m[2]);
}
// A manual lists `-T<0-5>` or `-p <port ranges>`; keep the bare stem as well.
for (const m of text.matchAll(/(^|[\s(,])(-[A-Za-z][A-Za-z0-9]{0,5})(?=[<\[])/g)) shortFlags.add(m[2]);

const spec = {
  tool,
  aliases: aliases.length > 0 ? aliases : [tool],
  provenance: {
    source: url,
    version,
    fetched: new Date().toISOString().slice(0, 10),
    note: 'Flag names extracted mechanically from the tool\'s own documentation. Extraction is deliberately over-inclusive.',
  },
  longFlags: [...longFlags].sort(),
  shortFlags: [...shortFlags].sort(),
  subcommands: null,
};

if (subcommandsFromUrl) {
  const sub = await get(subcommandsFromUrl);
  if (sub.status === 0 || sub.status >= 400) {
    console.error(`could not fetch ${subcommandsFromUrl} (${sub.status || 'no response'})`);
    process.exit(1);
  }
  // Two useful shapes: a directory listing of files (plugin trees) and a shell list.
  const names = new Set();
  for (const m of sub.body.matchAll(/"name"\s*:\s*"([^"]+\.(py|go|mkape|sh))"/g)) {
    names.add(m[1].replace(/\.(py|go|mkape|sh)$/, ''));
  }
  for (const m of sub.body.matchAll(/(?:^|\n)\s*([a-z][a-z0-9-]{2,30})(?=\s|$)/g)) names.add(m[1]);
  spec.subcommands = [...names].sort();
}

const out = arg('out') ?? resolve('scripts/utilities/tool-specs', `${tool.replace(/[^\w.-]/g, '_')}.json`);

// A catalogue that is too thin is worse than none: it makes the checker report healthy
// commands as broken, and a checker that cries wolf gets switched off. Refuse to write one.
const minFlags = Number(arg('min-flags', '12'));
const total = spec.longFlags.length + spec.shortFlags.length;
if (total < minFlags) {
  console.error(
    `REFUSED: only ${total} flags extracted from ${url} (minimum ${minFlags}).\n` +
      `That usually means the page is an index rather than the flag list. Point --url at a\n` +
      `source that enumerates the options — the tool's source code, its man page source, or\n` +
      `its --help output — and run again. Writing this catalogue would make the checker cry wolf.`,
  );
  process.exit(1);
}

if (!existsSync(dirname(out))) mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, `${JSON.stringify(spec, null, 2)}\n`, 'utf8');
console.log(
  `wrote ${out}\n  long flags: ${spec.longFlags.length}\n  short flags: ${spec.shortFlags.length}` +
    (spec.subcommands ? `\n  subcommands: ${spec.subcommands.length}` : ''),
);
