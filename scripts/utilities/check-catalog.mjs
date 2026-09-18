#!/usr/bin/env node
// check-catalog.mjs — repository self-check.
//
// The failure mode this guards against is the one that actually bit this repository:
// the certification catalog in README.md drifting away from what is on disk — a module
// folder that no table links to, a table row pointing at a folder that was moved or
// renamed, a module missing one of the four conventional subfolders.
//
// Usage:
//   node scripts/utilities/check-catalog.mjs [root] [--verbose]
//
// Exit codes: 0 = consistent, 1 = drift found, 2 = usage/IO error.
// Dependencies: none (Node stdlib only).

import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, resolve, relative, sep } from 'node:path';
import { headings } from './markdown.mjs';

const argv = process.argv.slice(2);
const flags = new Set(argv.filter((a) => a.startsWith('--')));
const positional = argv.filter((a) => !a.startsWith('--'));
const ROOT = resolve(positional[0] ?? '.');
const VERBOSE = flags.has('--verbose');

const AREAS = ['01-Fundamentals', '02-RedTeam', '03-BlueTeam', '04-Emerging-Technologies'];
const REQUIRED_SUBFOLDERS = ['methodology', 'tools', 'labs', 'cheatsheets'];
const README = join(ROOT, 'README.md');

if (!existsSync(README)) {
  console.error(`check-catalog: no README.md in ${ROOT}`);
  process.exit(2);
}

// --- what is on disk -------------------------------------------------------------
const onDisk = [];
const structureProblems = [];
for (const area of AREAS) {
  const areaDir = join(ROOT, area);
  if (!existsSync(areaDir)) {
    structureProblems.push(`${area}/ is missing`);
    continue;
  }
  for (const entry of readdirSync(areaDir, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const moduleDir = join(areaDir, entry.name);
    const moduleReadme = join(moduleDir, 'README.md');
    if (!existsSync(moduleReadme)) {
      structureProblems.push(`${area}/${entry.name}/ has no README.md`);
      continue;
    }
    // Sample images and scratch folders are not modules.
    // Every directory that holds a README is a module, even before its subfolders exist:
    // skipping the empty case would hide exactly the mistake this check exists to catch.
    onDisk.push(`${area}/${entry.name}`);
    for (const sub of REQUIRED_SUBFOLDERS) {
      if (!existsSync(join(moduleDir, sub))) {
        structureProblems.push(`${area}/${entry.name}/ is missing ${sub}/`);
      }
    }
  }
}

// --- house style: every module note is a title, a checklist and a resources list ---
// Kept deliberately lenient: the heading only has to *contain* "Checklist" or
// "Further Resources", so "## Module Checklist" and "## Progress Checklist" both pass.
// The H1 rule is exact, because a file without a single H1 breaks the anchor slugs.
function mdFiles(dir, out = []) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) mdFiles(join(dir, entry.name), out);
    else if (entry.isFile() && entry.name.toLowerCase().endsWith('.md')) out.push(join(dir, entry.name));
  }
  return out;
}

const styleProblems = [];
for (const modulePath of onDisk) {
  const [area, name] = modulePath.split('/');
  const moduleReadme = readFileSync(join(ROOT, area, name, 'README.md'), 'utf8');
  for (const file of mdFiles(join(ROOT, area, name))) {
    const rel = relative(ROOT, file).split(sep).join('/');
    const base = file.split(sep).pop();
    const headingLines = headings(readFileSync(file, 'utf8'));
    const h1s = headingLines.filter((line) => /^#\s/.test(line));
    if (h1s.length !== 1) styleProblems.push(`${rel}: expected exactly one H1, found ${h1s.length}`);
    if (!headingLines.some((line) => /^#{2,3}\s.*Checklist/.test(line))) {
      styleProblems.push(`${rel}: no "## … Checklist" section`);
    }
    if (!headingLines.some((line) => /^#{2,3}\s.*Further Resources/.test(line))) {
      styleProblems.push(`${rel}: no "## Further Resources" section`);
    }
    // The module README is the index: a note nobody links is invisible to readers.
    // This is the failure mode that actually happened here — files written but never
    // indexed after a long editing session. Both "01-foo.md" and "01-foo" count as a
    // reference, because module indexes in this repository use both styles.
    if (base !== 'README.md') {
      const stem = base.replace(/\.md$/i, '');
      if (!moduleReadme.includes(base) && !moduleReadme.includes(stem)) {
        styleProblems.push(`${rel}: ORPHAN — not referenced from ${area}/${name}/README.md`);
      }
    }
  }
}

// --- what README.md claims -------------------------------------------------------
const readme = readFileSync(README, 'utf8');
const linked = new Set();
const linkRe = /\]\((0[1-4]-[A-Za-z-]+\/([A-Za-z0-9._-]+)\/README\.md)(?:#[^)]*)?\)/g;
for (const m of readme.matchAll(linkRe)) linked.add(`${m[1].split('/')[0]}/${m[2]}`);

const missingFromReadme = onDisk.filter((m) => !linked.has(m));
const pointingNowhere = [...linked].filter(
  (m) => !existsSync(join(ROOT, m.split('/')[0], m.split('/')[1], 'README.md')),
);

// --- report ----------------------------------------------------------------------
if (VERBOSE) {
  console.log(`Modules on disk: ${onDisk.length}`);
  for (const m of onDisk) console.log(`  ${m}`);
  console.log(`Modules linked from README.md: ${linked.size}`);
}

let failed = false;
if (structureProblems.length > 0) {
  failed = true;
  console.error(`\nSTRUCTURE (${structureProblems.length}):`);
  for (const p of structureProblems) console.error(`  ${p}`);
}
if (missingFromReadme.length > 0) {
  failed = true;
  console.error(`\nIN DISK BUT NOT IN README.md (${missingFromReadme.length}):`);
  for (const m of missingFromReadme) console.error(`  ${m}`);
}
if (pointingNowhere.length > 0) {
  failed = true;
  console.error(`\nLINKED FROM README.md BUT NOT ON DISK (${pointingNowhere.length}):`);
  for (const m of pointingNowhere) console.error(`  ${m} (${relative(ROOT, README).split(sep).join('/')})`);
}
if (styleProblems.length > 0) {
  failed = true;
  console.error(`\nHOUSE STYLE (${styleProblems.length}):`);
  for (const p of styleProblems.slice(0, 40)) console.error(`  ${p}`);
  if (styleProblems.length > 40) console.error(`  … and ${styleProblems.length - 40} more`);
}

if (failed) {
  console.error('\ncheck-catalog: FAILED — the catalog and the repository disagree.');
  process.exit(1);
}
console.log(
  `check-catalog: OK — ${onDisk.length} modules on disk, all linked from README.md, ` +
    `all with ${REQUIRED_SUBFOLDERS.join('/')}, and every module note keeps the ` +
    `H1 + Checklist + Further Resources convention.`,
);
