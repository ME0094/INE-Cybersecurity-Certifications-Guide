// markdown.mjs — shared helpers for the repository self-check scripts.
//
// Kept dependency-free on purpose: the checks must run on a bare Node install, both on
// a contributor's machine and in CI.

// Remove fenced code blocks (``` or ~~~), preserving line count so that reported line
// numbers still match the file on disk. Without this, a shell comment inside a code
// sample (`# start the collector`) is mistaken for a Markdown heading, and a command
// containing brackets is mistaken for a link.
export function stripFences(text) {
  let inFence = false;
  let marker = null;
  return text
    .split('\n')
    .map((line) => {
      const fence = line.match(/^\s*(```+|~~~+)/);
      if (fence) {
        if (!inFence) {
          inFence = true;
          marker = fence[1][0];
        } else if (fence[1][0] === marker) {
          inFence = false;
          marker = null;
        }
        return '';
      }
      return inFence ? '' : line;
    })
    .join('\n');
}

// GitHub's heading-anchor slug: lowercase, drop punctuation and formatting, whitespace to
// hyphens. Each whitespace character becomes one hyphen rather than runs collapsing, because
// that is what GitHub does: `## Common Mistakes & Tips` resolves as
// `#common-mistakes--tips`, and collapsing the run would both reject the real anchor and
// accept one that does not exist.
export function slugify(heading) {
  return heading
    .trim()
    .toLowerCase()
    .replace(/[`*_~]/g, '')
    .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/[^\p{L}\p{N}\s-]/gu, '')
    .trim()
    .replace(/\s/g, '-');
}

// All heading lines of a Markdown file, fences stripped.
export function headings(text) {
  return stripFences(text)
    .split('\n')
    .filter((line) => /^#{1,6}\s/.test(line));
}

// Slugs of every heading, with GitHub's -1/-2 suffixing for repeated headings.
export function headingSlugs(text) {
  const slugs = new Set();
  const seen = new Map();
  for (const line of headings(text)) {
    const base = slugify(line.replace(/^#{1,6}\s+/, ''));
    if (!base) continue;
    const n = seen.get(base) ?? 0;
    seen.set(base, n + 1);
    slugs.add(n === 0 ? base : `${base}-${n}`);
  }
  return slugs;
}
