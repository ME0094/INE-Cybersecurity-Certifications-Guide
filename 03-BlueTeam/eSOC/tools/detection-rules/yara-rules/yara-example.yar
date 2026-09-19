/*
 * EDUCATIONAL EXAMPLE YARA RULE (study only)
 * -------------------------------------------
 * YARA is a pattern-matching language for identifying malware samples,
 * memory dumps, and suspicious files. A rule holds string/byte patterns
 * plus a Boolean condition: when the condition is true for a scanned
 * object, the rule "fires" (matches).
 *
 * DETECTS: two rules over the same string set, such as "mimikatz",
 * "sekurlsa::", "privilege::debug", or a reference to lsass.exe.
 *   - Suspicious_CredDump_Strings_PE      -- fires only on a real PE file (or
 *     a memory image holding one) that also carries the strings: a strong
 *     hint of a credential-theft tool.
 *   - Suspicious_CredDump_Strings_AnyFile -- the same strings with no file
 *     type required, so it is the rule that fires on the harmless .txt the
 *     drill below has you create. Low signal on its own: a note someone
 *     saved reads the same as a staged payload at this level.
 *
 * STUDY ONLY: test it in your lab against a harmless text file you create
 * that contains those words; never run real malware without authorization.
 *   $ yara yara-example.yar suspicious.txt     # matches ..._AnyFile only
 *   $ yara yara-example.yar some-unsigned.exe  # what ..._PE is there for
 *
 * Syntax: block comments (slash-star ... star-slash) and // line comments;
 * rule names must start with a letter or underscore.
 */

// Import the PE module so rules can use pe.* helpers. Scanning a non-PE
// file simply produces no PE-based match (no error).
import "pe"

rule Suspicious_CredDump_Strings_PE
{
    // meta is informational: it travels with every match but never
    // influences whether the rule fires.
    meta:
        author = "Your Name (example for study)"
        description = "PE files carrying common credential-dumping tool strings (Mimikatz-style) - educational example"
        date = "2024/06/01"
        reference = "https://attack.mitre.org/techniques/T1003/001/"
        severity = "high"

    // strings: each $ identifier is one pattern searched across the whole
    // scanned object (file bytes or memory).
    strings:
        // Text modifiers: 'ascii' = single-byte text, 'wide' = UTF-16 (how
        // Windows stores strings internally), 'nocase' = case-insensitive.
        $s1 = "mimikatz" ascii wide nocase
        $s2 = "sekurlsa" ascii wide nocase
        $s3 = "logonpasswords" ascii wide nocase
        $s4 = "privilege::debug" ascii wide nocase
        $s5 = "lsass.exe" ascii wide nocase
        // Hex strings match exact byte sequences (whitespace is ignored and
        // '??' is a wildcard). This hex spells "Mimikatz" in ASCII bytes to
        // demonstrate the syntax.
        $h1 = { 4D 69 6D 69 6B 61 74 7A }

    // condition: a Boolean over the strings and file properties. The
    // expression only fires on a real PE that ALSO carries enough dump-tool
    // strings OR the exact hex signature. YARA short-circuits, so
    // "pe.is_pe and ..." is safe to evaluate on any file.
    condition:
        pe.is_pe
        and (
            3 of ($s*)   // at least 3 of the 5 text strings must be present
            or $h1       // ... or the exact hex "Mimikatz" bytes must match
        )
        // A minimum string count reduces false positives from one generic
        // word (e.g. a log file that merely mentions "lsass.exe").
}

/*
 * The same string set, with no PE requirement at all. This is the rule the
 * drills in ../../../labs/soc-scenarios.md and ../../../labs/sigma-rule-tuning.md
 * exercise against a harmless text file: the match they promise is reachable
 * only because nothing here constrains the file type. YARA has no way to share
 * a strings block between two rules in one file, so the set is repeated --
 * deliberately, rather than by accident.
 *
 * Read a hit from this rule as a lead, never as a verdict: a saved note and a
 * staged payload match identically here, which is exactly why the PE rule above
 * exists next to it.
 */
rule Suspicious_CredDump_Strings_AnyFile
{
    meta:
        author = "Your Name (example for study)"
        description = "Any file (text, script, log, binary) carrying common credential-dumping tool strings - low signal on its own, educational example"
        date = "2024/06/01"
        reference = "https://attack.mitre.org/techniques/T1003/001/"
        severity = "low"

    strings:
        $s1 = "mimikatz" ascii wide nocase
        $s2 = "sekurlsa" ascii wide nocase
        $s3 = "logonpasswords" ascii wide nocase
        $s4 = "privilege::debug" ascii wide nocase
        $s5 = "lsass.exe" ascii wide nocase
        $h1 = { 4D 69 6D 69 6B 61 74 7A }

    // No pe.is_pe term: this condition is what makes a plain .txt match. The
    // minimum count of 3 still keeps a single generic word from firing it.
    condition:
        3 of ($s*)
        or $h1
}

/*
 * Bonus: a 'private' rule cannot fire on its own; other rules reference it
 * by name to reuse shared logic, e.g. "IsWindowsExecutable and <...>".
 */
private rule IsWindowsExecutable
{
    condition:
        // uint16(0) reads an unsigned 16-bit integer at file offset 0.
        // 0x5A4D is little-endian 'MZ', the DOS header magic of every
        // Windows PE file -- a cheap PE check that needs no module.
        uint16(0) == 0x5A4D
}

/*
 * VERIFICATION -- executed with yara 4.5.0 on 2026-09-19, against files created
 * under /tmp (nothing was written inside the repository):
 *
 *   $ yara yara-example.yar suspicious.txt       -> Suspicious_CredDump_Strings_AnyFile
 *   $ yara yara-example.yar pe-with-strings.exe  -> Suspicious_CredDump_Strings_PE
 *                                                   Suspicious_CredDump_Strings_AnyFile
 *   $ yara yara-example.yar notepad.exe          -> no match
 *   $ yara yara-example.yar benign.txt           -> no match
 *   $ yara yara-example.yar fake-pe.bin          -> Suspicious_CredDump_Strings_AnyFile only
 *                                                   (starts with 'MZ' but is not a valid PE)
 *
 * The same suspicious.txt returned NO match under the earlier single-rule
 * version of this file, because that condition required pe.is_pe: a plain text
 * file could never satisfy it. That is the defect the second rule fixes.
 * Not verified: Windows-side behaviour (this ran under WSL Ubuntu 24.04).
 */
