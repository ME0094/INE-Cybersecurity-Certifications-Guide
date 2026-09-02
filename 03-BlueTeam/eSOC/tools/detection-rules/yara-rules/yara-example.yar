/*
 * EDUCATIONAL EXAMPLE YARA RULE (study only)
 * -------------------------------------------
 * YARA is a pattern-matching language for identifying malware samples,
 * memory dumps, and suspicious files. A rule holds string/byte patterns
 * plus a Boolean condition: when the condition is true for a scanned
 * object, the rule "fires" (matches).
 *
 * DETECTS: a Windows PE file or memory image holding credential-dumping
 * strings such as "mimikatz", "sekurlsa::", "privilege::debug", or a
 * reference to lsass.exe -- a strong hint of a credential-theft tool.
 *
 * STUDY ONLY: test it in your lab against a harmless text file you create
 * that contains those words; never run real malware without authorization.
 *   $ yara yara-example.yar suspicious.txt
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
