# Suspicious-Safe Fixture Corpus

These fixtures are synthetic, inert samples designed to exercise strong passive detection logic.

They are intentionally suspicious in wording and structure, but they remain harmless because they use:

- dummy or invalid domains
- placeholder commands
- non-functional script fragments
- synthetic import or symbol strings
- inert encoded content

They must never contain:

- real malware
- working payloads
- credential theft
- persistence logic
- destructive behavior

Categories:

- `scripts/`: downloader or launcher-like script chains with inert endpoints
- `office/`: macro-like automation and download patterns expressed as inert text
- `binary/`: binary-side fixtures covering PE/ELF/Mach-O strings, packed-section cues, entrypoint and resource relationships, import, loader, dynamic-symbol, static-symbol, linked-library, relative loader-path, and self-relaunch relationships, plus parser-depth regressions
- `encoded/`: encoded text that decodes into suspicious but harmless placeholder behavior
- newer additions broaden this slice with archive extract-and-run phrasing, fetch/decode/blob chains, Mach-O loader/network wording, and encoded stager-style configuration notes that remain inert

Some parser-depth regressions also use deterministic PE/ELF/Mach-O byte builders from `tests/support/parser_fixtures.rs` so tests can exercise real header, import-table, ELF symbol-table, and Mach-O load-command parsing without adding executable or unsafe blobs to the repository.
The parser regression layer also includes near-threshold PE/ELF/Mach-O binary cases to keep borderline parsed-structure behavior consistent across formats.
The intelligence-layer regressions also verify that confidence-tagged local rule families remain explainable, retain useful family context in reports, and continue to escalate suspicious-safe cases without external lookups or trust-based suppression.
