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
- `binary/`: binary-side fixtures covering PE/ELF strings, packed-section cues, resource staging, import, loader, dynamic-symbol, and self-relaunch relationships, plus parser-depth regressions
- `encoded/`: encoded text that decodes into suspicious but harmless placeholder behavior

Some parser-depth regressions also use deterministic PE/ELF byte builders from `tests/support/parser_fixtures.rs` so tests can exercise real header, import-table, and ELF symbol-table parsing without adding executable or unsafe blobs to the repository.
The parser regression layer also includes near-threshold PE/ELF binary cases to keep borderline parsed-structure behavior consistent across formats.
