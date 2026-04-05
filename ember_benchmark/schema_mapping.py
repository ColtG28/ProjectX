#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

from projectx_ember_schema import write_schema_mapping_files


def main() -> int:
    root = Path(__file__).resolve().parent
    write_schema_mapping_files(root / "schema_mapping.json", root / "schema_mapping.md")
    print(root / "schema_mapping.json")
    print(root / "schema_mapping.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
