#!/usr/bin/env python3
"""
Diaphora, a binary diffing tool
Copyright (c) 2015-2026 Joxean Koret
Copyright (c) 2026 ClaudeMonkey (Java port, Claude-Rays/diaphora-ng-ghidra)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

Generate src/main/resources/diaphorang/heuristics.json from the original
diaphora_heuristics.py, so the Java port runs the same SQL heuristics as the
IDAPython version.

Usage:
  python tools/gen_heuristics.py [path\\to\\diaphora]

The default diaphora path is ..\\diaphora (next to this repository).
"""
import os
import sys
import json

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if len(sys.argv) > 1:
    DIAPHORA_DIR = os.path.abspath(sys.argv[1])
else:
    DIAPHORA_DIR = os.path.abspath(os.path.join(ROOT, "..", "diaphora"))

sys.path.insert(0, DIAPHORA_DIR)
import diaphora_heuristics as h

def main():
    heuristics = []
    for heur in h.HEURISTICS:
        flags_list = list(heur.get("flags", []))
        heuristics.append({
            "name": heur["name"],
            "category": heur["category"],
            "ratio": heur["ratio"],
            "min": float(heur.get("min", 0.0)),
            "flags": flags_list,
            "sql": heur["sql"].strip()
        })

    out_path = os.path.join(ROOT, "src", "main", "resources", "diaphorang", "heuristics.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(heuristics, f, indent=2)
    print(f"Generated {len(heuristics)} heuristics into {out_path}")

if __name__ == "__main__":
    main()
