#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_golden.py — сборка всех золотых лаб: spec → валидация → .pkt.

    python build_golden.py            # собрать всё в ../corpus/golden/
    python build_golden.py --out DIR

Выход: файлы .pkt + сводка. Код возврата 1, если хоть одна лаба не собралась.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import pt_build  # noqa: E402
import pt_tool  # noqa: E402
import validate as _v  # noqa: E402

GOLDEN_DIR = Path(__file__).parent / "golden"
DEFAULT_DONOR = Path(__file__).parent / "a.xml"


def build_one(spec_path: Path, out_dir: Path, donor: Path = DEFAULT_DONOR) -> tuple[bool, str]:
    spec = __import__("json").loads(spec_path.read_text(encoding="utf-8"))
    # 1) валидация (тихая, через core-функцию)
    registry = _v.load_registry(None)
    donor_index, donor_ports = _v.donor_device_index([donor])
    problems = _v.validate_spec(spec, registry, donor_index, donor_ports)
    errs = [p for p in problems if p["severity"] == "error"]
    if errs:
        return False, f"валидация: {len(errs)} ошибок: " + "; ".join(
            f"[{p['device']}] {p['message']}" for p in errs[:3]
        )

    # 2) сборка
    donor_xml = (
        donor.read_bytes()
        if donor.suffix.lower() == ".xml"
        else pt_tool.decrypt_pkt_auto(donor.read_bytes())
    )
    xml = pt_build.build(spec, donor_xml)
    out = out_dir / (spec_path.stem + ".pkt")
    out.write_bytes(pt_tool.encrypt_pkt(xml))

    # 3) контроль: расшифровка обратно + версия
    xml2 = pt_tool.decrypt_pkt_auto(out.read_bytes())
    if xml2 != xml:
        return False, f"roundtrip XML разошёлся для {out.name}"
    ver = "8.x"
    return True, f"{out} ({out.stat().st_size} Б, XML {len(xml)}, ошибок валидации 0)"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(Path(__file__).parent.parent / "corpus" / "golden"))
    ap.add_argument("--donor", default=str(DEFAULT_DONOR))
    args = ap.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    donor = Path(args.donor)

    specs = sorted(GOLDEN_DIR.glob("*.json"))
    if not specs:
        print("нет спек в golden/", file=sys.stderr)
        return 1
    ok = 0
    for s in specs:
        good, msg = build_one(s, out_dir, donor)
        print(("OK  " if good else "FAIL") + f" {s.name}: {msg}")
        ok += good
    print(f"\nсобрано {ok}/{len(specs)}")
    return 0 if ok == len(specs) else 1


if __name__ == "__main__":
    raise SystemExit(main())
