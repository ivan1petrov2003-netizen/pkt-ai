#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fix_templates.py - согласовать поля "template" JSON-спеки с реальным донором.
Использование: python fix_templates.py a.xml lab_L1.json
Для каждой роли ищет устройство донора по подстроке model и переписывает спеку:
имя донора -> "template", а если имён в доноре нет -> "model".
"""
import json
import sys
from pathlib import Path
from lxml import etree

ROLES = [
    ("Router1", ["4321", "4331"]),
    ("Switch0", ["2960"]),
    ("Switch5", ["2950T", "2960"]),
    ("PC0",     ["PC-PT", "PT-PC", "PC"]),
    ("Server0", ["SERVER"]),
    ("Laptop0", ["LAPTOP"]),
]

def inventory(path: Path):
    root = etree.fromstring(path.read_bytes(),
                            etree.XMLParser(recover=True, huge_tree=True))
    inv = []
    for dev in root.findall("NETWORK/DEVICES/DEVICE"):
        name = dev.findtext("ENGINE/NAME") or ""
        t = dev.find("ENGINE/TYPE")
        model = (t.get("model") or "") if t is not None else ""
        inv.append((name, model))
    return inv

def main() -> int:
    donor = Path(sys.argv[1] if len(sys.argv) > 1 else "a.xml")
    spec_path = Path(sys.argv[2] if len(sys.argv) > 2 else "lab_L1.json")
    inv = inventory(donor)
    if not inv:
        print("В доноре нет устройств - это не банк. Собери bank.pkt в PT 8.x")
        return 1

    mapping = {}
    for role, substrs in ROLES:
        found = None
        for s in substrs:
            for name, model in inv:
                if s.upper() in model.upper():
                    found = name or ("model:" + model)
                    break
            if found:
                break
        mapping[role] = found

    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    for d in spec.get("devices", []):
        new = mapping.get(d.get("template"))
        if not new:
            print(f"WARNING: в доноре нет роли {d.get('template')} для {d['name']}")
            continue
        if new.startswith("model:"):
            d.pop("template", None)
            d["model"] = new[len("model:"):]
        else:
            d["template"] = new

    spec_path.write_text(json.dumps(spec, ensure_ascii=False, indent=2), encoding="utf-8")
    for role, new in mapping.items():
        print(f"{role:10} -> {new}")
    print(f"переписал {spec_path}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())