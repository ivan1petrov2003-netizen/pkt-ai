#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Печать inventory донора: имя, model, число портов. Использование: python donor_list.py a.xml"""
import sys
from pathlib import Path
from lxml import etree

def main() -> int:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "a.xml")
    root = etree.fromstring(path.read_bytes(),
                            etree.XMLParser(recover=True, huge_tree=True))
    devs = root.findall("NETWORK/DEVICES/DEVICE")
    if not devs:
        print("В доноре нет NETWORK/DEVICES/DEVICE - это НЕ банк шаблонов")
        return 1
    for dev in devs:
        name = dev.findtext("ENGINE/NAME") or "<без имени>"
        t = dev.find("ENGINE/TYPE")
        model = (t.get("model") or "?") if t is not None else "?"
        nports = len(list(dev.iter("PORT")))
        print(f"{name:28} | model={model:30} | ports={nports}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())