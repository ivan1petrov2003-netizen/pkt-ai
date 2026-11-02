#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
export_spec.py — обратный экспорт: собранный .pkt → IR-спека (формат pt_build).

Пригодится для: (1) few-shot примеров для LLM из реальных лаб,
(2) восстановления спеки, когда конфиги в источнике полные.

ВАЖНО: экспортируйте из файла, СОБРАННОГО генератором (авторские конфиги),
а не из файла, пересохранённого в PT (PT переносит настройки EtherChannel
на интерфейс Port-channel и теряет привязку физических портов).

    python export_spec.py in.pkt -o spec.json [--donor донор.pkt]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from lxml import etree

sys.path.insert(0, str(Path(__file__).parent))
import pt_tool  # noqa: E402


def export(path: Path, donor: Path | None = None) -> dict:
    xml = pt_tool.decrypt_pkt_auto(path.read_bytes())
    root = etree.fromstring(xml, etree.XMLParser(recover=True, huge_tree=True))
    net = root.find("NETWORK")
    if net is None:
        raise ValueError("нет NETWORK")

    ref2name: dict[str, str] = {}
    devices = []
    for dev in net.findall("DEVICES/DEVICE"):
        eng = dev.find("ENGINE")
        name = eng.findtext("NAME") or "?"
        ref = eng.findtext("SAVE_REF_ID") or ""
        if ref:
            ref2name[ref] = name
        t = eng.find("TYPE")
        d: dict = {"name": name, "model": (t.get("model") or "") if t is not None else ""}
        lx = dev.find("WORKSPACE/LOGICAL")
        if lx is not None:
            d["x"] = int(float(lx.findtext("X") or 0))
            d["y"] = int(float(lx.findtext("Y") or 0))
        cfg = eng.find("RUNNINGCONFIG")
        if cfg is not None:
            lines = [(ln.text or "") for ln in cfg.findall("LINE")]
            if any(l.strip() for l in lines):
                d["config"] = lines
        # VLAN-база (кастомные, кроме 1 и 1002–1005)
        vlans = []
        ev = eng.find("VLANS")
        if ev is not None:
            for v in ev.findall("VLAN"):
                try:
                    vid = int(v.get("number"))
                except (TypeError, ValueError):
                    continue
                if vid != 1 and vid < 1002:
                    vlans.append({"id": vid, "name": v.get("name") or f"VLAN{vid:04d}"})
        if vlans:
            d["vlans"] = vlans
        # статический IP хостовых
        for port in dev.findall(".//PORT"):
            ip = port.findtext("IP") or ""
            if ip and not ip.startswith("169.254.") and port.findtext("PORT_GATEWAY"):
                d["ip"] = ip
                d["mask"] = port.findtext("SUBNET") or "255.255.255.0"
                d["gateway"] = port.findtext("PORT_GATEWAY") or ""
                dns = port.findtext("PORT_DNS") or ""
                if dns:
                    d["dns"] = dns
                break
        devices.append(d)

    links = []
    for link in net.findall("LINKS/LINK"):
        cable = link.find("CABLE")
        if cable is None:
            continue
        a, b = ref2name.get(cable.findtext("FROM") or ""), ref2name.get(cable.findtext("TO") or "")
        ports = [p.text or "" for p in cable.findall("PORT")]
        if not a or not b or len(ports) < 2:
            continue
        l = {"from": a, "from_port": ports[0], "to": b, "to_port": ports[1]}
        ct = cable.findtext("TYPE") or ""
        if ct and ct != "eStraightThrough":
            l["cable"] = ct
        links.append(l)

    spec = {"meta": {"name": path.stem, "source": str(path)}, "devices": devices, "links": links}
    if donor:
        spec["meta"]["donor"] = Path(donor).name
    return spec


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("--donor", default=None)
    args = ap.parse_args()
    spec = export(Path(args.input), Path(args.donor) if args.donor else None)
    Path(args.output).write_text(json.dumps(spec, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"export: {len(spec['devices'])} устройств, {len(spec['links'])} линков -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
