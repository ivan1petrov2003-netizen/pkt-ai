#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pkt_graph.py - turn decrypted Packet Tracer XML into a compact JSON topology
that is easy for a human or an LLM to read and regenerate.

    python pkt_graph.py a.xml -o topology.json
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from lxml import etree


def parse_xml(text: str):
    """Parse Packet Tracer XML, tolerating the binary junk in log entries."""
    parser = etree.XMLParser(recover=True, huge_tree=True)
    data = text.encode("utf-8", errors="replace")
    return etree.fromstring(data, parser)


def _text(el, path, default=""):
    found = el.find(path)
    if found is None or found.text is None:
        return default
    return found.text.strip()


def _config_lines(device):
    lines = []
    for conf in device.iter("RUNNINGCONFIG"):
        for line in conf.iter("LINE"):
            if line.text and line.text.strip():
                lines.append(line.text.rstrip())
    # drop duplicates while keeping order (PT often stores running+startup)
    seen = set()
    out = []
    for line in lines:
        if line not in seen:
            seen.add(line)
            out.append(line)
    return out


def _port_info(device):
    ports = []
    seen = set()
    for port in device.iter("PORT"):
        ip = _text(port, "IP")
        mask = _text(port, "SUBNET")
        gw = _text(port, "PORT_GATEWAY")
        if not ip:
            continue
        key = (ip, mask, gw)
        if key in seen:
            continue
        seen.add(key)
        ports.append({"ip": ip, "mask": mask, "gateway": gw})
    return ports


_INTERFACE_RE = re.compile(r"^interface\s+(\S+)", re.I)


def _interfaces_from_config(lines):
    """Group running-config lines by interface."""
    result = []
    current = None
    for line in lines:
        stripped = line.strip()
        m = _INTERFACE_RE.match(stripped)
        if m:
            current = {"name": m.group(1), "lines": []}
            result.append(current)
            continue
        if current is not None and stripped:
            current["lines"].append(stripped)
    return result


def build_graph(xml_text: str) -> dict:
    root = parse_xml(xml_text)
    network = root.find("NETWORK")
    if network is None:
        raise ValueError("no <NETWORK> element - is this really a Packet Tracer file?")

    devices = []
    by_ref = {}
    for dev in network.findall("DEVICES/DEVICE"):
        name = _text(dev, "ENGINE/NAME")
        model = ""
        type_el = dev.find("ENGINE/TYPE")
        if type_el is not None:
            model = type_el.get("model") or ""
        ref = _text(dev, "ENGINE/SAVE_REF_ID")
        entry = {
            "name": name,
            "model": model,
            "type": (type_el.text or "").strip() if type_el is not None else "",
            "ref": ref,
            "x": _text(dev, "WORKSPACE/LOGICAL/X"),
            "y": _text(dev, "WORKSPACE/LOGICAL/Y"),
        }
        ports = _port_info(dev)
        if ports:
            entry["ip_config"] = ports
        ssid = _text(dev, "ENGINE/WIRELESS_CLIENT/WIRELESS_COMMON/SSID")
        if ssid:
            entry["ssid"] = ssid
        gateway = _text(dev, "ENGINE/GATEWAY")
        if gateway:
            entry["gateway"] = gateway
        config = _config_lines(dev)
        if config:
            entry["config"] = config
            ifaces = _interfaces_from_config(config)
            if ifaces:
                entry["interfaces"] = ifaces
        devices.append(entry)
        if ref:
            by_ref[ref] = entry

    links = []
    for link in network.findall("LINKS/LINK"):
        cable = link.find("CABLE")
        if cable is None:
            continue
        src = _text(cable, "FROM")
        dst = _text(cable, "TO")
        links.append({
            "from": by_ref.get(src, {}).get("name", src),
            "from_port": _text(cable, "PORT"),
            "to": by_ref.get(dst, {}).get("name", dst),
            "to_port": _text(cable, "PORT"),
            "link_type": _text(link, "TYPE"),
            "cable": _text(cable, "TYPE"),
        })

    # "PORT" appears twice in CABLE; the second one belongs to "TO"
    for link, link_el in zip(links, network.findall("LINKS/LINK")):
        ports = link_el.findall("CABLE/PORT")
        if len(ports) >= 2 and ports[1].text:
            link["to_port"] = ports[1].text.strip()

    return {
        "version": _text(root, "VERSION"),
        "device_count": len(devices),
        "link_count": len(links),
        "devices": devices,
        "links": links,
    }


def main(argv=None) -> int:
    argv = argv or sys.argv[1:]
    if not argv:
        print("usage: python pkt_graph.py <decrypted.xml> [-o out.json]", file=sys.stderr)
        return 2
    src = Path(argv[0])
    dst = None
    if "-o" in argv:
        dst = Path(argv[argv.index("-o") + 1])
    graph = build_graph(src.read_text(encoding="utf-8", errors="replace"))
    text = json.dumps(graph, ensure_ascii=False, indent=2)
    if dst:
        dst.write_text(text, encoding="utf-8")
        print(f"graph written to {dst}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
