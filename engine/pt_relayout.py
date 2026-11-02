#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pt_relayout.py - rebuild the lab with a new layout, new VLAN colours and a new
IP subnet, keeping every device and configuration from the source file.

    python pt_relayout.py a.xml -o lab_18.pkt

What it does:
  * rewrites 192.168.7.x -> 192.168.18.x everywhere (configs, ports, DHCP);
  * groups devices by the coloured VLAN rectangle they belong to;
  * moves every rectangle together with its devices to a new position;
  * recolours the rectangles;
  * repacks the result into .pkt.
"""

from __future__ import annotations

import argparse
import copy
import random
import uuid as uuidlib
from pathlib import Path

from lxml import etree

import pt_tool

OLD_PREFIX = "192.168.7."
NEW_PREFIX = "192.168.18."

# new zone layout: key -> (x, y, w, h, (r, g, b), title)
NEW_ZONES = {
    "Design":     (60,   190, 520, 270, (173, 216, 255), "VLAN 10 - Design"),
    "Accounting": (640,  190, 500, 270, (183, 244, 197), "VLAN 20 - Accounting"),
    "Management": (1200, 190, 480, 270, (255, 224, 178), "VLAN 30 - Management"),
    "Servers":    (120,  520, 460, 280, (214, 198, 255), "VLAN 40 - Servers"),
    "Wireless":   (640,  520, 460, 280, (178, 235, 242), "VLAN 50 - Guests"),
}

# fixed positions for the core devices
CORE_POS = {
    "Router0": (930, 10),
    "Switch0": (930, 85),
    "Cloud0": (1150, 5),
    "Power Distribution Device0": (1720, 880),
}


def parse(data: bytes):
    parser = etree.XMLParser(recover=True, huge_tree=True)
    return etree.fromstring(data, parser)


def set_ip_subnet(root):
    changed = 0
    for el in root.iter():
        if el.text and OLD_PREFIX in el.text:
            el.text = el.text.replace(OLD_PREFIX, NEW_PREFIX)
            changed += 1
        if el.tail and OLD_PREFIX in el.tail:
            el.tail = el.tail.replace(OLD_PREFIX, NEW_PREFIX)
            changed += 1
    return changed


def logical_pos(dev):
    x = dev.findtext("WORKSPACE/LOGICAL/X")
    y = dev.findtext("WORKSPACE/LOGICAL/Y")
    try:
        return float(x), float(y)
    except (TypeError, ValueError):
        return None


def set_logical_pos(dev, x, y):
    lx = dev.find("WORKSPACE/LOGICAL/X")
    ly = dev.find("WORKSPACE/LOGICAL/Y")
    if lx is not None:
        lx.text = str(int(round(x)))
    if ly is not None:
        ly.text = str(int(round(y)))


def rect_bounds(rect):
    def val(tag):
        return float(rect.findtext(tag))

    return val("TopLeftX"), val("TopLeftY"), val("BottomRightX"), val("BottomRightY")


def zone_of(x, y, rects, pad=140):
    """Return the rectangle which owns this device (nearest, inside padded box)."""
    best = None
    best_d = None
    for rect, (x0, y0, x1, y1) in rects:
        if x0 - pad <= x <= x1 + pad and y0 - pad <= y <= y1 + pad:
            cx, cy = (x0 + x1) / 2, (y0 + y1) / 2
            d = (x - cx) ** 2 + (y - cy) ** 2
            if best_d is None or d < best_d:
                best, best_d = rect, d
    return best


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("-o", "--output", required=True)
    args = ap.parse_args(argv)

    raw = Path(args.input).read_bytes()
    if args.input.lower().endswith((".pkt", ".pka")):
        raw = pt_tool.decrypt_pkt(raw)
    root = parse(raw)

    network = root.find("NETWORK")
    devices = network.findall("DEVICES/DEVICE")
    rects_el = root.find("RECTANGLES")
    rects = rects_el.findall("RECTANGLE") if rects_el is not None else []
    bounds = [(r, rect_bounds(r)) for r in rects]

    # --- 1. new IP subnet -------------------------------------------------
    n = set_ip_subnet(root)
    print(f"IP addresses rewritten: {n} values")

    # --- 2. assign devices to zones --------------------------------------
    zones = {r: [] for r in rects}
    core = []
    for dev in devices:
        name = dev.findtext("ENGINE/NAME") or ""
        pos = logical_pos(dev)
        if pos is None or name in CORE_POS:
            core.append(dev)
            continue
        owner = zone_of(pos[0], pos[1], bounds)
        if owner is None:
            core.append(dev)
        else:
            zones[owner].append(dev)

    # sort rectangles by their current position so the mapping is stable
    ordered = sorted(rects, key=lambda r: rect_bounds(r)[1] + rect_bounds(r)[0] / 3)
    def kind(devs):
        names_ = " ".join(d.findtext("ENGINE/NAME") or "" for d in devs)
        if "Access Point" in names_:
            return "Wireless"
        for switch, zone in (("Switch3", "Servers"), ("Switch4", "Management"),
                             ("Switch1", "Design"), ("Switch2", "Accounting")):
            if switch in names_:
                return zone
        return "Design"

    assigned = {}
    for rect in rects:
        assigned[kind(zones[rect])] = rect

    # --- 3. move zones with their devices --------------------------------
    for key, rect in assigned.items():
        x, y, w, h, colour, title = NEW_ZONES[key]
        devs = zones[rect]
        pts = [logical_pos(d) for d in devs]
        pts = [p for p in pts if p]
        if not pts:
            continue
        min_x = min(p[0] for p in pts)
        max_x = max(p[0] for p in pts)
        min_y = min(p[1] for p in pts)
        max_y = max(p[1] for p in pts)
        span_x = max(max_x - min_x, 1)
        span_y = max(max_y - min_y, 1)
        pad_x, pad_y = 70, 80
        for dev, p in zip(devs, [logical_pos(d) for d in devs]):
            if not p:
                continue
            nx = x + pad_x + (p[0] - min_x) / span_x * (w - 2 * pad_x)
            ny = y + pad_y + (p[1] - min_y) / span_y * (h - 2 * pad_y)
            set_logical_pos(dev, nx, ny)

        # rectangle
        rect.find("TopLeftX").text = str(x)
        rect.find("TopLeftY").text = str(y)
        rect.find("BottomRightX").text = str(x + w)
        rect.find("BottomRightY").text = str(y + h)
        rect.find("Color/Red").text = str(colour[0])
        rect.find("Color/Green").text = str(colour[1])
        rect.find("Color/Blue").text = str(colour[2])
        rect.set("uuid", "{" + str(uuidlib.uuid4()) + "}")
        mem = rect.find("MEM_ADDR")
        if mem is not None:
            mem.text = str(random.randint(2524000000000, 2524999999999))
        print(f"zone {key:11} -> ({x},{y}) {w}x{h} rgb{colour}, {len(devs)} devices")

    # --- 4. core devices --------------------------------------------------
    for dev in core:
        name = dev.findtext("ENGINE/NAME") or ""
        pos = CORE_POS.get(name)
        if pos:
            set_logical_pos(dev, *pos)

    # --- 5. write ---------------------------------------------------------
    xml = etree.tostring(root, encoding="utf-8")
    out = Path(args.output)
    if out.suffix.lower() == ".xml":
        out.write_bytes(xml)
    else:
        out.write_bytes(pt_tool.encrypt_pkt(xml))
    print(f"wrote {out} ({out.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
