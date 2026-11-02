#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pt_build.py - build a Cisco Packet Tracer .pkt from a small JSON description.

The idea: take an existing (decrypted) Packet Tracer XML as a *donor* file and
clone real device/link records from it, so we never have to invent the
proprietary parts of the format ourselves.

    python pt_build.py lab.json -o lab.pkt --template a.xml

JSON format
-----------
{
  "devices": [
    {"name": "R1", "template": "Router0", "x": 200, "y": 200,
     "config": ["interface GigabitEthernet0/0", " ip address 10.0.0.1 255.255.255.0", " no shutdown"]},
    {"name": "SW1", "template": "Switch0", "x": 400, "y": 200},
    {"name": "PC1", "template": "PC0", "x": 600, "y": 200,
     "ip": "10.0.0.10", "mask": "255.255.255.0", "gateway": "10.0.0.1"}
  ],
  "links": [
    {"from": "R1", "from_port": "GigabitEthernet0/0",
     "to": "SW1", "to_port": "GigabitEthernet0/1", "cable": "eStraightThrough"}
  ]
}

Device "template" is the name of a device inside the donor file (use
`python pkt_graph.py` to see what is available). You may also use
"model": "PC-PT" to pick the first donor device of that model.
"""

from __future__ import annotations

import argparse
import copy
import json
import random
import re
import sys
import uuid as uuidlib
from pathlib import Path

from lxml import etree

import pt_tool


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

_used_serials = set()
_used_macs = set()
_used_refs = set()
_mem_counter = [2524000000000]


def _next_mem() -> int:
    _mem_counter[0] += 128
    return _mem_counter[0]


def _rand_digits(n: int) -> str:
    return "".join(random.choice("0123456789") for _ in range(n))


def _new_ref() -> str:
    while True:
        ref = "save-ref-id:" + _rand_digits(19)
        if ref not in _used_refs:
            _used_refs.add(ref)
            return ref


def _new_serial() -> str:
    while True:
        s = "PTT" + _rand_digits(4) + random.choice("ABCDEFGHJKLMNPQRSTUVWXYZ") + \
            random.choice("ABCDEFGHJKLMNPQRSTUVWXYZ") + _rand_digits(1) + "-"
        if s not in _used_serials:
            _used_serials.add(s)
            return s


def _new_mac() -> str:
    while True:
        mac = "000C.%04X.%04X" % (random.randint(0, 0xFFFF), random.randint(0, 0xFFFF))
        if mac not in _used_macs:
            _used_macs.add(mac)
            return mac


def parse_xml(data: bytes):
    parser = etree.XMLParser(recover=True, huge_tree=True)
    return etree.fromstring(data, parser)


# --------------------------------------------------------------------------
# building blocks
# --------------------------------------------------------------------------

class Builder:
    def __init__(self, template_xml: bytes):
        self.root = parse_xml(template_xml)
        self.network = self.root.find("NETWORK")
        if self.network is None:
            raise ValueError("donor file has no <NETWORK>")

        self.donor_devices = {}
        for dev in self.network.findall("DEVICES/DEVICE"):
            name = dev.findtext("ENGINE/NAME") or ""
            model = ""
            t = dev.find("ENGINE/TYPE")
            if t is not None:
                model = t.get("model") or ""
            self.donor_devices.setdefault(name, dev)
            if model:
                self.donor_devices.setdefault("model:" + model, dev)

        links = self.network.findall("LINKS/LINK")
        self.link_templates = {}
        for link in links:
            key = (link.findtext("TYPE") or "", link.findtext("CABLE/TYPE") or "")
            self.link_templates.setdefault(key, link)
        self.link_templates.setdefault("default", links[0] if links else None)
        if not links:
            raise ValueError("donor file has no links to clone")

        self.devices_by_name = {}
        self.out_devices = self.network.find("DEVICES")
        self.out_links = self.network.find("LINKS")
        if self.out_devices is None or self.out_links is None:
            raise ValueError("donor file has no DEVICES/LINKS section")

        # clear old content
        for dev in list(self.out_devices):
            self.out_devices.remove(dev)
        for link in list(self.out_links):
            self.out_links.remove(link)

        self._rack = self._find_node_by_type("4")
        self.physical_nodes = []
        for node in list(self.root.iter("NODE")):
            if node.findtext("TYPE") == "6":
                self.physical_nodes.append(node)
        self._physical_template = self.physical_nodes[0] if self.physical_nodes else None

        # remove old physical device nodes
        for node in self.physical_nodes:
            parent = node.getparent()
            if parent is not None:
                parent.remove(node)
        self.physical_nodes = []

        # drop donor annotations so the new file starts clean
        for tag in ("RECTANGLES", "ELLIPSES", "POLYGONS", "LINES", "NOTES"):
            for parent in (self.root, self.network):
                el = parent.find(tag)
                if el is not None:
                    for child in list(el):
                        el.remove(child)
        desc = self.network.find("DESCRIPTION")
        if desc is not None:
            desc.text = None
            for child in list(desc):
                desc.remove(child)
        notes = self.root.find("PHYSICALWORKSPACE/NOTES")
        if notes is not None:
            notes.text = None
            for child in list(notes):
                notes.remove(child)

    # -- physical workspace ------------------------------------------------
    def _find_node_by_type(self, t):
        for node in self.root.iter("NODE"):
            if node.findtext("TYPE") == t:
                return node
        return None

    def _make_physical_node(self, donor: etree._Element, name: str, x: str):
        if self._physical_template is None:
            return None
        node = copy.deepcopy(self._physical_template)
        uuid = "{" + str(uuidlib.uuid4()) + "}"
        for el in node.iter():
            if el.tag == "UUID_STR":
                el.text = uuid
        n = node.find("NAME")
        if n is not None:
            n.text = name
        xel = node.find("X")
        if xel is not None:
            xel.text = x
        parent = self._rack
        if parent is None:
            parent = self.root.find("PHYSICALWORKSPACE")
        parent.append(node)
        return uuid

    # -- devices -----------------------------------------------------------
    def add_device(self, spec: dict) -> etree._Element:
        name = spec["name"]
        donor = None
        if spec.get("template"):
            donor = self.donor_devices.get(spec["template"])
        if donor is None and spec.get("model"):
            donor = self.donor_devices.get("model:" + spec["model"])
        if donor is None:
            raise KeyError(f"no donor device for {name!r} "
                           f"(template={spec.get('template')!r}, model={spec.get('model')!r})")

        dev = copy.deepcopy(donor)

        # name
        nm = dev.find("ENGINE/NAME")
        if nm is not None:
            nm.text = name

        # identity
        ref = _new_ref()
        sr = dev.find("ENGINE/SAVE_REF_ID")
        if sr is not None:
            sr.text = ref
        sn = dev.find("ENGINE/SERIALNUMBER")
        if sn is not None:
            sn.text = _new_serial()

        # unique MAC addresses
        for tag in ("MACADDRESS", "BIA"):
            for el in dev.iter(tag):
                el.text = _new_mac()

        # logical coordinates
        x = str(spec.get("x", 0))
        y = str(spec.get("y", 0))
        for tag in ("X", "Y"):
            pass
        cx = dev.find("ENGINE/COORD_SETTINGS/X_COORD")
        cy = dev.find("ENGINE/COORD_SETTINGS/Y_COORD")
        if cx is not None:
            cx.text = x
        if cy is not None:
            cy.text = y
        lx = dev.find("WORKSPACE/LOGICAL/X")
        ly = dev.find("WORKSPACE/LOGICAL/Y")
        if lx is not None:
            lx.text = str(int(float(x)))
        if ly is not None:
            ly.text = str(int(float(y)))

        # memory addresses
        dev_addr = _next_mem()
        for tag in ("MEM_ADDR", "DEV_ADDR"):
            el = dev.find("WORKSPACE/LOGICAL/" + tag)
            if el is not None:
                el.text = str(dev_addr)

        # physical placement: new uuid as last element of the chain
        phys_uuid = "{" + str(uuidlib.uuid4()) + "}"
        ph = dev.find("WORKSPACE/PHYSICAL")
        if ph is not None and ph.text:
            parts = [p for p in ph.text.split(",") if p.strip()]
            parts[-1] = phys_uuid
            ph.text = ",".join(parts)
        self._make_physical_node(donor, name, str(spec.get("rack_x", len(self.out_devices) * 4)))

        # static IP for host-like devices
        ip = spec.get("ip")
        if ip:
            self._set_host_ip(dev, ip, spec.get("mask", "255.255.255.0"), spec.get("gateway", ""),
                              spec.get("dns", ""))

        # running / startup config
        # ВАЖНО (изм. 2026-11-02): если config не задан — конфиг ДОНОРА НАСЛЕДОВАЛСЯ,
        # что ломало сгенерированные схемы (VLAN/трунки донора рвали связность).
        # Теперь по умолчанию конфиг очищается; наследование больше не применяется.
        config = spec.get("config")
        self._set_config(dev, config or [])

        # switch VLAN database: всегда нормализуем (base + указанные),
        # пишем и vlan.dat (FILE_CONTENT), и ENGINE/VLANS (его читает PT 8.0).
        # Если vlans не заданы — извлекаем базу из CLI-конфига ("vlan N / name X").
        vlans = list(spec.get("vlans") or [])
        if not vlans and config:
            cur = None
            for ln in config:
                s = ln.strip()
                m = re.match(r"^vlan\s+(\d+)$", s)
                if m:
                    cur = int(m.group(1))
                    continue
                m = re.match(r"^name\s+(\S.*)$", s)
                if m and cur:
                    vlans.append({"id": cur, "name": m.group(1).strip()})
                    cur = None
        # плюс все VLAN, УПОМЯНУТЫЕ в конфиге (access/trunk allowed/interface VlanN):
        # конфиг может ссылаться на VLAN, создание которого живёт в VLAN-базе донора
        seen = {v["id"] for v in vlans}
        for ln in config or []:
            for m in re.finditer(r"(?:access vlan|trunk allowed vlan(?:\s+add)?|voice vlan)\s+(\d+)", ln, re.I):
                vid = int(m.group(1))
                if vid not in seen:
                    vlans.append({"id": vid})
                    seen.add(vid)
            m = re.match(r"^interface\s+[Vv]lan\s*(\d+)", ln.strip())
            if m and int(m.group(1)) not in seen:
                vlans.append({"id": int(m.group(1))})
                seen.add(int(m.group(1)))
        self._set_vlans(dev, vlans)

        # wireless SSID
        if spec.get("ssid"):
            for el in dev.iter("SSID"):
                el.text = spec["ssid"]

        self.out_devices.append(dev)
        self.devices_by_name[name] = {"el": dev, "ref": ref, "mem": dev_addr}
        return dev

    @staticmethod
    def _set_host_ip(dev, ip, mask, gateway, dns=""):
        target = None
        for port in dev.iter("PORT"):
            t = (port.findtext("TYPE") or "")
            if "Ethernet" in t:
                target = port
                break
        if target is None:
            target = dev.find(".//PORT")
        if target is None:
            return
        for tag, val in (("IP", ip), ("SUBNET", mask), ("PORT_GATEWAY", gateway)):
            el = target.find(tag)
            if el is not None:
                el.text = val
        dhcp = target.find("PORT_DHCP_ENABLE")
        if dhcp is not None:
            dhcp.text = "false"
        if dns:
            d = target.find("PORT_DNS")
            if d is not None:
                d.text = dns
        gw = dev.find("ENGINE/GATEWAY")
        if gw is not None and gateway:
            gw.text = gateway

    @staticmethod
    def _set_config(dev, lines):
        """Write the config into every place Packet Tracer keeps it."""
        containers = []
        for tag in ("RUNNINGCONFIG", "STARTUPCONFIG"):
            for conf in dev.iter(tag):
                containers.append(conf)
        for conf in dev.iter("CONFIG"):
            containers.append(conf)
        for conf in containers:
            for line in list(conf):
                if line.tag == "LINE":
                    conf.remove(line)
            for text in lines:
                line = etree.SubElement(conf, "LINE")
                line.text = text

    @staticmethod
    def _set_vlans(dev, vlans):
        """Нормализует VLAN-базу свитча: vlan.dat (FILE_CONTENT) + ENGINE/VLANS.

        Вызывается всегда: без spec-вланов база сбрасывается к 5 дефолтным,
        чтобы не тащить VLAN-таблицу донора в собранную схему.
        """
        base = [
            (1, "default"),
            (1002, "fddi-default"),
            (1003, "token-ring-default"),
            (1004, "fddinet-default"),
            (1005, "trnet-default"),
        ]
        table = {}
        for entry in vlans:
            table[int(entry["id"])] = entry.get("name", f"VLAN{int(entry['id']):04d}")
        full = base + sorted(table.items())

        # 1) vlan.dat
        for fc in dev.iter("FILE_CONTENT"):
            if fc.get("class") != "CVlanDatFileContent":
                continue
            vlans_el = fc.find("VLANS")
            if vlans_el is None:
                continue
            for v in list(vlans_el):
                vlans_el.remove(v)
            for vid, vname in full:
                el = etree.SubElement(vlans_el, "VLAN")
                el.set("rspan", "0")
                el.set("number", str(vid))
                el.set("name", vname)
            count = fc.find("VLAN_COUNT")
            if count is not None:
                count.text = str(len(full))

        # 2) ENGINE/VLANS — PT 8.0 восстанавливает VLAN-базу отсюда
        #    (подтверждено patch_vlans в build_pr3 пользователя)
        eng = dev.find("ENGINE")
        if eng is None:
            return
        el = eng.find("VLANS")
        if el is None:
            el = etree.SubElement(eng, "VLANS")
        for v in list(el):
            el.remove(v)
        for vid, vname in full:
            e = etree.SubElement(el, "VLAN")
            e.set("number", str(vid))
            e.set("name", vname)
            e.set("rspan", "0")

    # -- links -------------------------------------------------------------
    def add_link(self, spec: dict):
        a = self.devices_by_name.get(spec["from"])
        b = self.devices_by_name.get(spec["to"])
        if not a or not b:
            raise KeyError(f"link refers to unknown device: {spec['from']} -> {spec['to']}")

        from_port = spec.get("from_port", "")
        to_port = spec.get("to_port", "")
        cable = spec.get("cable")
        link_type = spec.get("link_type")
        if cable is None or link_type is None:
            auto_cable, auto_type = self._guess_cable(a["el"], from_port, b["el"], to_port)
            cable = cable or auto_cable
            link_type = link_type or auto_type

        template = self.link_templates.get((link_type, cable))
        if template is None:
            template = self.link_templates["default"]
        link = copy.deepcopy(template)
        tel = link.find("TYPE")
        if tel is not None:
            tel.text = link_type
        cable_el = link.find("CABLE")
        if cable_el is None:
            raise ValueError("donor link has no <CABLE>")
        cable_el.find("FROM").text = a["ref"]
        cable_el.find("TO").text = b["ref"]
        ports = cable_el.findall("PORT")
        if len(ports) < 2:
            raise ValueError("donor link has fewer than two <PORT> elements")
        ports[0].text = from_port
        ports[1].text = to_port
        t = cable_el.find("TYPE")
        if t is not None:
            t.text = cable
        for tag, val in (("FROM_DEVICE_MEM_ADDR", a["mem"]), ("TO_DEVICE_MEM_ADDR", b["mem"])):
            el = cable_el.find(tag)
            if el is not None:
                el.text = str(val)
        for tag in ("FROM_PORT_MEM_ADDR", "TO_PORT_MEM_ADDR"):
            el = cable_el.find(tag)
            if el is not None:
                el.text = str(_next_mem())
        self.out_links.append(link)

    @staticmethod
    def _guess_cable(dev_a, port_a, dev_b, port_b):
        model_a = (dev_a.find("ENGINE/TYPE").get("model") or "").lower()
        model_b = (dev_b.find("ENGINE/TYPE").get("model") or "").lower()
        pa = port_a.lower()
        pb = port_b.lower()
        if "serial" in pa or "serial" in pb:
            return "eSerial", "eSerial"
        if "fiber" in pa or "fiber" in pb:
            return "eFiber", "eFiber"
        wireless = ("smartphone" in model_a or "laptop" in model_a or "tablet" in model_a
                    or "accesspoint" in model_b or "accesspoint" in model_a)
        if wireless and ("port 0" in pa or "port 0" in pb):
            return "eWireless", "eWireless"
        switchish = ("2960" in model_a or "3560" in model_b or "switch" in model_a
                     or "2960" in model_b or "switch" in model_b)
        if ("switch" in model_a and "switch" in model_b) or \
           ("router" in model_a and "router" in model_b):
            return "eCrossOver", "eCopper"
        return "eStraightThrough", "eCopper"

    # -- output ------------------------------------------------------------
    def to_xml(self) -> bytes:
        return etree.tostring(self.root, xml_declaration=False, encoding="utf-8")


def build(spec: dict, template_xml: bytes) -> bytes:
    b = Builder(template_xml)

    auto = not any("x" in d and "y" in d for d in spec.get("devices", []))
    for i, d in enumerate(spec.get("devices", [])):
        if auto:
            col, row = i % 5, i // 5
            d.setdefault("x", 150 + col * 220)
            d.setdefault("y", 150 + row * 220)
        b.add_device(d)
    for link in spec.get("links", []):
        b.add_link(link)
    return b.to_xml()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Build a .pkt from a JSON description")
    ap.add_argument("spec")
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("--template", default="a.xml",
                    help="decrypted donor XML or .pkt file with example devices")
    ap.add_argument("--xml-only", action="store_true", help="write plain XML instead of .pkt")
    ap.add_argument("--no-validate", action="store_true",
                    help="skip semantic validation of the spec")
    args = ap.parse_args(argv)

    spec = json.loads(Path(args.spec).read_text(encoding="utf-8"))
    tpl_path = Path(args.template)
    if tpl_path.suffix.lower() in (".pkt", ".pka"):
        template_xml = pt_tool.decrypt_pkt_auto(tpl_path.read_bytes())
    else:
        template_xml = tpl_path.read_bytes()

    if not args.no_validate:
        import validate as _v
        _v.PROBLEMS.clear()
        rc = _v.main([args.spec, "--donor", str(tpl_path), "--max-warnings", "5"])
        if rc != 0:
            print("\nсборка отменена: исправьте ошибки спеки (или --no-validate)")
            return rc

    xml = build(spec, template_xml)
    out = Path(args.output)
    if args.xml_only:
        out.write_bytes(xml)
        print(f"wrote {out} ({len(xml)} bytes of XML)")
    else:
        blob = pt_tool.encrypt_pkt(xml)
        out.write_bytes(blob)
        print(f"wrote {out} ({len(blob)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
