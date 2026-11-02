#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Сборка ПР№3 «Базовая настройка и коммутация» для Cisco Packet Tracer 8.0.

Схема адресации — индивидуальный вариант x=17:
    VLAN 100 (LAN)  192.168.17.0/24
    VLAN 200 (MGMT) 192.168.117.0/24
    VLAN 10  (BR)   172.16.10.64/27
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

from lxml import etree

sys.path.insert(0, r"C:\Project\Cisco")
import pt_build
import pt_tool

LAN = "192.168.17.0"
MGMT = "192.168.117.0"

BASE = [
    "no ip domain-lookup",
    "ip domain-name kkep.local",
    "enable password class",
    "service password-encryption",
    "username admin privilege 15 secret cisco",
    "ip ssh version 2",
]

AAA = [
    "aaa new-model",
    "aaa authentication login default local",
    "aaa authentication login console local",
    "line vty 0 4",
    " login authentication default",
    " privilege level 15",
    " transport input ssh",
    "line con 0",
    " login authentication console",
]

ROUTER_TAIL = [
    "line con 0",
    " logging synchronous",
]


def host_block(hostname):
    return ["hostname " + hostname] + BASE


def router_cfg(hostname):
    return host_block(hostname) + AAA + [
        "line con 0",
        " privilege level 1",
        "",
    ]


def switch_cfg(hostname, extra, unused):
    """extra — список строк после базовой части; unused — список портов в shutdown."""
    lines = host_block(hostname)
    lines += [
        "vlan 100",
        " name LAN",
        "vlan 200",
        " name MGMT",
        "vlan 300",
        " name EDGE",
        "spanning-tree mode rapid-pvst",
    ]
    lines += extra
    for p in unused:
        lines += ["interface " + p, " shutdown"]
    return lines


# --------------------------------------------------------------------------
# HQ
# --------------------------------------------------------------------------
HQ = router_cfg("HQ") + [
    "ipv6 unicast-routing",
    "interface GigabitEthernet0/0/0",
    " no shutdown",
    "interface GigabitEthernet0/0/0.100",
    " encapsulation dot1Q 100",
    " ip address 192.168.17.254 255.255.255.0",
    " ipv6 enable",
    " ipv6 address A1F:EA75:CA75::254/64",
    " ipv6 nd other-config-flag",
    " ipv6 nd managed-config-flag",
    "interface GigabitEthernet0/0/0.200",
    " encapsulation dot1Q 200",
    " ip address 192.168.117.254 255.255.255.0",
    "interface Loopback100",
    " ip address 11.11.11.11 255.255.255.255",
    " ipv6 enable",
    " ipv6 address DEAD:BEEF::1/128",
]

ISP = router_cfg("ISP") + [
    "interface Loopback100",
    " ip address 8.8.8.8 255.255.255.0",
    "interface Loopback101",
    " ip address 209.136.0.1 255.255.0.0",
    "interface Loopback102",
    " ip address 138.76.0.1 255.255.0.0",
]

BR = router_cfg("BR") + [
    "interface GigabitEthernet0/0/1",
    " no shutdown",
    "interface GigabitEthernet0/0/1.10",
    " encapsulation dot1Q 10",
    " ip address 172.16.10.65 255.255.255.224",
    "interface Loopback3",
    " ip address 3.3.3.3 255.255.255.255",
    " ipv6 enable",
    " ipv6 address DEAD:BEEF:3::1/128",
]

# BR: по методичке на локальной консоли сразу максимальный уровень
BR = [l for l in BR]
_br = BR.index(" privilege level 1")
BR[_br] = " privilege level 15"

# --------------------------------------------------------------------------
# SW1
# --------------------------------------------------------------------------
SW1 = switch_cfg(
    "SW1",
    [
        "spanning-tree vlan 100 priority 0",
        "spanning-tree vlan 200 priority 4096",
        "spanning-tree vlan 300 priority 8192",
        # портовая группа 1 (PAgP, пассивный режим) с SW2
        "interface Port-channel1",
        " switchport mode trunk",
        " switchport nonegotiate",
        "interface FastEthernet0/1",
        " switchport mode trunk",
        " switchport nonegotiate",
        " channel-group 1 mode auto",
        "interface FastEthernet0/2",
        " switchport mode trunk",
        " switchport nonegotiate",
        " channel-group 1 mode auto",
        # порт вне портовых групп (данные при отказе канала)
        "interface FastEthernet0/3",
        " spanning-tree vlan 100 cost 8",
        " spanning-tree vlan 200 cost 8",
        " spanning-tree vlan 300 cost 8",
        # портовая группа 3 (LACP, пассивный режим) с SW3
        "interface FastEthernet0/7",
        " switchport mode dynamic auto",
        " channel-group 3 mode passive",
        "interface FastEthernet0/8",
        " switchport mode dynamic auto",
        " channel-group 3 mode passive",
        "interface FastEthernet0/9",
        " switchport mode dynamic auto",
        " spanning-tree vlan 100 cost 8",
        " spanning-tree vlan 200 cost 8",
        " spanning-tree vlan 300 cost 8",
        # access-порт PC1 + защита корня + portfast
        "interface FastEthernet0/10",
        " switchport mode access",
        " switchport access vlan 100",
        " spanning-tree portfast",
        " spanning-tree guard root",
        "interface Vlan200",
        " ip address 192.168.117.51 255.255.255.0",
        " no shutdown",
        "ip default-gateway 192.168.117.254",
    ]
    + AAA
    + ["line con 0", " privilege level 1"],
    ["FastEthernet0/4", "FastEthernet0/5", "FastEthernet0/6"]
    + ["FastEthernet0/%d" % i for i in range(11, 25)]
    + ["GigabitEthernet0/1", "GigabitEthernet0/2"],
)

SW2 = switch_cfg(
    "SW2",
    [
        "spanning-tree vlan 200 priority 0",
        "spanning-tree vlan 300 priority 4096",
        "spanning-tree vlan 100 priority 8192",
        "interface Port-channel1",
        " switchport mode trunk",
        " switchport nonegotiate",
        "interface FastEthernet0/1",
        " switchport mode trunk",
        " switchport nonegotiate",
        " channel-group 1 mode desirable",
        "interface FastEthernet0/2",
        " switchport mode trunk",
        " switchport nonegotiate",
        " channel-group 1 mode desirable",
        "interface FastEthernet0/3",
        " spanning-tree vlan 100 cost 8",
        " spanning-tree vlan 200 cost 8",
        " spanning-tree vlan 300 cost 8",
        "interface FastEthernet0/4",
        " switchport mode dynamic auto",
        " channel-group 2 mode passive",
        "interface FastEthernet0/5",
        " switchport mode dynamic auto",
        " channel-group 2 mode passive",
        "interface FastEthernet0/6",
        " switchport mode dynamic auto",
        " spanning-tree vlan 100 cost 8",
        " spanning-tree vlan 200 cost 8",
        " spanning-tree vlan 300 cost 8",
        "interface FastEthernet0/10",
        " switchport mode access",
        " switchport access vlan 200",
        "interface Vlan200",
        " ip address 192.168.117.52 255.255.255.0",
        " no shutdown",
        "ip default-gateway 192.168.117.254",
    ]
    + AAA
    + ["line con 0", " privilege level 1"],
    ["FastEthernet0/%d" % i for i in range(7, 10)]
    + ["FastEthernet0/%d" % i for i in range(11, 25)]
    + ["GigabitEthernet0/1", "GigabitEthernet0/2"],
)

SW3 = switch_cfg(
    "SW3",
    [
        "spanning-tree vlan 300 priority 0",
        "spanning-tree vlan 100 priority 4096",
        "spanning-tree vlan 200 priority 8192",
        "interface Port-channel2",
        "interface Port-channel3",
        "interface FastEthernet0/4",
        " switchport mode dynamic desirable",
        " channel-group 2 mode active",
        "interface FastEthernet0/5",
        " switchport mode dynamic desirable",
        " channel-group 2 mode active",
        "interface FastEthernet0/6",
        " switchport mode dynamic desirable",
        " spanning-tree vlan 100 cost 8",
        " spanning-tree vlan 200 cost 8",
        " spanning-tree vlan 300 cost 8",
        "interface FastEthernet0/7",
        " switchport mode dynamic desirable",
        " channel-group 3 mode active",
        "interface FastEthernet0/8",
        " switchport mode dynamic desirable",
        " channel-group 3 mode active",
        "interface FastEthernet0/9",
        " switchport mode dynamic desirable",
        " spanning-tree vlan 100 cost 8",
        " spanning-tree vlan 200 cost 8",
        " spanning-tree vlan 300 cost 8",
        # транк в сторону HQ (802.1Q, теги VLAN 100 и 200)
        "interface FastEthernet0/21",
        " switchport mode trunk",
        "interface Vlan200",
        " ip address 192.168.117.53 255.255.255.0",
        " no shutdown",
        "ip default-gateway 192.168.117.254",
    ]
    + AAA
    + ["line con 0", " privilege level 1"],
    ["FastEthernet0/1", "FastEthernet0/2", "FastEthernet0/3"]
    + ["FastEthernet0/%d" % i for i in range(10, 21)]
    + ["FastEthernet0/22", "FastEthernet0/23", "FastEthernet0/24"]
    + ["GigabitEthernet0/1", "GigabitEthernet0/2"],
)

BR_SW = switch_cfg(
    "BR-SW",
    [
        "interface GigabitEthernet0/1",
        " switchport mode trunk",
        "interface FastEthernet0/10",
        " switchport mode access",
        " switchport access vlan 10",
        " spanning-tree portfast",
        "interface Vlan10",
        " ip address 172.16.10.66 255.255.255.224",
        " no shutdown",
        "ip default-gateway 172.16.10.65",
    ]
    + AAA
    + ["line con 0", " privilege level 1"],
    ["FastEthernet0/%d" % i for i in range(1, 10)]
    + ["FastEthernet0/%d" % i for i in range(11, 25)]
    + ["GigabitEthernet0/2"],
)

VLANS = [
    {"id": 100, "name": "LAN"},
    {"id": 200, "name": "MGMT"},
    {"id": 300, "name": "EDGE"},
]
VLANS_BR = [{"id": 10, "name": "BR-LAN"}]

DEVICES = [
    # name, template, x, y, config, vlans
    ("PC1", "PC0", 150, 200, None, None),
    ("SW1", "Switch0", 360, 200, SW1, VLANS),
    ("SRV01", "Server0", 150, 470, None, None),
    ("SW2", "Switch0", 360, 470, SW2, VLANS),
    ("SW3", "Switch0", 570, 335, SW3, VLANS),
    ("HQ", "Router0", 810, 200, HQ, None),
    ("ISP", "Router0", 1030, 320, ISP, None),
    ("BR", "Router0", 810, 520, BR, None),
    ("BR-SW", "Switch0", 810, 690, BR_SW, VLANS_BR),
    ("BR-CLI", "Laptop0", 1030, 690, None, None),
]

LINKS = [
    ("PC1", "FastEthernet0", "SW1", "FastEthernet0/10"),
    ("SRV01", "FastEthernet0", "SW2", "FastEthernet0/10"),
    ("SW1", "FastEthernet0/1", "SW2", "FastEthernet0/1"),
    ("SW1", "FastEthernet0/2", "SW2", "FastEthernet0/2"),
    ("SW1", "FastEthernet0/3", "SW2", "FastEthernet0/3"),
    ("SW1", "FastEthernet0/7", "SW3", "FastEthernet0/7"),
    ("SW1", "FastEthernet0/8", "SW3", "FastEthernet0/8"),
    ("SW1", "FastEthernet0/9", "SW3", "FastEthernet0/9"),
    ("SW2", "FastEthernet0/4", "SW3", "FastEthernet0/4"),
    ("SW2", "FastEthernet0/5", "SW3", "FastEthernet0/5"),
    ("SW2", "FastEthernet0/6", "SW3", "FastEthernet0/6"),
    ("SW3", "FastEthernet0/21", "HQ", "GigabitEthernet0/0/0"),
    ("HQ", "GigabitEthernet0/0/1", "ISP", "GigabitEthernet0/0/1"),
    ("ISP", "GigabitEthernet0/0/0", "BR", "GigabitEthernet0/0/0"),
    ("BR", "GigabitEthernet0/0/1", "BR-SW", "GigabitEthernet0/1"),
    ("BR-SW", "FastEthernet0/10", "BR-CLI", "FastEthernet0"),
]

HOSTS = {
    "PC1": dict(ip="192.168.17.100", mask="255.255.255.0",
                gateway="192.168.17.254", dns="192.168.17.100"),
    "SRV01": dict(ip="192.168.117.200", mask="255.255.255.0",
                  gateway="192.168.117.254", dns="192.168.117.200"),
    "BR-CLI": dict(ip="172.16.10.70", mask="255.255.255.224",
                   gateway="172.16.10.65", dns="172.16.10.65"),
}


def patch_vlans(xml: bytes) -> bytes:
    """Прописать таблицу VLAN в ENGINE/VLANS каждого коммутатора."""
    root = etree.fromstring(xml, etree.XMLParser(recover=True, huge_tree=True))
    wanted = {}
    for name, *_rest in DEVICES:
        pass
    spec = {d[0]: d[5] for d in DEVICES}
    defaults = [(1, "default"), (1002, "fddi-default"), (1003, "token-ring-default"),
                (1004, "fddinet-default"), (1005, "trnet-default")]
    for dev in root.iter("DEVICE"):
        eng = dev.find("ENGINE")
        if eng is None:
            continue
        name = eng.findtext("NAME") or ""
        vl = spec.get(name)
        if not vl:
            continue
        el = eng.find("VLANS")
        if el is None:
            el = etree.SubElement(eng, "VLANS")
        for ch in list(el):
            el.remove(ch)
        table = defaults + [(v["id"], v["name"]) for v in vl]
        for vid, vname in sorted(table):
            e = etree.SubElement(el, "VLAN")
            e.set("number", str(vid))
            e.set("name", vname)
            e.set("rspan", "0")
    return etree.tostring(root, xml_declaration=False, encoding="utf-8")


def main():
    out = Path(r"C:\Users\gaming\Desktop\Cisco 3 практическая\ПР3_x17.pkt")
    donor_xml = pt_tool.decrypt_pkt(Path(r"C:\Project\Cisco\донор.pkt").read_bytes())

    spec = {"devices": [], "links": []}
    for name, tpl, x, y, cfg, vl in DEVICES:
        d = {"name": name, "template": tpl, "x": x, "y": y}
        if cfg is not None:
            d["config"] = [l for l in cfg if l != ""]
        if vl:
            d["vlans"] = vl
        if name in HOSTS:
            d.update(HOSTS[name])
        spec["devices"].append(d)
    for a, ap, b, bp in LINKS:
        spec["links"].append({"from": a, "from_port": ap, "to": b, "to_port": bp})

    Path(r"C:\Project\Cisco\pr3\spec.json").write_text(
        json.dumps(spec, ensure_ascii=False, indent=1), encoding="utf-8")

    xml = pt_build.build(spec, donor_xml)
    xml = patch_vlans(xml)
    out.write_bytes(pt_tool.encrypt_pkt(xml))
    print("wrote", out, len(xml), "bytes XML")


if __name__ == "__main__":
    main()
