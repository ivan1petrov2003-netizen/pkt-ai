#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_connectivity.py — логическая проверка пингуемости собранного .pkt БЕЗ Packet Tracer.

Парсит XML собранного файла и симулирует L2/L3 в объёме MVP:
  access-порты (switchport access vlan N), trunk (без ограничений), сабинтерфейсы
  роутера (encapsulation dot1Q), native VLAN 1, хосты (access VLAN 1).

Проверяет для каждого хоста:
  1. IP/маска валидны, шлюз в той же подсети
  2. До шлюза есть L2-путь в одном VLAN (через цепочку свитчей)
  3. Хосты одной подсети достижимы друг до друга

    python check_connectivity.py file.pkt [file2.pkt ...]
Код возврата: 0 — всё пингуется; 1 — есть проблемы (они напечатаны).
"""
from __future__ import annotations

import ipaddress
import json
import re
import sys
from pathlib import Path

from lxml import etree

sys.path.insert(0, str(Path(__file__).parent))
import pt_tool  # noqa: E402


def parse_dev_config(dev) -> dict:
    """Конфиг устройства → {интерфейс: [строки]}."""
    ifs: dict[str, list[str]] = {}
    cur = None
    cfg = dev.find("ENGINE/RUNNINGCONFIG")
    if cfg is None:
        return ifs
    for line in cfg.findall("LINE"):
        txt = (line.text or "").strip()
        m = re.match(r"^interface\s+(\S+)", txt, re.I)
        if m:
            cur = m.group(1)
            ifs.setdefault(cur, [])
        elif cur:
            ifs[cur].append(txt)
    return ifs


def iface_state(lines: list[str]) -> dict:
    """Строки одного интерфейса → {mode, vlan, allowed, dot1q, ip, shutdown}."""
    st = {"mode": None, "vlan": None, "allowed": None, "dot1q": None,
          "ip": None, "shutdown": False}
    for t in lines:
        low = t.lower()
        if "shutdown" in low and not low.startswith("no "):
            st["shutdown"] = True
        m = re.search(r"ip address (\S+) (\S+)", t)
        if m:
            st["ip"] = (m.group(1), m.group(2))
        if "switchport mode trunk" in low:
            st["mode"] = "trunk"
        elif "switchport mode access" in low:
            st["mode"] = "access"
        elif "switchport mode dynamic" in low or "channel-group" in low:
            # dynamic auto/desirable + EtherChannel между свитчами → согласуется в транк
            st["mode"] = "trunk"
        m = re.search(r"switchport access vlan (\d+)", low)
        if m:
            st["vlan"] = int(m.group(1))
        m = re.search(r"switchport trunk allowed vlan(?:\s+add)?\s+(.+)$", low)
        if m:
            vlans: set[int] = set()
            for part in m.group(1).replace("all", "").split(","):
                part = part.strip()
                if "-" in part:
                    try:
                        a, b = part.split("-")
                        vlans.update(range(int(a), int(b) + 1))
                    except ValueError:
                        pass
                elif part.isdigit():
                    vlans.add(int(part))
            if vlans:
                st["allowed"] = vlans if st["allowed"] is None else st["allowed"] | vlans
        m = re.search(r"encapsulation dot1q (\d+)", low)
        if m:
            st["dot1q"] = int(m.group(1))
    return st


def is_router(model: str) -> bool:
    return model in ("2911", "2911 ", "1841", "2811", "2901", "1941") or \
        model.upper().startswith("ISR") or model in ("4321", "4331")


def is_switch(model: str) -> bool:
    return model.startswith(("2950", "2960", "3560", "3650", "Switch-PT"))


def is_host(model: str) -> bool:
    return model.startswith(("PC-PT", "Server-PT", "Laptop-PT", "Printer"))


def analyze(pkt_path: Path) -> tuple[list[str], int]:
    """-> (список проблем [], число проверенных хостов)."""
    problems: list[str] = []
    xml = pt_tool.decrypt_pkt_auto(pkt_path.read_bytes())
    root = etree.fromstring(xml, etree.XMLParser(recover=True, huge_tree=True))
    net = root.find("NETWORK")

    # --- устройства ---
    devs: dict[str, dict] = {}
    ref2name: dict[str, str] = {}
    for dev in net.findall("DEVICES/DEVICE"):
        eng = dev.find("ENGINE")
        name = eng.findtext("NAME") or "?"
        t = eng.find("TYPE")
        model = (t.get("model") or "") if t is not None else ""
        ref = eng.findtext("SAVE_REF_ID") or ""
        ref2name[ref] = name

        cfg = parse_dev_config(dev)
        # POWER портов: имя -> true/false (имена реконструируем по раскладке)
        from donor_registry import reconstruct, SWITCH_MODELS

        modules = dev.findall(".//MODULE")
        if modules:
            layout = [[q.findtext("TYPE") or "" for q in m.findall(".//PORT")] for m in modules]
            ports = [q for m in modules for q in m.findall(".//PORT")]
        else:
            ports = dev.findall(".//PORT")
            layout = [[q.findtext("TYPE") or "" for q in ports]]
        isr_m = model.upper().startswith("ISR") or model in ("4321", "4331")
        start_m = 1 if model in SWITCH_MODELS else 0
        power_by_port: dict[str, bool] = {}
        for p_el, nm in zip(ports, reconstruct(layout, start=start_m, isr=isr_m)):
            if nm.startswith("?unk:"):
                continue
            power_by_port[nm] = (p_el.findtext("POWER") or "true").lower() != "false"

        # IP хоста: PORT с непустым IP
        hip = hmask = hgw = None
        for port in dev.findall(".//PORT"):
            ip = port.findtext("IP") or ""
            if ip:
                hip = ip
                hmask = port.findtext("SUBNET") or "255.255.255.0"
                hgw = port.findtext("PORT_GATEWAY") or ""
                break
        # DHCP-карта донора: проводной порт в DHCP_CLIENT → PT принудительно
        # включает DHCP и игнорирует статический IP (проверено в PT 8.0)
        if hip:
            dm = dev.find("ENGINE/DHCP_CLIENT/PORT_DATA_MAP")
            if dm is not None:
                for entry in dm.findall("PORT_DATA_ENTRY"):
                    pname = (entry.findtext("PORT") or "").strip()
                    if "Ethernet" in pname:
                        problems.append(f"[{name}] проводной порт {pname} числится в "
                                        f"DHCP-карте донора → статический IP применён не будет")
        vlans_db: set[int] = {1, 1002, 1003, 1004, 1005}
        for fc in dev.iter("FILE_CONTENT"):
            if fc.get("class") == "CVlanDatFileContent":
                for v in fc.findall("VLANS/VLAN"):
                    try:
                        vlans_db.add(int(v.get("number")))
                    except (TypeError, ValueError):
                        pass
        eng_vlans = eng.find("VLANS")
        if eng_vlans is not None:
            for v in eng_vlans.findall("VLAN"):
                try:
                    vlans_db.add(int(v.get("number")))
                except (TypeError, ValueError):
                    pass
        devs[name] = {"model": model, "cfg": cfg, "hip": hip, "hmask": hmask,
                      "hgw": hgw, "vlans_db": vlans_db, "power": power_by_port,
                      "kind": ("router" if is_router(model) else
                               "switch" if is_switch(model) else
                               "host" if is_host(model) else "other")}

    # --- линки: имя_устройства -> {порт: [(сосед, порт_соседа)]} ---
    adj: dict[str, dict[str, list]] = {}
    for link in net.findall("LINKS/LINK"):
        cable = link.find("CABLE")
        if cable is None:
            continue
        refs = [cable.findtext("FROM") or "", cable.findtext("TO") or ""]
        ports = [p.text or "" for p in cable.findall("PORT")]
        if len(refs) < 2 or not all(r in ref2name for r in refs):
            continue
        a, b = ref2name[refs[0]], ref2name[refs[1]]
        adj.setdefault(a, {}).setdefault(ports[0], []).append((b, ports[1]))
        adj.setdefault(b, {}).setdefault(ports[1], []).append((a, ports[0]))
        # физически выключенный порт с линком = мёртвый линк
        for dn, dp in ((a, ports[0]), (b, ports[1])):
            d = devs.get(dn)
            if d and d["power"].get(dp) is False:
                problems.append(f"[{dn}] порт {dp}: POWER=false (физически выключен), "
                                f"но на нём линк → линк мёртв")

    # --- эффективный VLAN порта свитча ---
    def switch_port_vlan(dev_name: str, port: str, seen=None):
        """None — порт мёртв; ("access", vlan) или ("trunk", allowed|None)."""
        seen = seen or set()
        if (dev_name, port) in seen:
            return None
        seen.add((dev_name, port))
        d = devs.get(dev_name)
        if not d or d["kind"] != "switch":
            return None
        st = iface_state(d["cfg"].get(port, []))
        if st["shutdown"]:
            return None
        if st["mode"] == "trunk":
            return ("trunk", st["allowed"])
        vlan = st["vlan"] or 1
        if vlan not in d["vlans_db"]:
            problems.append(f"[{dev_name}] порт {port}: access vlan {vlan}, "
                            f"но VLAN {vlan} нет в vlan.dat → порт мёртв")
            return None
        return ("access", vlan)

    def router_if_vlan(dev_name: str, port: str) -> tuple[int | None, dict]:
        """(VLAN сабинтерфейса/главного, state) для порта роутера.
        Сабинтерфейс Gi0/0.10 → VLAN 10; главный Gi0/0 → VLAN 1."""
        d = devs.get(dev_name)
        if not d or d["kind"] != "router":
            return None, {}
        st = iface_state(d["cfg"].get(port, []))
        if st["shutdown"] or not st["ip"]:
            return None, st
        m = re.match(r"^(.*)\.(\d+)$", port)
        if m:  # сабинтерфейс: ищем dot1q у родителя с этим номером
            sub = iface_state(d["cfg"].get(port, []))
            return (sub["dot1q"] or 1), sub
        return 1, st  # физический интерфейс с IP = native VLAN 1

    def port_dead(dev_name: str, port: str) -> bool:
        """Порт физически выключен (POWER=false)."""
        d = devs.get(dev_name)
        return bool(d) and d["power"].get(port) is False

    # --- BFS по L2: свитч флудит во ВСЕ свои порты, не только пару линка ---
    def l2_reachable(src_dev: str, src_port: str, vlan: int | str) -> set[str]:
        """Все устройства, достижимые на канальном уровне в данном VLAN."""
        seen: set[tuple[str, str]] = set()
        out: set[str] = set()
        stack = [(src_dev, src_port)]
        while stack:
            dv, dp = stack.pop()
            if (dv, dp) in seen:
                continue
            seen.add((dv, dp))
            dv_dev = devs.get(dv)
            # свитч мостит на все остальные свои порты
            if dv_dev and dv_dev["kind"] == "switch":
                for np2 in adj.get(dv, {}):
                    if np2 == dp or port_dead(dv, np2):
                        continue
                    v = switch_port_vlan(dv, np2)
                    if v is None:
                        continue
                    kind, payload = v
                    ok = (payload == "trunk") if kind == "trunk" else (
                        payload == vlan if isinstance(vlan, int) else True)
                    if kind == "trunk":
                        ok = payload is None or (isinstance(vlan, int) and vlan in payload)
                    if ok:
                        for (nd, ndp) in adj[dv][np2]:
                            out.add(nd)
                            stack.append((nd, ndp))
                continue
            # обычный порт: идём к соседям по линку
            for (nd, np_) in adj.get(dv, {}).get(dp, []):
                nd_dev = devs.get(nd)
                if not nd_dev or port_dead(nd, np_):
                    continue
                if nd_dev["kind"] == "switch":
                    v = switch_port_vlan(nd, np_)
                    if v is None:
                        continue
                    kind, payload = v
                    if kind == "trunk":
                        ok = payload is None or (isinstance(vlan, int) and vlan in payload)
                    else:
                        ok = payload == vlan
                    if ok:
                        out.add(nd)
                        stack.append((nd, np_))
                elif nd_dev["kind"] == "router":
                    # порт роутера: главный интерфейс + все его сабинтерфейсы (.N)
                    ok = False
                    rv, rst = router_if_vlan(nd, np_)
                    if rv == vlan:
                        ok = True
                    for ifname in nd_dev["cfg"]:
                        if ifname.startswith(np_ + "."):
                            sv, sst = router_if_vlan(nd, ifname)
                            if sv == vlan and sst.get("ip"):
                                ok = True
                                break
                    if ok:
                        out.add(nd)
                elif nd_dev["kind"] == "host":
                    out.add(nd)
        return out

    # --- проверка каждого хоста ---
    hosts = [n for n, d in devs.items() if d["kind"] == "host" and d["hip"]]
    for h in sorted(hosts):
        d = devs[h]
        try:
            hnet = ipaddress.ip_network(f"{d['hip']}/{d['hmask']}", strict=False)
        except ValueError as e:
            problems.append(f"[{h}] кривой IP/маска: {d['hip']}/{d['hmask']} ({e})")
            continue
        gw = d["hgw"]
        if not gw:
            problems.append(f"[{h}] нет шлюза → пинг за пределы LAN невозможен")
            continue
        try:
            gw_ip = ipaddress.ip_address(gw)
        except ValueError:
            problems.append(f"[{h}] кривой шлюз «{gw}»")
            continue
        if gw_ip not in hnet:
            problems.append(f"[{h}] шлюз {gw} вне подсети {d['hip']}/{d['hmask']}")
            continue

        # порт хоста: тот, что в линках (Fa0)
        h_ports = list(adj.get(h, {}).keys()) or ["FastEthernet0"]
        reachable: set[str] = set()
        for hp in h_ports:
            # стартовый VLAN хоста задаёт access-порт соседнего свитча;
            # без свитча (хост-роутер напрямую) — VLAN 1 (native)
            start_vlan: int | str = 1
            for (nd, np_) in adj.get(h, {}).get(hp, []):
                nd_dev = devs.get(nd)
                if nd_dev and nd_dev["kind"] == "switch":
                    v = switch_port_vlan(nd, np_)
                    if v and v[0] == "access":
                        start_vlan = v[1]
            reachable |= l2_reachable(h, hp, start_vlan)

        # ищем роутер с IP=шлюз среди L2-достижимых (учитывая VLAN хоста=1)
        gw_found = False
        for r in reachable:
            if devs[r]["kind"] != "router":
                continue
            for ifname, lines in devs[r]["cfg"].items():
                st = iface_state(lines)
                if not st["ip"] or st["shutdown"]:
                    continue
                # главный интерфейс (VLAN 1) или сабинтерфейс .N где N=1? считаем main
                if st["ip"][0] == gw:
                    # роутер должен быть физически в VLAN 1 от хоста
                    base = ifname.split(".")[0]
                    if base in adj.get(r, {}) or ifname in adj.get(r, {}):
                        gw_found = True
        if not gw_found:
            problems.append(
                f"[{h}] шлюз {gw} НЕ достижим на L2 (VLAN 1). "
                f"L2-соседи: {sorted(reachable) or 'нет'}")

        # хосты той же подсети
        for other in hosts:
            if other == h:
                continue
            o = devs[other]
            if not o["hip"]:
                continue
            try:
                onet = ipaddress.ip_network(f"{o['hip']}/{o['hmask']}", strict=False)
            except ValueError:
                continue
            if onet == hnet and other not in reachable:
                problems.append(f"[{h}] ↔ [{other}] одна подсеть, но нет L2-пути "
                                f"(VLAN/трулок разорван)")

    return problems, len(hosts)


def main() -> int:
    files = [Path(a) for a in sys.argv[1:]]
    if not files:
        print("укажите .pkt файлы")
        return 1
    total_bad = 0
    for f in files:
        problems, nhosts = analyze(f)
        problems = sorted(set(problems))  # дедуп повторов
        status = "OK" if not problems else f"ПРОБЛЕМ: {len(problems)}"
        print(f"=== {f.name}: хостов {nhosts}, {status}")
        for p in problems:
            print("   " + p)
        total_bad += bool(problems)
    return 1 if total_bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
