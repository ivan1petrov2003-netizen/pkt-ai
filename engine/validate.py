#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
validate.py — семантическая валидация IR-спеки (формат pt_build.py) ДО сборки.

Ловит то, что иначе всплывёт только в Packet Tracer:
  - битые ссылки на устройства/шаблоны
  - несуществующие или повторно занятые порты
  - кривые IP/маски, шлюз вне подсети, дубли адресов
  - кривые VLAN
  - конфиги, ссылающиеся на несуществующие интерфейсы

    python validate.py spec.json [--registry registry.json] [--donor a.xml ...]
Выход: человекочитаемый отчёт; код возврата 1, если есть ошибки (error).
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

# имена интерфейсов, легитимные в конфигах, но не являющиеся физическими портами
_LOGICAL_IF = re.compile(
    r"^(Vlan|Loopback|Port-channel|Po|Tunnel|Dialer|NVI|Virtual-Access|BVI|sg\d+)\d+(/[\d.]+)?$",
    re.IGNORECASE,
)
_SUBIF = re.compile(r"^(?P<base>.+?)\.(?P<sub>\d{1,4})$")

PROBLEMS: list[dict] = []


def err(dev: str, msg: str):
    PROBLEMS.append({"severity": "error", "device": dev, "message": msg})


def warn(dev: str, msg: str):
    PROBLEMS.append({"severity": "warning", "device": dev, "message": msg})


def load_registry(path: Path | None) -> dict:
    if path is None:
        p = Path(__file__).parent / "registry.json"
        if not p.exists():
            return {}
        path = p
    return json.loads(path.read_text(encoding="utf-8"))


def donor_device_index(donor_paths: list[Path]) -> tuple[dict[str, str], dict[str, set[str]]]:
    """(name -> model, model -> допустимые имена портов) по донорам.

    Порты донор-инстанса — ground truth: клонирование берёт их как есть
    (Switch-PT с добавленным модулем имеет больше портов, чем генерический реестр).
    """
    import pt_tool
    from lxml import etree
    from donor_registry import reconstruct

    names: dict[str, str] = {}
    ports: dict[str, set[str]] = {}
    for p in donor_paths:
        raw = p.read_bytes()
        xml = raw if p.suffix.lower() == ".xml" else pt_tool.decrypt_pkt_auto(raw)
        root = etree.fromstring(xml, etree.XMLParser(recover=True, huge_tree=True))
        for dev in root.iter("DEVICE"):
            eng = dev.find("ENGINE")
            if eng is None:
                continue
            name = eng.findtext("NAME") or ""
            t = eng.find("TYPE")
            model = (t.get("model") or "") if t is not None else ""
            if not name:
                continue
            names[name] = model
            if not model:
                continue
            mods = dev.findall(".//MODULE")
            layout = [[q.findtext("TYPE") or "" for q in m.findall(".//PORT")] for m in mods] or [
                [q.findtext("TYPE") or "" for q in dev.findall(".//PORT")]
            ]
            isr = model.upper().startswith("ISR") or model in ("4321", "4331")
            start = 1 if model in ("2950-24", "2950T-24", "2960-24TT", "3560-24PS", "3650-24PS",
                                   "Switch-PT", "Switch-PT-Empty") else 0
            for nm in reconstruct(layout, start=start, isr=isr):
                ports.setdefault(model, set()).add(nm)
    return names, ports


def structural_port_ok(name: str, bases: set[str]) -> bool:
    """Порт вида Base<k>/<n> (или Base0/<k>/<n>), где Base — физически есть у модели.
    Покрывает доп-модули роутеров (Ethernet1/0) и ISR (GigabitEthernet0/2/0)."""
    m = re.match(r"^(?P<base>[A-Za-z]+)(?P<nums>(?:/\d+)+)$", name)
    if not m or m.group("base") not in bases:
        return False
    nums = [int(x) for x in m.group("nums").strip("/").split("/")]
    return len(nums) in (2, 3) and all(0 <= v < 64 for v in nums)


def valid_port(name: str, model: str, registry: dict, donor_ports: dict[str, set[str]] | None = None) -> bool:
    if donor_ports and name in donor_ports.get(model, ()):
        return True  # физически есть у донор-инстанса — высший приоритет
    entry = registry.get(model)
    if not entry:
        return True  # модели нет в реестре — не блокируем (новая/редкая)
    if name in entry["ports"] or name in entry.get("observed_names", {}):
        return True
    bases = {p.split("/")[0].split(" ")[0] for p in entry["ports"]}
    return structural_port_ok(name, bases)


def check_config_interfaces(dev: str, model: str, lines: list[str], registry: dict,
                            donor_ports: dict[str, set[str]] | None = None,
                            problems: list[dict] | None = None):
    known = set()
    entry = registry.get(model)
    if entry:
        known = set(entry["ports"]) | set(entry.get("observed_names", {}))
    if donor_ports:
        known |= donor_ports.get(model, set())
    for ln in lines:
        if re.match(r"^\s*interface\s+range\b", ln, re.IGNORECASE):
            continue  # interface range Fa0/1 - 2 : диапазоны не валидируем
        m = re.match(r"^\s*interface\s+(\S+)", ln, re.IGNORECASE)
        if not m:
            continue
        ifname = m.group(1)
        if ifname in known or _LOGICAL_IF.match(ifname):
            continue
        sub = _SUBIF.match(ifname)
        if sub and (sub.group("base") in known or _LOGICAL_IF.match(sub.group("base"))):
            continue
        # сериалки вида Serial0/0/0: покрыты реестром/структурой
        bases = {p.split("/")[0].split(" ")[0] for p in known} if known else set()
        if bases and structural_port_ok(ifname, bases):
            continue
        if problems is not None:
            problems.append({"severity": "warning", "device": dev,
                             "message": f"конфиг ссылается на неизвестный интерфейс «{ifname}»"})


def validate_spec(spec: dict, registry: dict,
                  donor_index: dict[str, str] | None = None,
                  donor_ports: dict[str, set[str]] | None = None) -> list[dict]:
    """Ядро валидации: возвращает список проблем {severity, device, message}."""
    problems: list[dict] = []
    donor_index = donor_index or {}
    donor_ports = donor_ports or {}

    def err(dev: str, msg: str):
        problems.append({"severity": "error", "device": dev, "message": msg})

    def warn(dev: str, msg: str):
        problems.append({"severity": "warning", "device": dev, "message": msg})

    devices = spec.get("devices") or []
    links = spec.get("links") or []

    # --- устройства ---
    names: list[str] = []
    dev_model: dict[str, str] = {}
    used_ports: dict[tuple[str, str], str] = {}
    ip_seen: dict[str, str] = {}

    for d in devices:
        name = d.get("name") or ""
        if not name:
            err("?", "устройство без имени (name)")
            continue
        names.append(name)
        model = d.get("model") or ""
        if not model and d.get("template"):
            # модель узнаем по донору позже; пока template-проверка отдельная
            model = "template:" + str(d["template"])
        dev_model[name] = model

    for n in names:
        if names.count(n) > 1:
            err(n, f"дублирующееся имя устройства «{n}»")

    for d in devices:
        name = d.get("name") or "?"
        tpl = d.get("template")
        mdl = d.get("model")
        if not tpl and not mdl:
            err(name, "нет ни template, ни model — сборщик не сможет клонировать устройство")
        if tpl and donor_index and tpl not in donor_index:
            err(name, f"template «{tpl}» отсутствует в доноре(ах)")
        if mdl and mdl not in ("PC-PT",) and mdl not in registry and registry:
            warn(name, f"модель «{mdl}» отсутствует в реестре (корпус её не видел)")

        # IP-поля
        ip = d.get("ip")
        if ip:
            mask = d.get("mask", "255.255.255.0")
            try:
                net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
            except ValueError as e:
                err(name, f"кривой IP/маска: {ip} {mask} ({e})")
                net = None
            gw = d.get("gateway")
            if gw:
                try:
                    gwa = ipaddress.ip_address(gw)
                    if net and gwa not in net:
                        err(name, f"шлюз {gw} вне подсети {ip}/{mask}")
                except ValueError:
                    err(name, f"кривой шлюз: {gw}")
            if net and str(net.network_address) in ip_seen:
                warn(name, f"IP {ip} дублируется с «{ip_seen[str(net.network_address)]}»")
            elif net:
                ip_seen[str(net.network_address)] = name
            dns = d.get("dns")
            if dns:
                try:
                    ipaddress.ip_address(dns)
                except ValueError:
                    err(name, f"кривой DNS: {dns}")

        # VLAN
        seen_ids: set[int] = set()
        for v in d.get("vlans") or []:
            vid = v.get("id")
            if not isinstance(vid, int) or not (1 <= vid <= 4094):
                err(name, f"кривой VLAN id: {vid!r}")
            elif vid in seen_ids:
                err(name, f"дублирующийся VLAN {vid}")
            seen_ids.add(vid)

        cfg = d.get("config")
        if cfg is not None:
            if not isinstance(cfg, list) or not all(isinstance(x, str) for x in cfg):
                err(name, "config должен быть списком строк CLI")
            else:
                mdl_real = donor_index.get(d.get("template") or "", d.get("model") or "")
                check_config_interfaces(name, mdl_real, cfg, registry, donor_ports, problems)

    # --- линки ---
    for l in links:
        a, b = l.get("from"), l.get("to")
        pa, pb = l.get("from_port") or "", l.get("to_port") or ""
        if a not in dev_model:
            err(str(a), f"линк ссылается на несуществующее устройство «{a}»")
            continue
        if b not in dev_model:
            err(str(b), f"линк ссылается на несуществующее устройство «{b}»")
            continue
        if a == b and pa == pb:
            err(a, f"линк сам в себя: {a}[{pa}] -> {b}[{pb}]")
        for dev, port in ((a, pa), (b, pb)):
            if not port:
                err(dev, f"линк {a}<->{b}: не указан порт устройства «{dev}»")
                continue
            key = (dev, port)
            if key in used_ports:
                err(dev, f"порт {port} занят дважды: «{used_ports[key]}» и «{a}<->{b}»")
            else:
                used_ports[key] = f"{a}<->{b}"
            mdl = dev_model.get(dev, "").replace("template:", "")
            mdl_real = donor_index.get(mdl, mdl)
            if registry and not valid_port(port, mdl_real, registry, donor_ports):
                err(dev, f"порта «{port}» нет у модели «{mdl_real or mdl}»")

    return problems


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("spec")
    ap.add_argument("--registry", default=None)
    ap.add_argument("--donor", action="append", default=[], help="донор .pkt/.xml (проверка template)")
    ap.add_argument("--max-warnings", type=int, default=10)
    args = ap.parse_args(argv)

    spec = json.loads(Path(args.spec).read_text(encoding="utf-8"))
    registry = load_registry(Path(args.registry) if args.registry else None)
    donor_index: dict[str, str] = {}
    donor_ports: dict[str, set[str]] = {}
    if args.donor:
        donor_index, donor_ports = donor_device_index([Path(p) for p in args.donor])

    problems = validate_spec(spec, registry, donor_index, donor_ports)
    errors = [p for p in problems if p["severity"] == "error"]
    warnings = [p for p in problems if p["severity"] == "warning"]
    for p in errors:
        print(f"ERROR [{p['device']}] {p['message']}")
    for p in warnings[: args.max_warnings]:
        print(f"warn  [{p['device']}] {p['message']}")
    if len(warnings) > args.max_warnings:
        print(f"… и ещё {len(warnings) - args.max_warnings} предупреждений")
    print(f"\nитог: устройств {len(spec.get('devices') or [])}, "
          f"линков {len(spec.get('links') or [])}, "
          f"ошибок {len(errors)}, предупреждений {len(warnings)}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
