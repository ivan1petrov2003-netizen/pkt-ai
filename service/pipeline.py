#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pipeline.py — ядро сервиса: задание (+ фото) → IR → валидация → repair-loop → .pkt.

Использует движок из ../engine (pt_build, validate, pt_tool) и реестр моделей.
Repair-loop: до MAX_ITER раз ошибки валидации возвращаются в LLM на исправление.
"""
from __future__ import annotations

import base64
import json
import re
import sys
import time
import uuid
from pathlib import Path

ENGINE = Path(__file__).parent.parent / "engine"
sys.path.insert(0, str(ENGINE))
sys.path.insert(0, str(Path(__file__).parent))

import validate as _v  # noqa: E402
import pt_build  # noqa: E402
import pt_tool  # noqa: E402
import llm as _llm  # noqa: E402

MAX_ITER = 3
DEFAULT_DONOR = ENGINE / "a.xml"

SYSTEM_PROMPT = """Ты — сетевой инженер, собирающий лабораторные работы в Cisco Packet Tracer.
Пользователь даёт задание (текст, возможно с фото схемы). Ты возвращаешь ТОЛЬКО JSON
в формате pt_build (без пояснений, без markdown-ограждений):

{
  "devices": [
    {"name": "R1", "template": "Router0", "x": 300, "y": 200,
     "config": ["hostname R1", "interface GigabitEthernet0/0",
                " ip address 10.0.0.1 255.255.255.0", " no shutdown"]},
    {"name": "SW1", "template": "Switch0", "x": 500, "y": 200,
     "vlans": [{"id": 10, "name": "IT"}], "config": ["…"]},
    {"name": "PC1", "template": "PC0", "x": 250, "y": 350,
     "ip": "10.0.0.10", "mask": "255.255.255.0", "gateway": "10.0.0.1", "dns": "8.8.8.8"}
  ],
  "links": [
    {"from": "R1", "from_port": "GigabitEthernet0/0",
     "to": "SW1", "to_port": "GigabitEthernet0/1"}
  ]
}

Правила:
- name — уникальное имя; template — имя устройства-донора из инвентаря ниже
  (или "model": "<модель>" вместо template).
- x, y — координаты на канве (пирамидой/слоями, без пересечений).
- config — ПОЛНЫЙ список строк CLI без приглашений; для PC/Server конфиг не нужен —
  используй ip/mask/gateway/dns.
- Порты бери строго из инвентаря донора ниже. Каждый порт — максимум один линк.
- Кабели: роутер↔свитч/хост eStraightThrough, свитч↔свитч и роутер↔роутер eCrossOver
  (можно не указывать — подберётся автоматически).
- Wi-Fi клиенты (Smartphone) к AP не линком: SSID в устройстве, линк не создавай.
- IP-план: подсети без пересечений; шлюз — адрес интерфейса роутера в той же подсети;
  /30 для p2p-транзитов; маски точные.
- Для VLAN: vlans на свитчах + trunk/access в конфигах + сабинтерфейсы роутера
  (encapsulation dot1Q N).
- Если фото схемы — точно перенеси устройства, имена, связи и подписи IP с неё.
Верни только JSON."""


def donor_inventory(donor_path: Path) -> str:
    """Текстовый инвентарь донора для промпта: имена, модели, порты."""
    di, dp = _v.donor_device_index([donor_path])
    registry = _v.load_registry(None)
    lines = ["Инвентарь донора (template -> модель, доступные порты):"]
    for name, model in sorted(di.items()):
        ports = sorted(dp.get(model, set()))
        if not ports and model in registry:
            ports = registry[model]["ports"]
        if not ports:
            lines.append(f"  {name} ({model})")
        elif len(ports) > 14:
            fam: dict[str, list[str]] = {}
            for p in ports:
                m = re.match(r"^([A-Za-z]+)", p)
                fam.setdefault(m.group(1) if m else p, []).append(p)
            pretty = ", ".join(
                (f"{ps[0]}…{ps[-1]}" if len(ps) > 2 else ", ".join(ps))
                for ps in fam.values()
            )
            lines.append(f"  {name} ({model}): {pretty}")
        else:
            lines.append(f"  {name} ({model}): {', '.join(ports)}")
    return "\n".join(lines)


def build_pkt(ir: dict, donor_xml: bytes) -> bytes:
    xml = pt_build.build(ir, donor_xml)
    return pt_tool.encrypt_pkt(xml)


def _connectivity_check(pkt_bytes: bytes) -> list[str]:
    """Симуляция пингов собранного файла без PT (check_connectivity)."""
    import tempfile

    import check_connectivity as _cc

    with tempfile.NamedTemporaryFile(suffix=".pkt", delete=False) as tf:
        tf.write(pkt_bytes)
        tmp = tf.name
    try:
        problems, _ = _cc.analyze(Path(tmp))
        return sorted(set(problems))
    finally:
        Path(tmp).unlink(missing_ok=True)


def run(task: str, images: list[str] | None = None, provider: str | None = None,
        model: str | None = None, donor_path: Path | None = None,
        inline_ir: dict | None = None) -> dict:
    """Полный цикл. Возвращает {ok, pkt_b64, ir, problems, iterations, log}."""
    donor_path = donor_path or DEFAULT_DONOR
    donor_xml = (donor_path.read_bytes() if donor_path.suffix.lower() == ".xml"
                 else pt_tool.decrypt_pkt_auto(donor_path.read_bytes()))
    registry = _v.load_registry(None)
    di, dp = _v.donor_device_index([donor_path])
    system = SYSTEM_PROMPT + "\n\n" + donor_inventory(donor_path)

    log: list[str] = []
    t0 = time.time()

    # --- inline IR: без LLM ---
    if inline_ir is not None:
        problems = _v.validate_spec(inline_ir, registry, di, dp)
        errors = [p for p in problems if p["severity"] == "error"]
        log.append(f"inline IR: ошибок {len(errors)}, предупреждений "
                   f"{len(problems) - len(errors)}")
        if errors:
            return {"ok": False, "pkt_b64": None, "ir": inline_ir, "problems": problems,
                    "iterations": 0, "log": log, "error": "inline IR не прошёл валидацию"}
        pkt = build_pkt(inline_ir, donor_xml)
        conn = _connectivity_check(pkt)
        log.append("связность (симуляция пингов): " + ("OK" if not conn else "; ".join(conn[:3])))
        if conn:
            return {"ok": False, "pkt_b64": None, "ir": inline_ir, "problems": problems,
                    "iterations": 0, "log": log, "connectivity": conn,
                    "error": "собранная схема не проходит проверку связности"}
        log.append(f"собрано .pkt за {time.time() - t0:.1f}с")
        return {"ok": True, "pkt_b64": base64.b64encode(pkt).decode(), "ir": inline_ir,
                "problems": problems, "connectivity": [], "iterations": 0, "log": log}

    # --- LLM + repair-loop ---
    prov_name, chat = _llm.pick_provider(provider)
    log.append(f"провайдер: {prov_name}" + (f", модель {model}" if model else ""))
    user_msg = task
    messages_extra: list[dict] = []  # пары (assistant, user) для repair-loop
    ir = None

    for it in range(1, MAX_ITER + 1):
        full_user = user_msg if it == 1 else user_msg
        text = _chat_with_history(chat, system, full_user, images, model, messages_extra)
        try:
            ir = _llm.extract_json(text)
        except _llm.LLMError as e:
            log.append(f"[итерация {it}] {e}; повтор с требованием чистого JSON")
            messages_extra.append({"role": "assistant", "content": text[:4000]})
            messages_extra.append({
                "role": "user",
                "content": "Твой ответ не был чистым JSON. Верни ТОЛЬКО JSON-объект "
                           "{\"devices\": [...], \"links\": [...]}, без текста вокруг."})
            continue

        problems = _v.validate_spec(ir, registry, di, dp)
        errors = [p for p in problems if p["severity"] == "error"]
        log.append(f"[итерация {it}] устройств {len(ir.get('devices', []))}, "
                   f"линков {len(ir.get('links', []))}, ошибок {len(errors)}")
        if not errors:
            pkt = build_pkt(ir, donor_xml)
            conn = _connectivity_check(pkt)
            if conn:
                log.append(f"[итерация {it}] связность: " + "; ".join(conn[:3]))
                if it == MAX_ITER:
                    return {"ok": False, "pkt_b64": None, "ir": ir, "problems": problems,
                            "connectivity": conn, "iterations": it, "log": log,
                            "error": "схема собирается, но не проходит проверку связности"}
                # связность чинит тот же repair-loop: ошибки валидации = проблемы связности
                messages_extra.append({"role": "assistant",
                                       "content": json.dumps(ir, ensure_ascii=False)[:8000]})
                messages_extra.append({"role": "user",
                                       "content": _repair_prompt([
                                           {"device": "сеть", "message": m} for m in conn])})
                continue
            log.append(f"готово: .pkt собран за {time.time() - t0:.1f}с (связность OK)")
            return {"ok": True, "pkt_b64": base64.b64encode(pkt).decode(), "ir": ir,
                    "problems": problems, "connectivity": [], "iterations": it, "log": log}

        if it == MAX_ITER:
            break
        log.append(f"[итерация {it}] возврат ошибок в LLM на исправление")
        messages_extra.append({"role": "assistant",
                               "content": json.dumps(ir, ensure_ascii=False)[:8000]})
        messages_extra.append({"role": "user", "content": _repair_prompt(errors)})

    return {"ok": False, "pkt_b64": None, "ir": ir, "problems": problems, "iterations": MAX_ITER,
            "log": log, "error": f"валидация не пройдена за {MAX_ITER} итераций"}


def _chat_with_history(chat, system, user, images, model, extras) -> str:
    """Провайдеры ниже не принимают историю — склеиваем repair-диалог в user-сообщение."""
    if extras:
        hist = "\n\n".join(
            f"[Предыдущий ответ]:\n{m['content']}\n\n[Замечание]:\n{extras[i + 1]['content']}"
            for i, m in enumerate(extras[::2])
        )
        user = hist + f"\n\n[Задание]:\n{user}\n\nВерни исправленный ТОЛЬКО JSON."
        images = None  # фото учитываем только в первой итерации
    return chat(system, user, images, model)


def _repair_prompt(errors: list[dict]) -> str:
    lines = ["Твой JSON не прошёл валидацию. Исправь ТОЛЬКО эти ошибки и верни "
             "ПОЛНЫЙ исправленный JSON:"]
    for p in errors[:15]:
        lines.append(f"- [{p['device']}] {p['message']}")
    return "\n".join(lines)
