#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
llm_e2e.py — сквозной тест с РЕАЛЬНЫМ LLM: текст задания → IR → валидация → .pkt.

Ключи берутся из окружения (НЕ хардкодить!):
    OPENAI_API_KEY, OPENAI_BASE_URL, OPENAI_MODEL

    python llm_e2e.py "текст задания" [--out out.pkt] [--task2 "задание с ошибкой"]
"""
from __future__ import annotations

import base64
import json
import os
import sys
from pathlib import Path

SERVICE = Path(__file__).parent
sys.path.insert(0, str(SERVICE))
sys.path.insert(0, str(SERVICE.parent / "engine"))

import pipeline  # noqa: E402
import pt_tool  # noqa: E402
import check_connectivity as _cc  # noqa: E402


def run_task(task: str, out_path: Path) -> dict:
    print(f"\n=== ЗАДАНИЕ: {task[:120]}")
    result = pipeline.run(task=task, provider="openai")
    print(f"итераций: {result['iterations']}")
    for line in result["log"]:
        print("  " + line)
    if not result["ok"]:
        print("!!! ПРОВАЛ:", result.get("error"))
        if result.get("ir"):
            print("IR (черновик):", json.dumps(result["ir"], ensure_ascii=False)[:600])
        return result
    pkt = base64.b64decode(result["pkt_b64"])
    out_path.write_bytes(pkt)
    # контроль: расшифровка + симуляция связности
    xml = pt_tool.decrypt_pkt_auto(pkt)
    ok_xml = b"<PACKETTRACER5" in xml[:100]
    problems, nhosts = _cc.analyze(out_path)
    ir = result["ir"]
    print(f"IR: устройств {len(ir.get('devices', []))}, линков {len(ir.get('links', []))}")
    print(f".pkt: {out_path} ({len(pkt)} Б), XML корректен: {ok_xml}")
    print(f"симуляция связности: {'OK' if not problems else problems[:3]} (хостов {nhosts})")
    return result


def main() -> int:
    task = sys.argv[1] if len(sys.argv) > 1 else (
        "Соберите лабораторную схему: компьютеры PC1 и PC2 подключены к коммутатору SW1 "
        "(модель 2960), коммутатор соединён с роутером R1 (модель 2911) через его порт "
        "GigabitEthernet0/0. Адресация 192.168.30.0/24: R1 — 192.168.30.1, PC1 — 192.168.30.10, "
        "PC2 — 192.168.30.11, шлюз для ПК — R1. Роутер должен пинговать оба ПК."
    )
    out = Path(sys.argv[sys.argv.index("--out") + 1]) if "--out" in sys.argv else SERVICE.parent / "out" / "llm_e2e_lab.pkt"
    out.parent.mkdir(parents=True, exist_ok=True)

    if not os.environ.get("OPENAI_API_KEY"):
        print("OPENAI_API_KEY не задан")
        return 1

    result = run_task(task, out)
    ok = bool(result.get("ok"))

    # тест repair-loop: намеренно невыполнимое требование → LLM должен исправить по фидбеку
    task2 = ("Соберите схему из двух устройств: роутер R1 (2911) и коммутатор SW1 (2960). "
             "Соедините порт GigabitEthernet0/9 роутера R1 с портом GigabitEthernet0/1 свитча SW1. "
             "Никакие другие порты не используйте.")
    out2 = out.with_name(out.stem + "_repair.pkt")
    print("\n=== REPAIR-LOOP ТЕСТ (в задании несуществующий порт Gi0/9):")
    result2 = run_task(task2, out2)
    ok2 = bool(result2.get("ok"))
    if ok2:
        ir2 = result2["ir"]
        used = [l.get("from_port") for l in ir2.get("links", [])]
        print(f"LLM использовал порт(ы) вместо Gi0/9: {used} — repair-loop сработал"
              if any("0/9" not in (u or "") for u in used) else "LLM оставил битый порт")

    print(f"\nИТОГ: основной E2E {'OK' if ok else 'FAIL'}, repair-loop {'OK' if ok2 else 'FAIL'}")
    return 0 if (ok and ok2) else 1


if __name__ == "__main__":
    raise SystemExit(main())
