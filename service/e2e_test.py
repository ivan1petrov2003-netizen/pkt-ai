#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
e2e_test.py — сквозной тест сервиса БЕЗ LLM-ключа (inline IR → валидация → сборка → .pkt).

    python e2e_test.py
Код возврата 0 = всё зелёное.
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

SERVICE = Path(__file__).parent
sys.path.insert(0, str(SERVICE))
sys.path.insert(0, str(SERVICE.parent / "engine"))

import pt_tool  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import app  # noqa: E402

client = TestClient(app)
fails = 0


def check(name: str, cond: bool, extra: str = ""):
    global fails
    print(("OK  " if cond else "FAIL") + f" {name}" + (f" — {extra}" if extra else ""))
    if not cond:
        fails += 1


# 1) health
r = client.get("/health")
check("GET /health", r.status_code == 200 and r.json()["ok"])

# 2) inventory
r = client.get("/api/v1/inventory")
inv = r.json()
check("GET /api/v1/inventory", r.status_code == 200 and "Router0" in inv["inventory"])
check("реестр подключён", inv["registry_models"] >= 100, f"{inv['registry_models']} моделей")

# 3) полный цикл с inline IR (золотая лаба G2) — валидация + сборка + круглый путь
g2 = json.loads((SERVICE.parent / "engine" / "golden" / "g2_vlan_trunk.json").read_text(encoding="utf-8"))
r = client.post("/api/v1/labs", json={"task": "VLAN 10/20 через router-on-a-stick",
                                      "inline_ir": g2})
body = r.json()
check("POST /labs (inline IR) = 200", r.status_code == 200, str(body.get("error", "")))
check("ответ ok", body.get("ok") is True)
check("валидация без ошибок", not [p for p in body.get("validation", []) if p["severity"] == "error"])
check("файл записан", bool(body.get("file")) and Path(body["file"]).exists(), body.get("file", ""))

pkt = base64.b64decode(body["pkt_b64"])
xml = pt_tool.decrypt_pkt_auto(pkt)
check("PKT расшифровывается (наш core)", b"<PACKETTRACER5>" in xml[:200])
flat = b" ".join(xml.split())
check("конфиг R1 на месте", b"encapsulation dot1Q 10" in flat)

# 4) негативный: битый inline IR → 200 c ok=false и ошибками валидации
bad = json.loads(json.dumps(g2))
bad["links"][0]["from_port"] = "GigabitEthernet0/9"
r = client.post("/api/v1/labs", json={"task": "bad", "inline_ir": bad})
body = r.json()
check("битый IR → ok=false", r.status_code == 200 and body.get("ok") is False)
check("ошибка валидации видна", any("GigabitEthernet0/9" in p["message"]
                                    for p in body.get("validation", [])))

# 5) без ключа-провайдера и без inline_ir → понятная ошибка, не 500
r = client.post("/api/v1/labs", json={"task": "собери сеть"})
body = r.json()
check("нет провайдера → внятная ошибка", r.status_code == 200 and body.get("ok") is False
      and "провайдер" in (body.get("error") or "") + str(body.get("log", [])))

print(f"\n{'ВСЁ ЗЕЛЁНОЕ' if fails == 0 else f'ПРОВАЛОВ: {fails}'}")
sys.exit(1 if fails else 0)
