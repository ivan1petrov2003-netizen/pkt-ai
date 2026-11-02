#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mcp_server.py — MCP-сервер pkt-ai: любая MCP-совместимая нейросеть (Claude Desktop и др.)
собирает валидные .pkt как инструментом.

Tools:
  build_pkt(ir, task?, donor?)     — IR-JSON → .pkt (валидация внутри; файл в out/, путь в ответе)
  validate_ir(ir, donor?)          — проверить IR, вернуть список проблем
  inventory(donor?)                — какие template/модели/порты доступны
  pkt_inspect(file)                — расшифровать .pkt/.pka → сводка (версия, устройства, линки)

Запуск:   python mcp_server.py
Подключение (Claude Desktop, claude_desktop_config.json):
  "mcpServers": { "pkt-ai": { "command": "python",
                              "args": ["C:/Users/gaming/Desktop/pkt-ai/service/mcp_server.py"] } }
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

from mcp.server.fastmcp import FastMCP

SERVICE = Path(__file__).parent
sys.path.insert(0, str(SERVICE))
sys.path.insert(0, str(SERVICE.parent / "engine"))

import pipeline  # noqa: E402
import pt_tool  # noqa: E402
import validate as _v  # noqa: E402

OUT_DIR = SERVICE.parent / "out"
ENGINE = SERVICE.parent / "engine"

mcp = FastMCP("pkt-ai")


def _donor(name: str | None) -> Path:
    if not name:
        return pipeline.DEFAULT_DONOR
    p = (ENGINE / name).resolve()
    if not str(p).startswith(str(ENGINE.resolve())) or not p.exists():
        raise ValueError(f"донор «{name}» не найден в engine/")
    return p


@mcp.tool()
def build_pkt(ir: dict, task: str = "", donor: str = "") -> str:
    """Собрать файл Cisco Packet Tracer (.pkt) из IR-JSON (devices+links, формат pt_build).
    IR валидируется; готовый файл пишется в out/ и расшифровочно проверяется.
    Возвращает JSON: {ok, file, validation, log} или {ok:false, validation}."""
    try:
        result = pipeline.run(task=task or "MCP build", provider="auto",
                              donor_path=_donor(donor or None), inline_ir=ir)
    except Exception as e:  # noqa: BLE001
        return json.dumps({"ok": False, "error": str(e)}, ensure_ascii=False)
    if not result["ok"]:
        return json.dumps({"ok": False, "validation": result["problems"],
                           "log": result["log"]}, ensure_ascii=False)
    pkt = base64.b64decode(result["pkt_b64"])
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUT_DIR / f"mcp_{int(__import__('time').time())}.pkt"
    out.write_bytes(pkt)
    return json.dumps({"ok": True, "file": str(out), "size": len(pkt),
                       "validation": result["problems"]}, ensure_ascii=False)


@mcp.tool()
def validate_ir(ir: dict, donor: str = "") -> str:
    """Проверить IR-JSON без сборки: ссылки, порты (по реестру 140 моделей и донору),
    IP-план, VLAN, интерфейсы в конфигах. Возвращает список проблем с severity."""
    p = _donor(donor or None)
    registry = _v.load_registry(None)
    di, dp = _v.donor_device_index([p])
    problems = _v.validate_spec(ir, registry, di, dp)
    errors = [x for x in problems if x["severity"] == "error"]
    return json.dumps({"ok": not errors, "problems": problems}, ensure_ascii=False)


@mcp.tool()
def inventory(donor: str = "") -> str:
    """Инвентарь донора: доступные template (имя → модель) и списки портов.
    Вызывай ПЕРЕД build_pkt, чтобы знать допустимые имена устройств и портов."""
    return pipeline.donor_inventory(_donor(donor or None))


@mcp.tool()
def pkt_inspect(file: str) -> str:
    """Расшифровать .pkt/.pka (PT 6–8.x, оба контейнера) и вернуть сводку:
    версия PT, устройства (имя+модель), линки, размер XML."""
    p = Path(file)
    if not p.exists():
        return json.dumps({"error": f"файл не найден: {file}"}, ensure_ascii=False)
    xml = pt_tool.decrypt_pkt_auto(p.read_bytes()).decode("utf-8", errors="replace")
    import re as _re

    from lxml import etree

    root = etree.fromstring(xml.encode("utf-8"),
                            etree.XMLParser(recover=True, huge_tree=True))
    ver_m = _re.search(r"<VERSION>([^<]+)</VERSION>", xml[:4000])
    devices = []
    for dev in root.iter("DEVICE"):
        eng = dev.find("ENGINE")
        if eng is None:
            continue
        t = eng.find("TYPE")
        devices.append({"name": eng.findtext("NAME") or "?",
                        "model": (t.get("model") or "?") if t is not None else "?"})
    return json.dumps({"file": str(p), "pt_version": ver_m.group(1) if ver_m else "?",
                       "xml_bytes": len(xml), "devices": devices[:80],
                       "link_count": xml.count("<LINK>")}, ensure_ascii=False)


if __name__ == "__main__":
    mcp.run()  # stdio
