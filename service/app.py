#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
app.py — REST API pkt-ai.

    POST /api/v1/labs   {"task": "текст задания", "images": ["data:image/png;base64,…"],
                         "provider": "auto|openai|anthropic", "model": "…",
                         "inline_ir": {…}}            → {"pkt_b64", "ir", "validation", …}

    GET  /api/v1/inventory → инвентарь донора (что доступно LLM)
    GET  /health

Запуск:  python -m uvicorn app:app --host 127.0.0.1 --port 8317   (из папки service/)
Авторизация: если задан PKT_AI_API_KEY — требуется заголовок X-API-Key.
Любая нейросеть может вызывать HTTP; MCP-обёртка — phase 4.
"""
from __future__ import annotations

import base64
import os
import re
import sys
import time
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

SERVICE = Path(__file__).parent
sys.path.insert(0, str(SERVICE))

import pipeline  # noqa: E402
import llm as _llm  # noqa: E402

ENGINE = SERVICE.parent / "engine"

app = FastAPI(
    title="pkt-ai API",
    version="0.1.0",
    description="Текст задания (+ фото) → Cisco Packet Tracer .pkt. "
                "IR-JSON генерирует LLM, XML собирает детерминированный builder.",
)

OUT_DIR = Path(os.environ.get("PKT_AI_OUT", SERVICE.parent / "out"))
REQ_KEY = os.environ.get("PKT_AI_API_KEY")


class LabRequest(BaseModel):
    task: str = Field(min_length=1, description="Текст задания из методички")
    images: list[str] = Field(default_factory=list, description="data URL изображений")
    provider: str | None = Field(default="auto", description="auto|openai|anthropic")
    model: str | None = None
    donor: str | None = Field(default=None, description="имя файла донора в engine/ (a.xml)")
    inline_ir: dict | None = Field(default=None,
                                   description="Готовый IR (без LLM) — для тестов и MCP")


def _auth(key: str | None):
    if REQ_KEY and key != REQ_KEY:
        raise HTTPException(status_code=401, detail="неверный X-API-Key")


def _safe_donor(name: str | None) -> Path:
    if not name:
        return pipeline.DEFAULT_DONOR
    p = (ENGINE / name).resolve()
    if not str(p).startswith(str(ENGINE.resolve())) or not p.exists():
        raise HTTPException(status_code=400, detail=f"донор «{name}» не найден в engine/")
    return p


def _slug(text: str) -> str:
    s = re.sub(r"[^\w\d-]+", "_", text[:40].strip(), flags=re.UNICODE).strip("_")
    return s or "lab"


@app.get("/health")
def health():
    return {"ok": True, "version": "0.1.0"}


@app.get("/api/v1/inventory")
def inventory(donor: str | None = None, x_api_key: str | None = Header(default=None)):
    _auth(x_api_key)
    p = _safe_donor(donor)
    inv = pipeline.donor_inventory(p)
    registry = __import__("validate").load_registry(None)
    return {"donor": p.name, "inventory": inv, "registry_models": len(registry)}


@app.post("/api/v1/labs")
def create_lab(req: LabRequest, x_api_key: str | None = Header(default=None)):
    _auth(x_api_key)
    donor = _safe_donor(req.donor)
    try:
        result = pipeline.run(task=req.task, images=req.images or None,
                              provider=req.provider, model=req.model,
                              donor_path=donor, inline_ir=req.inline_ir)
    except _llm.LLMError as e:
        return {"ok": False, "error": str(e), "iterations": 0,
                "validation": [], "log": ["конфигурация LLM: " + str(e)]}

    resp = {
        "ok": result["ok"],
        "iterations": result["iterations"],
        "validation": result["problems"],
        "log": result["log"],
    }
    if result["ok"]:
        pkt = base64.b64decode(result["pkt_b64"])
        OUT_DIR.mkdir(parents=True, exist_ok=True)
        fname = f"{time.strftime('%Y%m%d_%H%M%S')}_{_slug(req.task)[:40]}.pkt"
        (OUT_DIR / fname).write_bytes(pkt)
        resp["pkt_b64"] = result["pkt_b64"]
        resp["file"] = str(OUT_DIR / fname)
        resp["ir"] = result["ir"]
    else:
        resp["error"] = result.get("error")
        if result.get("ir"):
            resp["ir"] = result["ir"]
    return resp
