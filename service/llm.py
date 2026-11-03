#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
llm.py — провайдеры LLM для pkt-ai. Все возвращают ТЕКСТ ответа.

Провайдеры:
  openai     — любой OpenAI-совместимый (OpenAI, vLLM, OpenRouter, DeepSeek…)
  anthropic  — Claude (api.anthropic.com)
  inline     — IR передан напрямую (без LLM; для тестов и MCP-оркестрации)

Ключи/настройки из окружения:
  OPENAI_API_KEY, OPENAI_BASE_URL (default https://api.openai.com/v1), OPENAI_MODEL (default gpt-4o)
  ANTHROPIC_API_KEY, ANTHROPIC_BASE_URL (default https://api.anthropic.com), ANTHROPIC_MODEL
"""
from __future__ import annotations

import base64
import os
import re


class LLMError(RuntimeError):
    pass


def _data_url_parts(data_url: str) -> tuple[str, bytes]:
    """'data:image/png;base64,XXX' -> ('image/png', bytes)."""
    m = re.match(r"^data:(image/[a-zA-Z0-9.+-]+);base64,(.*)$", data_url.strip(), re.DOTALL)
    if not m:
        raise LLMError("изображение должно быть data URL (data:image/...;base64,....)")
    return m.group(1), base64.b64decode(m.group(2))


def _http_post(url: str, headers: dict, payload: dict, timeout: float = 420.0) -> dict:
    import httpx

    try:
        r = httpx.post(url, headers=headers, json=payload, timeout=timeout)
    except httpx.TimeoutException as e:
        raise LLMError(f"LLM не ответил за {timeout:.0f}с (модель занята/медленная): {e}") from e
    except httpx.HTTPError as e:
        raise LLMError(f"сетевая ошибка LLM: {e}") from e
    if r.status_code >= 400:
        raise LLMError(f"LLM HTTP {r.status_code}: {r.text[:500]}")
    return r.json()


def chat_openai(system: str, user: str, images: list[str] | None = None,
                model: str | None = None) -> str:
    base = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    key = os.environ.get("OPENAI_API_KEY")
    if not key:
        raise LLMError("OPENAI_API_KEY не задан")
    content: list[dict] | str = user
    if images:
        content = [{"type": "text", "text": user}]
        for du in images:
            mt, raw = _data_url_parts(du)
            content.append({"type": "image_url",
                            "image_url": {"url": f"data:{mt};base64,{base64.b64encode(raw).decode()}"}})
    payload = {
        "model": model or os.environ.get("OPENAI_MODEL", "gpt-4o"),
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": content}],
        "temperature": 0.2,
    }
    data = _http_post(f"{base}/chat/completions",
                      {"Authorization": f"Bearer {key}"}, payload)
    try:
        msg = data["choices"][0]["message"]
        content = msg.get("content") or ""
        if not content.strip():
            # reasoning-модели: при обрезке токенов ответ может остаться в reasoning_content
            content = msg.get("reasoning_content") or ""
        return content
    except (KeyError, IndexError) as e:
        raise LLMError(f"неожиданный ответ OpenAI: {e}: {str(data)[:300]}")


def chat_anthropic(system: str, user: str, images: list[str] | None = None,
                   model: str | None = None) -> str:
    base = os.environ.get("ANTHROPIC_BASE_URL", "https://api.anthropic.com").rstrip("/")
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise LLMError("ANTHROPIC_API_KEY не задан")
    content: list[dict] = []
    for du in images or []:
        mt, raw = _data_url_parts(du)
        content.append({"type": "image",
                        "source": {"type": "base64", "media_type": mt,
                                   "data": base64.b64encode(raw).decode()}})
    content.append({"type": "text", "text": user})
    payload = {
        "model": model or os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-5"),
        "max_tokens": 8000,
        "system": system,
        "messages": [{"role": "user", "content": content}],
        "temperature": 0.2,
    }
    data = _http_post(f"{base}/v1/messages",
                      {"x-api-key": key, "anthropic-version": "2023-06-01"}, payload)
    try:
        return "".join(b.get("text", "") for b in data["content"] if b.get("type") == "text")
    except (KeyError, TypeError) as e:
        raise LLMError(f"неожиданный ответ Anthropic: {e}: {str(data)[:300]}")


def extract_json(text: str) -> dict:
    """Достаёт JSON-объект из ответа LLM (терпит ```-ограждения и мусор вокруг)."""
    t = text.strip()
    t = re.sub(r"^```(?:json)?\s*|\s*```$", "", t, flags=re.MULTILINE).strip()
    start, end = t.find("{"), t.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise LLMError("в ответе LLM нет JSON-объекта")
    import json

    try:
        return json.loads(t[start:end + 1])
    except json.JSONDecodeError as e:
        raise LLMError(f"JSON от LLM не парсится: {e}")


def pick_provider(preferred: str | None = None):
    """-> (name, chat_fn). 'auto': anthropic → openai → ошибка."""
    order = {"anthropic": chat_anthropic, "openai": chat_openai}
    if preferred and preferred != "auto":
        if preferred not in order:
            raise LLMError(f"неизвестный провайдер «{preferred}» (openai|anthropic|auto)")
        return preferred, order[preferred]
    for name, fn in order.items():
        if os.environ.get({"anthropic": "ANTHROPIC_API_KEY",
                           "openai": "OPENAI_API_KEY"}[name]):
            return name, fn
    raise LLMError("нет доступного провайдера: задайте ANTHROPIC_API_KEY или OPENAI_API_KEY "
                   "(или передайте inline_ir)")
