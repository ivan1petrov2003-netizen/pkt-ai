# Сервис pkt-ai

Два способа для «любой нейросети» собирать .pkt:

## 1. REST API (универсальный HTTP)

```bash
cd C:\Users\gaming\Desktop\pkt-ai\service
python -m uvicorn app:app --host 127.0.0.1 --port 8317
```

- Swagger: http://127.0.0.1:8317/docs
- `GET  /api/v1/inventory` — инвентарь донора (что доступно LLM)
- `POST /api/v1/labs`:
```json
{
  "task": "Собери сеть: PC и сервер в VLAN 10, роутер 2911, адресация 192.168.5.0/24",
  "images": ["data:image/png;base64,..."],
  "provider": "auto",
  "model": null,
  "inline_ir": null
}
```
Ответ: `{"ok": true, "pkt_b64": "...", "file": "…\\out\\….pkt", "ir": {...}, "validation": [], "log": [...]}`

### Ключи LLM (env)
- `ANTHROPIC_API_KEY` или `OPENAI_API_KEY` (+ опционально `OPENAI_BASE_URL`, `OPENAI_MODEL`, `ANTHROPIC_MODEL`)
- `PKT_AI_API_KEY` — если задан, требует заголовок `X-API-Key`
- Без ключа API всё равно работает: `inline_ir` → валидация → .pkt (для тестов и MCP-оркестрации)

Repair-loop: ошибки валидатора автоматически возвращаются LLM (до 3 итераций).

## 2. MCP-сервер (Claude Desktop и любые MCP-агенты)

`claude_desktop_config.json`:
```json
"mcpServers": {
  "pkt-ai": {
    "command": "python",
    "args": ["C:/Users/gaming/Desktop/pkt-ai/service/mcp_server.py"]
  }
}
```

Инструменты: `inventory()` → `build_pkt(ir)` → готовый .pkt в `out/`;
также `validate_ir(ir)` и `pkt_inspect(файл)` (расшифровка чужих .pkt).

## Тесты
```bash
python e2e_test.py        # 12 проверок API без ключа
```
