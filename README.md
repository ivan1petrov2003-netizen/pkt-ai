# pkt-ai

Генератор схем Cisco Packet Tracer: текст задания / фото → LLM → IR (JSON) → детерминированный
builder → валидный `.pkt` (PT 6–8.x).

- План и прогресс: [PLAN.md](PLAN.md), журнал: [PROGRESS.md](PROGRESS.md)
- Криптоядро (Фаза 0): `packages/core` — расшифровка/шифрование .pkt ⇄ XML
- CLI: `node packages/cli/src/pkt-tool.ts help`
- Тесты: `npm test` (node:test, без внешних зависимостей)
