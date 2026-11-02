# USAGE.md — как пользоваться pkt-ai

## Что это

Система, которая **превращает текст задания (и фото схемы) в готовый файл Cisco Packet Tracer (.pkt)**
с работающими устройствами и пингами. Работает в три слоя:

```
текст задания / фото
        │
        ▼
  [1] LLM (любая нейросеть через API) → IR-JSON (устройства, линки, конфиги)
        │
        ▼
  [2] Валидатор: порты, IP, ссылки, VLAN, связность   ──ошибки──▶ назад в LLM (≤3 раз)
        │
        ▼
  [3] Builder: клонирует реальные устройства из донора → шифрует → .pkt
        │
        ▼
  готовый файл: открывается в PT 8.0, пинги ходят (проверено вживую)
```

---

## 1. Самый простой способ — командная строка (без нейросети)

Готовые проверенные лабы лежат в `corpus/golden/` — просто открывайте их в Packet Tracer.

Собрать свою схему из JSON-описания:

```bash
cd C:\Users\gaming\Desktop\pkt-ai\engine
python pt_build.py моя_схема.json -o результат.pkt --template a.xml
```

Формат JSON (см. `golden/g1_simple_lan.json` как образец):

```json
{
  "devices": [
    {"name": "R1", "template": "Router0", "x": 400, "y": 100,
     "config": ["hostname R1", "interface GigabitEthernet0/0",
                " ip address 192.168.1.1 255.255.255.0", " no shutdown"]},
    {"name": "PC1", "template": "PC0", "x": 250, "y": 380,
     "ip": "192.168.1.10", "mask": "255.255.255.0", "gateway": "192.168.1.1"}
  ],
  "links": [
    {"from": "R1", "from_port": "GigabitEthernet0/0", "to": "SW1", "to_port": "GigabitEthernet0/1"}
  ]
}
```

- `template` — имя устройства-донора (список: `python donor_list.py a.xml`)
- перед сборкой автоматом проходит валидация (несуществующий порт → сборка отменена)

## 2. Через нейросеть — REST API

```bash
cd C:\Users\gaming\Desktop\pkt-ai\service
set OPENAI_API_KEY=ваш_ключ
set OPENAI_BASE_URL=https://plusvibeapi.ru/v1
set OPENAI_MODEL=deepseek-v4-flash-0731:free
python -m uvicorn app:app --host 127.0.0.1 --port 8317
```

Откройте http://127.0.0.1:8317/docs — там интерактивная форма. Либо запросом:

```
POST /api/v1/labs
{"task": "Соберите: PC1 и PC2 через свитч 2960 к роутеру 2911, сеть 192.168.30.0/24"}
```

Ответ: `{"ok": true, "pkt_b64": "...", "file": "…out\\….pkt", "ir": {...}, "log": [...]}` —
файл уже лежит в `out/`, можно открыть в PT.

Если LLM ошибся (несуществующий порт и т.п.) — валидатор вернёт ошибку нейросети,
и она исправит сама (до 3 итераций). Проверено: ловушка с битым портом исправляется.

## 3. Через MCP — для Claude Desktop и других MCP-агентов

В `claude_desktop_config.json`:

```json
"mcpServers": { "pkt-ai": { "command": "python",
  "args": ["C:/Users/gaming/Desktop/pkt-ai/service/mcp_server.py"] } }
```

Инструменты: `inventory()` → `build_pkt(ir)` → готовый .pkt; ещё `validate_ir`, `pkt_inspect`
(расшифровка чужих .pkt).

## 4. Утилиты ядра

```bash
cd C:\Users\gaming\Desktop\pkt-ai\engine
python pt_tool.py info файл.pkt          # версия/размер/контейнер
python pt_tool.py decrypt a.pkt -o a.xml # расшифровать (PT 6–9.x, оба контейнера)
python pt_tool.py encrypt a.xml -o b.pkt # зашифровать обратно
python pkt_graph.py a.xml -o topo.json   # топология в JSON
python export_spec.py a.pkt -o spec.json # .pkt → IR-спека (для few-shot'ов)
python check_connectivity.py лаба.pkt    # симуляция пингов без открытия PT
python build_golden.py                   # пересобрать все 5 эталонных лаб
python donor_registry.py <папка> -o registry.json  # реестр моделей из корпуса
```

## 5. Важно знать

- **Первые 1–2 ICMP-пакета могут теряться (ARP)** — это норма PT, пустите пинг второй раз.
- После открытия файла нажмите **«>>» (Fast Forward Time)** в правом нижнем углу 10–15 раз —
  свитчи/роутеры мгновенно «договорятся».
- Движок работает с PT 6–9.x: современный контейнер (Twofish-EAX) + легаси (XOR+zlib).
- Ключи/URL нейросети храните только в переменных окружения — в код они не записаны.

## 6. Проверено живьём (Packet Tracer 8.0.0.0212, скриншоты в docs/evidence/)

| Лаба | Пинг | Результат |
|---|---|---|
| g1_simple_lan (LAN через свитч) | PC1→PC2 | **Successful 3/3** |
| g2_vlan_trunk (меж-VLAN через роутер) | PC-A→PC-B | **Successful** (1-й ARP) |
| g3_static (2 роутера, статика) | PC1→PC2 | **Successful** (1-2 ARP) |
| g4_ospf (3 роутера, OSPF) | PC1→PC3 | **Successful 3/4** |
| g5_pr3_x17 (ПР№3: PAgP/LACP, VLAN, IPv6) | PC1→SRV01 (меж-VLAN) | **Successful 3/4** |
| **llm_e2e_lab (собрана нейросетью из текста!)** | PC1→PC2 | **Successful 3/3** |
