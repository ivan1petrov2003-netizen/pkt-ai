# Cisco Packet Tracer: расшифровка и сборка схем

Набор утилит без внешних зависимостей (кроме `lxml` для работы с XML).

| Файл | Назначение |
|---|---|
| `pt_tool.py` | расшифровать `.pkt/.pka` → XML и обратно; `info` — краткая сводка |
| `pkt_graph.py` | XML → компактный JSON (устройства, интерфейсы, конфиги, линки) |
| `pt_build.py` | JSON-описание схемы → готовый `.pkt` |
| `example_spec.json` | пример описания (router-on-a-stick, 2 VLAN) |
| `pt_relayout.py` | пересборка готовой схемы: новые цвета/места VLAN-зон и подсеть |
| `lab_18.pkt` | вариант исходной схемы: зоны перекрашены и переставлены, сеть 192.168.18.x |
| `a.xml` | расшифрованный исходный `a.pkt` (PT 8.0.0.0212) |
| `topology.json` | топология исходного файла в JSON |
| `SCHEMA.md` | разбор исходной схемы |

## Как устроен формат .pkt

Файл — это XML, сжатый zlib и зашифрованный в 4 стадии:

1. обратный XOR: `out[i] = in[n-1-i] ^ (n - i*n)`;
2. Twofish в режиме EAX, ключ `89 89 ... 89` (16 байт), IV `10 10 ... 10`;
3. XOR: `out[i] = in[i] ^ (n - i)`;
4. zlib-поток с 4-байтовым big-endian размером в начале.

Шифрование — ровно в обратном порядке. Реализация в `pt_tool.py` (Twofish портирован
из LibTomCrypt и проверен тестовыми векторами).

## Быстрый старт

```bash
python pt_tool.py decrypt a.pkt -o a.xml     # расшифровать
python pt_tool.py encrypt a.xml -o new.pkt   # зашифровать обратно
python pt_tool.py info a.pkt                 # версия/размер
python pkt_graph.py a.xml -o topology.json   # топология в JSON
python pt_build.py example_spec.json -o example.pkt --template a.xml
```

Проверено: файл, пересобранный `pt_tool.py`, и файл, собранный `pt_build.py`,
открываются в Cisco Packet Tracer 8.0 без ошибок (устройства, порты и связи на месте).

## Сборка схемы нейросетью

Идея: нейросеть не пишет XML руками (там слишком много служебных полей), а генерирует
небольшой JSON. `pt_build.py` клонирует реальные записи устройств из файла-донора
(`a.xml`) и подставляет имена, адреса, конфиги и связи.

### Формат JSON

```json
{
  "devices": [
    {"name": "R1", "template": "Router0", "x": 300, "y": 200,
     "config": ["hostname R1",
                "interface GigabitEthernet0/0.10",
                " encapsulation dot1Q 10",
                " ip address 10.0.0.1 255.255.255.0"]},

    {"name": "SW1", "template": "Switch1", "x": 600, "y": 200,
     "vlans": [{"id": 10, "name": "DESIGN"}, {"id": 20, "name": "ACC"}],
     "config": ["interface GigabitEthernet0/1",
                " switchport mode trunk",
                "interface FastEthernet0/1",
                " switchport access vlan 10"]},

    {"name": "PC-A", "template": "PC0", "x": 870, "y": 140,
     "ip": "10.0.0.10", "mask": "255.255.255.0", "gateway": "10.0.0.1",
     "dns": "8.8.8.8"}
  ],
  "links": [
    {"from": "R1", "from_port": "GigabitEthernet0/0",
     "to": "SW1", "to_port": "GigabitEthernet0/1"}
  ]
}
```

Поля устройства:

- `name` — имя в схеме (уникальное);
- `template` — имя устройства-донора из `a.xml` (или `model`: `"PC-PT"`, `"2911"`, ...);
- `x`, `y` — позиция на логическом холсте (пиксели; если не задать — сетка автоматически);
- `config` — список строк running-config (если не указан, наследуется конфиг донора;
  `[]` — очистить);
- `vlans` — таблица VLAN для коммутатора;
- `ip`, `mask`, `gateway`, `dns` — статический адрес для PC/серверов/принтеров;
- `ssid` — имя Wi-Fi сети.

Поля связи: `from`, `from_port`, `to`, `to_port`, `cable` (`eStraightThrough`,
`eCrossOver`, `eFiber`, `eSerial`, `eWireless`), `link_type` (`eCopper`, `eFiber`,
`eSerial`, `eWireless`). Если не указывать — тип подбирается автоматически.

### Имена портов

| Устройство | Порты |
|---|---|
| 2911 | `GigabitEthernet0/0`, `0/1`, `0/2` |
| 2960-24TT | `FastEthernet0/1..0/24`, `GigabitEthernet0/1`, `0/2` |
| PC / Server / Printer | `FastEthernet0` |
| AccessPoint-PT | `Port 0` |
| Cloud-PT | `Ethernet0..Ethernet6` |

### Что есть в доноре `a.xml`

`Router0` (2911), `Switch0..4` (2960-24TT), `PC0..PC14` (PC-PT), `Server0/1`,
`Printer0..2`, `AccessPoint0`, `Smartphone0..2`, `Cloud0`.

Нужен другой тип (1941, 3560, ноутбук и т.п.) — расшифруйте любой `.pkt`, где он есть,
и передайте его как `--template other.xml`.

### Готовый промпт для нейросети

> Ты собираешь лабораторную работу в Cisco Packet Tracer. Верни только JSON в формате
> `pt_build.py` (devices + links). Используй шаблоны: Router0 (2911), Switch1
> (2960-24TT), PC0 (PC-PT), Server0 (Server-PT), AccessPoint0, Smartphone0, Cloud0.
> Порты: у 2911 — GigabitEthernet0/0..2, у 2960 — FastEthernet0/1..24 и
> GigabitEthernet0/1..2, у PC/Server — FastEthernet0, у AP — Port 0.
> Конфиги давай полными списками строк CLI без символа приглашения. Для VLAN укажи
> `vlans` и настрой trunk/access. Беспроводные клиенты (Smartphone) не соединяются
> линком — они подключаются к AP по SSID. Схема: <опишите задачу>.

## Вариант схемы: `lab_18.pkt`

`pt_relayout.py` берёт расшифрованный XML, переносит каждый цветной блок VLAN вместе
с его устройствами на новое место, перекрашивает блоки и меняет подсеть
`192.168.7.x → 192.168.18.x` во всех конфигах, портах, DHCP-пулах и DNS.

```bash
python pt_relayout.py a.xml -o lab_18.pkt
```

Цвета и координаты зон задаются словарём `NEW_ZONES` в начале `pt_relayout.py`
(ключи: Design, Accounting, Management, Servers, Wireless), позиции ядра — `CORE_POS`.

Итоговая раскладка: ядро (Router0 + Switch0 + Cloud0) сверху по центру, ниже зоны
Design (голубая), Accounting (зелёная), Management (оранжевая), Servers (сиреневая),
Wireless/Guests (бирюзовая). Адресация — см. `SCHEMA.md`.

## Ограничения

- Ключи Packet Tracer меняются между версиями; текущая реализация работает с PT 6–8.x
  (файл `a.pkt` — 8.0.0.0212). При смене ключа будет ошибка `EAX authentication tag mismatch`.
- Ноутбук/смартфон подключается к точке доступа не линком, а по SSID; линк создавать не нужно.
- Новые типы модулей/плат не поддерживаются «из воздуха» — нужен донор с таким устройством.
- Файл-донор должен содержать хотя бы одно устройство каждого типа и хотя бы одну связь.
