# FORMAT.md — реконструкция формата файлов Cisco Packet Tracer

> Накапливается эмпирически (PLAN.md, Фаза 1). Каждое утверждение — с указанием, на чём проверено.
> Обозначения: `n` — длина данных в байтах; индексация с 0. Всё проверено на файлах из
> PT 8.0 (Windows, `C:\Program Files\Cisco Packet Tracer 8.0\saves\`).

## 1. Два семейства контейнеров

Магического заголовка нет — файл полностью зашифрован; семейство определяется только криптографически.

| | Легаси | Современный |
|---|---|---|
| Версии XML | PT 4.1 – 5.3.2 | PT 5.3.3 – 9.x |
| Расшифровка | XOR `data[i] ^ ((n-i)&255)` → `[BE uint32 длины XML][zlib]` | stage1 → Twofish-EAX → stage3 → `[BE uint32][zlib]` |
| Аутентификация | нет | EAX-тег 16 байт в конце |
| Кто пишет | учебные `saves/` в установке PT 8.0 (сохранились с 5.2) | сам PT 8.0 при сохранении, .pka из установки |

**Детект легаси:** `(data[4] ^ (n-4)) & 255 == 0x78 || (data[5] ^ (n-5)) & 255 == 0x9c`
(zlib-магия после XOR). Реализовано: `isLegacyPkt()`, автовыбор `decryptPktAuto()`.

## 2. Современный контейнер (целевой для builder'а)

```
decrypt: stage1 → EAX<Twofish>(KEY=16×0x89, IV=16×0x10).decrypt → stage3 → [4 байта BE длины XML][zlib] → XML
encrypt: XML → zlib deflate → +4 байта BE длины → stage3 → EAX.encrypt (+16 байт тега) → stage1inv
stage1:    out[i]        = in[n-1-i] ^ ((n*(1-i)) & 255)   // реверс + XOR, Math.imul знаковый!
stage1inv: out[n-1-i]    = in[i]     ^ ((n*(1-i)) & 255)
stage3:    out[i]        = in[i] ^ ((n-i) & 255)           // самообратна
```
Проверено: `corpus/samples/mqttdemo.pka` (675 КБ → XML 4.1 МБ, PT 7.3.0), sokoban.pka; тесты 6/6.
Эталон сверён с [pka2xml](https://github.com/mircodz/pka2xml) и
[packet-tracer-pkt-format](https://github.com/aacanadaa/packet-tracer-pkt-format).

## 3. Структура XML (черновик, пополняется в Фазе 1)

```xml
<PACKETTRACER5>                        <!-- .pkt; для .pka: <PACKETTRACER5_ACTIVITY>, внутри вложен <PACKETTRACER5> -->
 <VERSION>5.2.0.0068</VERSION>
 <NETWORK>
  <DEVICES>
   <DEVICE>
    <ENGINE>
     <TYPE model="1841" >              <!-- модель устройства -->
```
TODO (Фаза 1): полный срез DEVICE, ссылки линков на порты, где лежат конфиги, сквозные ID.

## 4. Открытые вопросы

- [ ] Подтвердить на файле, сохранённом самим PT 8.0 (ждём от пользователя) — что ключ/конвейер те же.
- [ ] Чему равны 4 байта заголовка в файлах, написанных самим PT (в наших — BE длина XML; PT 4.1 писал 00 00 …).
- [ ] Разница .pkt vs .pka внутри XML (activity-обёртка, грейдинг).
