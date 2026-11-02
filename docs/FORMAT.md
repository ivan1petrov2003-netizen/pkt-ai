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

## 3. Структура XML — проверенные поля (PT 8.0.0.0212, донор a.xml)

Источник знаний: разбор `engine/pt_build.py` (клонирует записи и файлы открываются в PT 8.0 — значит, поля существенны и достаточны).

```xml
<PACKETTRACER5>
 <VERSION>8.0.0.0212</VERSION>
 <PIXMAPBANK/> <MOVIEBANK/>
 <NETWORK>
  <DESCRIPTION/>
  <DEVICES>
   <DEVICE>
    <ENGINE>
      <NAME>Router0</NAME>
      <TYPE model="2911"/>              <!-- модель -->
      <SAVE_REF_ID>save-ref-id:0123…</SAVE_REF_ID>  <!-- сквозной ID устройства; на него ссылаются линки -->
      <SERIALNUMBER>PTT…</SERIALNUMBER>
      <COORD_SETTINGS><X_COORD/><Y_COORD/></COORD_SETTINGS>
      <GATEWAY/>                        <!-- для хостовых -->
    </ENGINE>
    <WORKSPACE>
      <LOGICAL><X/><Y/><MEM_ADDR/><DEV_ADDR/></LOGICAL>
      <PHYSICAL>{uuid-цепочка}</PHYSICAL>   <!-- последний uuid = узел в PHYSICALWORKSPACE -->
    </WORKSPACE>
    <PORT>…<TYPE>GigabitEthernet</TYPE><IP/><SUBNET/><PORT_GATEWAY/><PORT_DHCP_ENABLE/><PORT_DNS/></PORT>
    <RUNNINGCONFIG><LINE>hostname R1</LINE>…</RUNNINGCONFIG>
    <STARTUPCONFIG><LINE>…</LINE></STARTUPCONFIG>   <!-- конфиги = CLI-текст в <LINE>, дублируется в <CONFIG> -->
    <FILE_CONTENT class="CVlanDatFileContent">      <!-- vlan.dat свитча -->
      <VLANS><VLAN rspan="0" number="10" name="DESIGN"/>…</VLANS>
      <VLAN_COUNT>…</VLAN_COUNT>
    </FILE_CONTENT>
   </DEVICE>
  </DEVICES>
  <LINKS>
   <LINK>
    <TYPE>eCopper</TYPE>
    <CABLE>
      <TYPE>eStraightThrough</TYPE>
      <FROM>save-ref-id:…</FROM>        <!-- ссылка на SAVE_REF_ID устройства -->
      <TO>save-ref-id:…</TO>
      <PORT>GigabitEthernet0/0</PORT> <PORT>FastEthernet0/1</PORT>  <!-- два элемента, текстом -->
      <FROM_DEVICE_MEM_ADDR/> <TO_DEVICE_MEM_ADDR/> <FROM_PORT_MEM_ADDR/> <TO_PORT_MEM_ADDR/>
    </CABLE>
   </LINK>
  </LINKS>
 </NETWORK>
 <PHYSICALWORKSPACE>
   <NODE><TYPE>4</TYPE>…</NODE>          <!-- стойка (rack), TYPE=6 — узлы устройств -->
 </PHYSICALWORKSPACE>
 <RECTANGLES/> <ELLIPSES/> <NOTES/>      <!-- аннотации канвы; при сборке чистятся -->
</PACKETTRACER5>
```

**Существенно:** при клонировании устройства нужно заменить NAME, SAVE_REF_ID, SERIALNUMBER,
MACADDRESS/BIA (все вхождения), координаты (2 места), MEM_ADDR/DEV_ADDR (уникальные, шаг не критичен),
uuid в WORKSPACE/PHYSICAL (+ соответствующий NODE в PHYSICALWORKSPACE). Линк ссылается на устройство
через SAVE_REF_ID + текстовое имя порта + mem-адреса.

Кабели: `eStraightThrough`, `eCrossOver`, `eFiber`, `eSerial`, `eWireless`; тип линка `eCopper/eFiber/eSerial/eWireless`.
Wi-Fi (Smartphone→AP) — НЕ линк, а ассоциация по SSID (тег `SSID` в устройстве).

## 4. Отличие .pka

Корень `<PACKETTRACER5_ACTIVITY>`, внутри вложен полноценный `<PACKETTRACER5>` (сеть + activity-слои:
инструкции, дерево ответов, грейдинг — Фаза 5).

## 5. Открытые вопросы

- [x] Подтверждено на подлинном PT 8.0: `a.pkt` (8.0.0.0212) расшифровывается тем же ключом 0x89/0x10, roundtrip идентичен.
- [ ] Чему равны 4 байта заголовка в файлах, написанных самим PT (в наших — BE длина XML; PT 4.1 писал 00 00 …; pt_tool.py не проверяет жёстко).
- [ ] Полный список обязательных секций корня (что минимизируется при сборке пустой схемы).
