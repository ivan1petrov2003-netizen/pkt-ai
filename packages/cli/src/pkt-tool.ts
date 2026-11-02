#!/usr/bin/env node
// pkt-tool — CLI криптоядра pkt-ai (Фаза 0). Запуск: node packages/cli/src/pkt-tool.ts <cmd>
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import {
  decryptPkt,
  encryptPkt,
  decryptPktAuto,
  decryptPktLegacy,
  encryptPktLegacy,
  decryptPktRaw,
  isLegacyPkt,
  stage3,
  pktVersion,
} from "../../core/src/index.ts";

const usage = `pkt-tool — расшифровка/шифрование Cisco Packet Tracer (оба контейнера: современный PT 5.3.3+ и легаси)

Команды:
  dec <in.pkt|.pka> [out.xml]   расшифровать в XML (автодетект контейнера)
  enc <in.xml> [out.pkt]        зашифровать XML в современный .pkt
  enc-legacy <in.xml> [out.pkt] зашифровать XML в легаси-контейнер (как учебные saves PT)
  roundtrip <in.pkt> [--save F] dec → enc → dec со сверкой XML; --save — записать новый .pkt
  info <in.pkt>                 контейнер, версия PT, размеры, начало XML
  header <in.pkt>               внутренний 4-байтный заголовок (исследование формата)
`;

function fail(msg: string): never {
  console.error("Ошибка: " + msg);
  process.exit(1);
}
const read = (p: string): Uint8Array => new Uint8Array(readFileSync(p));
const writeOut = (p: string, data: Uint8Array): void => {
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, data);
};
const swapExt = (p: string, ext: string): string => p.replace(/\.[^.]+$/, "") + ext;
const fmt = (n: number): string =>
  n < 1024 ? `${n} Б` : n < 1048576 ? `${(n / 1024).toFixed(1)} КБ` : `${(n / 1048576).toFixed(2)} МБ`;
const family = (raw: Uint8Array): string => (isLegacyPkt(raw) ? "легаси (XOR+zlib, без EAX)" : "современный (Twofish-EAX)");

const [, , cmd, ...args] = process.argv;
if (!cmd || cmd === "help" || cmd === "--help") {
  console.log(usage);
  process.exit(0);
}

switch (cmd) {
  case "dec": {
    const [inp, outp] = args;
    if (!inp) fail("укажите входной файл");
    const raw = read(inp);
    const xml = decryptPktAuto(raw);
    const out = outp || swapExt(inp, ".xml");
    writeOut(out, xml);
    console.log(
      `OK: ${inp} → ${out} (${fmt(raw.length)} → ${fmt(xml.length)}, ${family(raw)}, PT ${pktVersion(xml) ?? "?"})`
    );
    break;
  }
  case "enc":
  case "enc-legacy": {
    const [inp, outp] = args;
    if (!inp) fail("укажите входной файл");
    const xml = read(inp);
    const head = new TextDecoder().decode(xml.subarray(0, 200));
    if (!/^\s*(\uFEFF)?<\?xml|^\s*<PACKETTRACER/i.test(head))
      fail("файл не похож на XML Packet Tracer (ожидается <?xml … или <PACKETTRACER5>)");
    const pkt = cmd === "enc" ? encryptPkt(xml) : encryptPktLegacy(xml);
    const out = outp || swapExt(inp, ".pkt");
    writeOut(out, pkt);
    console.log(`OK: ${inp} → ${out} (${fmt(xml.length)} → ${fmt(pkt.length)}, ${cmd === "enc" ? "современный" : "легаси"})`);
    break;
  }
  case "roundtrip": {
    const inp = args.find((a) => !a.startsWith("--"));
    const save = args.includes("--save") ? args[args.indexOf("--save") + 1] : undefined;
    if (!inp) fail("укажите входной файл");
    const raw = read(inp);
    const legacy = isLegacyPkt(raw);
    const xml = decryptPktAuto(raw);
    const pkt = legacy ? encryptPktLegacy(xml) : encryptPkt(xml);
    const xml2 = decryptPktAuto(pkt);
    const same = Buffer.compare(Buffer.from(xml), Buffer.from(xml2)) === 0;
    if (save) writeOut(save, pkt);
    console.log(
      `${same ? "OK" : "FAIL"}: ${inp} [${family(raw)}] ${fmt(raw.length)} → XML ${fmt(xml.length)} → .pkt ${fmt(pkt.length)} → XML ${fmt(xml2.length)} | XML идентичен: ${same ? "да" : "НЕТ"} | PT ${pktVersion(xml) ?? "?"}${save ? ` | повторно шифрованный файл: ${save}` : ""}`
    );
    if (!same) process.exit(1);
    break;
  }
  case "info": {
    const [inp] = args;
    if (!inp) fail("укажите входной файл");
    const raw = read(inp);
    const xml = decryptPktAuto(raw);
    console.log(
      `Файл: ${inp}\nКонтейнер: ${family(raw)}\nРазмер .pkt: ${fmt(raw.length)} → XML: ${fmt(xml.length)}\nPacket Tracer: ${pktVersion(xml) ?? "версия не найдена"}\n--- начало XML ---\n${new TextDecoder().decode(xml.subarray(0, 400))}`
    );
    break;
  }
  case "header": {
    const [inp] = args;
    if (!inp) fail("укажите входной файл");
    const raw = read(inp);
    if (isLegacyPkt(raw)) {
      const p = stage3(raw);
      const dv = new DataView(p.buffer, p.byteOffset, p.byteLength);
      const be = dv.getUint32(0);
      const xmlLen = decryptPktLegacy(raw).length;
      const hex = Array.from(p.subarray(0, 6))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(" ");
      console.log(
        `[легаси] первые 6 байт после XOR: ${hex}… | BE uint32 = ${be} | длина XML = ${xmlLen} | совпадает: ${be === xmlLen ? "да" : "НЕТ"}`
      );
    } else {
      const p = decryptPktRaw(raw);
      const dv = new DataView(p.buffer, p.byteOffset, p.byteLength);
      const be = dv.getUint32(0);
      const xmlLen = decryptPkt(raw).length;
      const hex = Array.from(p.subarray(0, 4))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(" ");
      console.log(
        `[современный] заголовок (4 байта): ${hex} → BE uint32 = ${be} (0x${be.toString(16)}) | длина XML = ${xmlLen} | совпадает: ${be === xmlLen ? "да" : "НЕТ"}`
      );
    }
    break;
  }
  default:
    fail(`неизвестная команда «${cmd}»\n\n${usage}`);
}
