// Конвейер .pkt ⇄ XML: stage-трансформации + Twofish-EAX + zlib — дословный перенос из «Дешивратор.html».
//
// decrypt: stage1(reverse+XOR) → EAX → stage3(XOR) → пропустить 4 байта заголовка → inflate
// encrypt: deflate → 4 байта длины XML (BE) → stage3 → EAX (добавляет 16 байт тега) → stage1inv
import { deflateSync, inflateSync } from "node:zlib";
import { EAX } from "./eax.ts";
import { Twofish } from "./twofish.ts";

/** Ключ Packet Tracer 6–8.x (16 × 0x89). */
export const PKT_KEY = new Uint8Array(16).fill(0x89);
/** Нонс EAX (16 × 0x10). */
export const PKT_IV = new Uint8Array(16).fill(0x10);

export function stage1(d: Uint8Array): Uint8Array {
  const n = d.length,
    o = new Uint8Array(n);
  for (let i = 0; i < n; i++) o[i] = d[n - 1 - i] ^ (Math.imul(n, 1 - i) & 255);
  return o;
}

export function stage1inv(d: Uint8Array): Uint8Array {
  const n = d.length,
    o = new Uint8Array(n);
  for (let i = 0; i < n; i++) o[n - 1 - i] = d[i] ^ (Math.imul(n, 1 - i) & 255);
  return o;
}

export function stage3(d: Uint8Array): Uint8Array {
  const n = d.length,
    o = new Uint8Array(n);
  for (let i = 0; i < n; i++) o[i] = d[i] ^ ((n - i) & 255);
  return o;
}

/** Расшифровка .pkt/.pka → внутренний XML Packet Tracer. */
export function decryptPkt(data: Uint8Array): Uint8Array {
  let p = stage1(data);
  p = new EAX(new Twofish(PKT_KEY), PKT_IV).decrypt(p);
  p = stage3(p);
  if (p.length < 6) throw new Error("Расшифрованные данные слишком коротки — это не .pkt/.pka?");
  return new Uint8Array(inflateSync(p.subarray(4)));
}

/** Внутренний XML → .pkt (обратный конвейер). */
export function encryptPkt(xml: Uint8Array): Uint8Array {
  const z = deflateSync(xml),
    p = new Uint8Array(z.length + 4);
  new DataView(p.buffer).setUint32(0, xml.length);
  p.set(z, 4);
  return stage1inv(new EAX(new Twofish(PKT_KEY), PKT_IV).encrypt(stage3(p)));
}

/** Stage3-вывод ДО срезки заголовка — для исследования того, что пишет сам PT в 4 байта. */
export function decryptPktRaw(data: Uint8Array): Uint8Array {
  return stage3(new EAX(new Twofish(PKT_KEY), PKT_IV).decrypt(stage1(data)));
}

// --- Легаси-контейнер (PT ≤ 5.3.2; в таком виде лежат учебные saves в установке PT 8.0) ---
// Конвейер: XOR каждого байта с (len-i) → [BE uint32 длины XML][zlib]. Без EAX, без реверса.

/** Детектор легаси-формата: после XOR на позициях 4/5 должна появиться магия zlib (78 9C). */
export function isLegacyPkt(data: Uint8Array): boolean {
  const n = data.length;
  if (n < 6) return false;
  return ((data[4] ^ (n - 4)) & 255) === 0x78 || ((data[5] ^ (n - 5)) & 255) === 0x9c;
}

export function decryptPktLegacy(data: Uint8Array): Uint8Array {
  const p = stage3(data);
  if (p.length < 6) throw new Error("Слишком короткий файл для легаси-формата");
  return new Uint8Array(inflateSync(p.subarray(4)));
}

export function encryptPktLegacy(xml: Uint8Array): Uint8Array {
  const z = deflateSync(xml);
  const p = new Uint8Array(z.length + 4);
  new DataView(p.buffer).setUint32(0, xml.length);
  p.set(z, 4);
  return stage3(p);
}

/** Автовыбор контейнера: сначала пробуем легаси по детектору, затем современный (и наоборот при сбое). */
export function decryptPktAuto(data: Uint8Array): Uint8Array {
  if (isLegacyPkt(data)) {
    try {
      return decryptPktLegacy(data);
    } catch {
      /* не легаси несмотря на детектор — пробуем современный ниже */
    }
  }
  try {
    return decryptPkt(data);
  } catch (e) {
    try {
      return decryptPktLegacy(data);
    } catch {
      throw e;
    }
  }
}

/** Версия Packet Tracer из тега <VERSION>, если найдена. */
export function pktVersion(xmlBytes: Uint8Array): string | null {
  const m = new TextDecoder()
    .decode(xmlBytes.subarray(0, 2000))
    .match(/<VERSION>([^<]+)<\/VERSION>/);
  return m ? (m[1] as string) : null;
}
