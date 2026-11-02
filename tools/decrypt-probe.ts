// Отладочный пробер формата .pkt (Фаза 0): расследование, почему файлы PT 8.0 не проходят EAX.
// Перебирает варианты ключей/порядка стадий/пропуска байтов. Запуск:
//   node tools/decrypt-probe.ts corpus/samples/CBAC_3Routers.pkt [--brute]
import { readFileSync } from "node:fs";
import { inflateSync } from "node:zlib";
import { EAX } from "../packages/core/src/eax.ts";
import { Twofish } from "../packages/core/src/twofish.ts";
import { stage1, stage3 } from "../packages/core/src/pkt.ts";

const file = process.argv[2];
if (!file) {
  console.error("укажите файл");
  process.exit(1);
}
const brute = process.argv.includes("--brute");
const data = new Uint8Array(readFileSync(file));

function attempt(keyByte: number, ivByte: number, pre: "stage1" | "none", skip: number): boolean {
  const key = new Uint8Array(16).fill(keyByte);
  const iv = new Uint8Array(16).fill(ivByte);
  const d = pre === "stage1" ? stage1(data) : data;
  let p: Uint8Array;
  try {
    p = new EAX(new Twofish(key), iv).decrypt(d); // бросает исключение, если тег не сошёлся
  } catch {
    return false;
  }
  const q = stage3(p);
  const body = q.subarray(skip);
  if (body[0] !== 0x78) return false; // магия zlib
  try {
    const xml = inflateSync(body);
    console.log(
      `!!! НАЙДЕНО: key=0x${keyByte.toString(16)} iv=0x${ivByte.toString(16)} pre=${pre} skip=${skip} → XML ${xml.length} байт`
    );
    return true;
  } catch {
    return false;
  }
}

// Фаза A: известные константы + локальные вариации конвейера
const knownKeys = [0x89, 0xba, 0x12, 0xfe];
const knownIvs = [0x10, 0xbe];
let found = false;
for (const k of knownKeys)
  for (const iv of knownIvs)
    for (const pre of ["stage1", "none"] as const)
      for (const skip of [0, 4]) if (attempt(k, iv, pre, skip)) found = true;

// Фаза B: полный перебор однородных ключей (все 256) × IV {0x10, =key}
if (!found && brute) {
  console.log("Фаза A не дала результата — полный перебор (это займёт до пары минут)…");
  for (let k = 0; k < 256 && !found; k++) {
    for (const iv of [0x10, k]) {
      for (const pre of ["stage1", "none"] as const) {
        for (const skip of [0, 4]) {
          if (attempt(k, iv, pre, skip)) {
            found = true;
            break;
          }
        }
        if (found) break;
      }
      if (found) break;
    }
    if (k % 32 === 0) console.error(`  … key 0x${k.toString(16).padStart(2, "0")}`);
  }
}
if (!found) console.log("Совпадений не найдено.");
