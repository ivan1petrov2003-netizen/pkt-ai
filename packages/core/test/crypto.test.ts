// Сравнительные тесты: порт (@pkt-ai/core) ⇄ эталон (original.mjs, дословно из «Дешивратор.html»).
// Криптоядро считается корректным только если оба выхода побайтово совпадают (PLAN.md ADR-7).
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import {
  Twofish,
  EAX,
  stage1,
  stage1inv,
  stage3,
  decryptPkt,
  encryptPkt,
  decryptPktAuto,
  decryptPktLegacy,
  encryptPktLegacy,
  isLegacyPkt,
  PKT_KEY,
  PKT_IV,
} from "../src/index.ts";
import * as orig from "./original.mjs";

// --- детерминированный ГПСЧ, чтобы тесты были воспроизводимы ---
function rng(seed: number): () => number {
  return () => {
    seed |= 0;
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
function randBytes(n: number, r: () => number): Uint8Array {
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i++) b[i] = Math.floor(r() * 256);
  return b;
}
const beq = (a: Uint8Array, b: Uint8Array): boolean =>
  a.length === b.length && Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;

// --- образцы из корпуса (если corpus/samples уже наполнен) ---
const samplesDir = join(import.meta.dirname, "..", "..", "..", "corpus", "samples");
let samples: string[] = [];
try {
  samples = readdirSync(samplesDir)
    .filter((f) => /\.(pkt|pka)$/i.test(f))
    .map((f) => join(samplesDir, f));
} catch {
  /* corpus/samples ещё пуст — тест пропустится */
}

test("stage1/stage1inv взаимно обратны, stage3 самообратна", () => {
  const r = rng(42);
  for (const n of [1, 2, 15, 16, 17, 255, 4096, 65537]) {
    const d = randBytes(n, r);
    assert.ok(beq(stage1inv(stage1(d)), d), `stage1 roundtrip n=${n}`);
    assert.ok(beq(stage3(stage3(d)), d), `stage3 roundtrip n=${n}`);
    // сверка с эталоном
    assert.ok(beq(stage1(d), orig.stage1(d)), `stage1 vs orig n=${n}`);
    assert.ok(beq(stage1inv(d), orig.stage1inv(d)), `stage1inv vs orig n=${n}`);
    assert.ok(beq(stage3(d), orig.stage3(d)), `stage3 vs orig n=${n}`);
  }
});

test("Twofish: поблочное шифрование совпадает с эталоном", () => {
  const r = rng(1337);
  for (let i = 0; i < 12; i++) {
    const key = randBytes(16, r);
    const block = randBytes(16, r);
    const a = new Twofish(key).encrypt(block);
    const b = new orig.Twofish(key).encrypt(block);
    assert.ok(beq(a, b), `блок #${i}`);
  }
});

test("EAX: roundtrip и побайтовое совпадение с эталоном", () => {
  const r = rng(2024);
  for (const n of [0, 1, 15, 16, 17, 100, 1000]) {
    const msg = randBytes(n, r);
    const ours = new EAX(new Twofish(PKT_KEY), PKT_IV);
    const theirs = new orig.EAX(new orig.Twofish(orig.KEY), orig.IV);
    const ct = ours.encrypt(msg);
    assert.ok(beq(ct, theirs.encrypt(msg)), `EAX encrypt n=${n}`);
    assert.ok(beq(ours.decrypt(ct), msg), `EAX decrypt n=${n}`);
  }
});

test("encryptPkt/decryptPkt: roundtrip и совпадение с эталоном", () => {
  const r = rng(777);
  for (const n of [10, 100, 4096, 20000]) {
    const xml = randBytes(n, r);
    const pkt = encryptPkt(xml);
    assert.ok(beq(pkt, orig.encryptPkt(xml)), `encryptPkt vs orig n=${n}`);
    assert.ok(beq(decryptPkt(pkt), xml), `decryptPkt roundtrip n=${n}`);
    assert.ok(beq(decryptPkt(pkt), orig.decryptPkt(pkt)), `decryptPkt vs orig n=${n}`);
  }
  // порча файла должна ломать тег EAX
  const pkt = encryptPkt(new TextEncoder().encode("<?xml version='1.0'?><PACKETTRACER5/>"));
  pkt[5] ^= 1;
  assert.throws(() => decryptPkt(pkt), /EAX/);
});

test("decryptPktAuto: современный формат распознаётся автоматически", () => {
  const r = rng(999);
  const xml = randBytes(500, r);
  const pkt = encryptPkt(xml); // современный контейнер
  assert.ok(beq(decryptPktAuto(pkt), xml));
});

test(
  "реальные файлы корпуса: автодетект, расшифровка, повторное шифрование (оба контейнера)",
  { skip: samples.length === 0 ? "нет файлов в corpus/samples" : false },
  () => {
    for (const f of samples) {
      const raw = new Uint8Array(readFileSync(f));
      const legacy = isLegacyPkt(raw);
      const xml = decryptPktAuto(raw);
      const head = new TextDecoder().decode(xml.subarray(0, 200));
      assert.match(head, /^\s*(\uFEFF)?<\?xml|^\s*<PACKETTRACER/i, `XML-начало: ${f}`);
      // повторное шифрование в родной контейнер и обратно — XML должен быть идентичен
      const pkt = legacy ? encryptPktLegacy(xml) : encryptPkt(xml);
      assert.ok(isLegacyPkt(pkt) === legacy, `повторное шифрование сохраняет семейство: ${f}`);
      assert.ok(beq(decryptPktAuto(pkt), xml), `roundtrip XML идентичен: ${f}`);
      // и через современный контейнер тоже (целевой формат builder'а — современный)
      assert.ok(beq(decryptPkt(encryptPkt(xml)), xml), `roundtrip через современный контейнер: ${f}`);
    }
  }
);
