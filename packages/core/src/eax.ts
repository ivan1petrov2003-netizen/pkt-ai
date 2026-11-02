// EAX-режим аутентифицированного шифрования поверх Twofish — дословный перенос из «Дешивратор.html».
import { Twofish } from "./twofish.ts";

const x16 = (a: Uint8Array, b: Uint8Array): Uint8Array => {
  const r = new Uint8Array(16);
  for (let i = 0; i < 16; i++) r[i] = a[i] ^ b[i];
  return r;
};

function dbl(b: Uint8Array): Uint8Array {
  const r = new Uint8Array(16);
  for (let i = 0; i < 16; i++) r[i] = ((b[i] << 1) | (i < 15 ? b[i + 1] >> 7 : 0)) & 255;
  if (b[0] & 128) r[15] ^= 0x87;
  return r;
}

export class EAX {
  private c: Twofish;
  private k1: Uint8Array;
  private k2: Uint8Array;
  private np: Uint8Array;
  private hp: Uint8Array;

  constructor(c: Twofish, nonce: Uint8Array) {
    this.c = c;
    this.k1 = dbl(c.encrypt(new Uint8Array(16)));
    this.k2 = dbl(this.k1);
    this.np = this.omac(0, nonce);
    this.hp = this.omac(1, new Uint8Array(0));
  }

  cmac(msg: Uint8Array): Uint8Array {
    const n = Math.max(1, Math.ceil(msg.length / 16)),
      full = msg.length > 0 && msg.length % 16 == 0;
    let x = new Uint8Array(16);
    for (let i = 0; i < n; i++) {
      let blk = new Uint8Array(16);
      const part = msg.subarray(i * 16, i * 16 + 16);
      blk.set(part);
      if (i == n - 1) {
        if (full) blk = x16(blk, this.k1);
        else {
          blk[part.length] = 0x80;
          blk = x16(blk, this.k2);
        }
      }
      x = this.c.encrypt(x16(x, blk));
    }
    return x;
  }

  omac(d: number, msg: Uint8Array): Uint8Array {
    const m = new Uint8Array(16 + msg.length);
    m[15] = d;
    m.set(msg, 16);
    return this.cmac(m);
  }

  tag(ct: Uint8Array): Uint8Array {
    const cp = this.omac(2, ct),
      t = new Uint8Array(16);
    for (let i = 0; i < 16; i++) t[i] = this.np[i] ^ cp[i] ^ this.hp[i];
    return t;
  }

  ctr(data: Uint8Array): Uint8Array {
    const out = new Uint8Array(data.length),
      c = this.np.slice(),
      ks = new Uint8Array(16);
    for (let i = 0; i < data.length; i += 16) {
      this.c.encrypt(c, 0, ks);
      const l = Math.min(16, data.length - i);
      for (let j = 0; j < l; j++) out[i + j] = data[i + j] ^ ks[j];
      for (let j = 15; j >= 0 && ++c[j] === 256; j--) c[j] = 0;
    }
    return out;
  }

  encrypt(p: Uint8Array): Uint8Array {
    const ct = this.ctr(p),
      r = new Uint8Array(ct.length + 16);
    r.set(ct);
    r.set(this.tag(ct), ct.length);
    return r;
  }

  decrypt(d: Uint8Array): Uint8Array {
    if (d.length < 16) throw new Error("Файл слишком короткий для .pkt");
    const ct = d.subarray(0, d.length - 16),
      t = d.subarray(d.length - 16),
      e = this.tag(ct);
    for (let i = 0; i < 16; i++)
      if (e[i] !== t[i])
        throw new Error("Ошибка проверки подлинности EAX: это не .pkt/.pka или ключ Packet Tracer изменился");
    return this.ctr(ct);
  }
}
