import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex, type Hex } from "viem";

/**
 * CKA_EC_POINT は DER OCTET STRING でラップされているので剥がして
 * 非圧縮公開鍵 "0x04||X||Y" (65byte) を返す
 */
export function decodeEcPoint(raw: Buffer): Hex {
  let buf = raw;

  // DER OCTET STRING (tag 0x04) を剥がす
  if (buf[0] === 0x04 && buf.length !== 65 && buf.length !== 33) {
    let off = 1;
    let len = buf[off++]!;
    if (len & 0x80) {
      const n = len & 0x7f;
      len = 0;
      for (let i = 0; i < n; i++) len = (len << 8) | buf[off++]!;
    }
    buf = buf.subarray(off, off + len);
  }

  // 圧縮形式(0x02/0x03)で返す HSM もあるので非圧縮に伸張
  const point = secp256k1.Point.fromBytes(new Uint8Array(buf));
  return bytesToHex(point.toBytes(false));
}

/**
 * C_Sign の戻り値を {r, s} に。
 * PKCS#11 標準は r||s の 64byte。DER を返す HSM 向けに保険も入れておく。
 */
export function decodeSignature(sig: Buffer): { r: bigint; s: bigint } {
  if (sig.length === 64) {
    return {
      r: BigInt("0x" + sig.subarray(0, 32).toString("hex")),
      s: BigInt("0x" + sig.subarray(32, 64).toString("hex")),
    };
  }
  if (sig[0] === 0x30) {
    // SEQUENCE { INTEGER r, INTEGER s }
    let off = 2;
    if (sig[1]! & 0x80) off += sig[1]! & 0x7f;
    const readInt = () => {
      if (sig[off++] !== 0x02) throw new Error("bad DER");
      const len = sig[off++]!;
      const v = BigInt("0x" + sig.subarray(off, off + len).toString("hex"));
      off += len;
      return v;
    };
    return { r: readInt(), s: readInt() };
  }
  throw new Error(`未知の署名フォーマット: ${sig.length} bytes`);
}