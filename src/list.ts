import {
  PKCS11,
  CKF_SERIAL_SESSION,
  CKA_CLASS, CKA_KEY_TYPE, CKA_LABEL, CKA_ID, CKA_EC_POINT,
  CKO_PUBLIC_KEY, CKO_PRIVATE_KEY, CKK_EC,
} from "pkcs11js";
import type { Handle, PKCS11 as PKCS11Lib } from "pkcs11js";
import { publicKeyToAddress } from "viem/accounts";
import { PKCS11_LIB } from "./hsm";
import { decodeEcPoint } from "./decode";

export type KeyInfo = {
  slot: string;       // スロットID（10進）
  tokenLabel: string;
  label: string;
  class: string;      // public / private
  keyType: string;    // EC など
  id: string;         // CKA_ID（hex）
  publicKey: string;  // 0x04 + X + Y（非圧縮）
  address: string;    // EIP-55 アドレス
};

const CLASS_NAME: Record<number, string> = {
  [CKO_PUBLIC_KEY]: "public",
  [CKO_PRIVATE_KEY]: "private",
};

const KEYTYPE_NAME: Record<number, string> = {
  [CKK_EC]: "EC",
};

/** pkcs11js は CK_ULONG 等を Buffer で返すので数値に変換 */
const toUlong = (b: Buffer): number =>
  Number(b.length === 8 ? b.readBigUInt64LE(0) : b.readUInt32LE(0));

/** 全スロット（トークンが入っているもの）の鍵を列挙する */
export async function listAllKeys(): Promise<{ keys: KeyInfo[]; errors: string[] }> {
  const p11 = new PKCS11();
  p11.load(PKCS11_LIB);
  p11.C_Initialize();
  const keys: KeyInfo[] = [];
  const errors: string[] = [];
  try {
    for (const slot of p11.C_GetSlotList(true)) {
      const slotNo = toUlong(slot).toString();
      const tokenLabel = p11.C_GetTokenInfo(slot).label.trim();
      let session: Handle | undefined;
      try {
        session = p11.C_OpenSession(slot, CKF_SERIAL_SESSION);
        keys.push(...readSlotKeys(p11, session, slotNo, tokenLabel));
      } catch (e) {
        errors.push(`slot ${slotNo} (${tokenLabel}): ${(e as Error).message}`);
      } finally {
        if (session) {
          try { p11.C_CloseSession(session); } catch { /* 無視 */ }
        }
      }
    }
  } finally {
    p11.C_Finalize();
  }
  return { keys, errors };
}

/** 1スロット分の鍵を読み出す（公開鍵・秘密鍵の両方、公開鍵/アドレスは CKA_ID で対応付け） */
function readSlotKeys(
  p11: PKCS11Lib,
  session: Handle,
  slotNo: string,
  tokenLabel: string,
): KeyInfo[] {
  // 公開鍵: CKA_EC_POINT から公開鍵・アドレスを計算
  const pubInfoById = new Map<string, { publicKey: string; address: string }>();
  const rows: Omit<KeyInfo, "publicKey" | "address">[] = [];
  const pubRows: KeyInfo[] = [];

  for (const klass of [CKO_PUBLIC_KEY, CKO_PRIVATE_KEY]) {
    for (const h of findAll(p11, session, klass)) {
      const [cls, label, keyType, id] = p11.C_GetAttributeValue(session, h, [
        { type: CKA_CLASS },
        { type: CKA_LABEL },
        { type: CKA_KEY_TYPE },
        { type: CKA_ID },
      ]);
      const row = {
        slot: slotNo,
        tokenLabel,
        label: label!.value.toString("utf8"),
        class: CLASS_NAME[toUlong(cls!.value)] ?? "unknown",
        keyType: KEYTYPE_NAME[toUlong(keyType!.value)] ?? "unknown",
        id: id!.value.toString("hex"),
      };
      if (row.class === "public") {
        const [point] = p11.C_GetAttributeValue(session, h, [{ type: CKA_EC_POINT }]);
        const publicKey = decodeEcPoint(point!.value);
        const info = { publicKey, address: publicKeyToAddress(publicKey) };
        pubInfoById.set(row.id, info);
        pubRows.push({ ...row, ...info });
      } else {
        rows.push(row);
      }
    }
  }

  // 秘密鍵は同じ CKA_ID の公開鍵から公開鍵・アドレスを引く
  const privRows: KeyInfo[] = rows.map((row) => {
    const info = pubInfoById.get(row.id);
    return { ...row, publicKey: info?.publicKey ?? "-", address: info?.address ?? "-" };
  });

  return [...pubRows, ...privRows];
}

/** 指定クラスのオブジェクトを全件取得 */
function findAll(p11: PKCS11Lib, session: Handle, klass: number): Handle[] {
  p11.C_FindObjectsInit(session, [{ type: CKA_CLASS, value: klass }]);
  const out: Handle[] = [];
  try {
    for (let obj = p11.C_FindObjects(session); obj; obj = p11.C_FindObjects(session)) {
      out.push(obj);
    }
  } finally {
    p11.C_FindObjectsFinal(session);
  }
  return out;
}

// 実行: bun run src/list.ts
if (import.meta.main) {
  const { keys, errors } = await listAllKeys();
  if (keys.length === 0) {
    console.log("鍵が見つかりませんでした");
  } else {
    console.table(keys);
  }
  for (const e of errors) console.warn("警告:", e);
}
