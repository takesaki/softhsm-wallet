import {
  PKCS11,
  CKF_SERIAL_SESSION,
  CKF_RW_SESSION,
  CKU_USER,
  CKA_CLASS,
  CKA_LABEL,
  CKO_PRIVATE_KEY,
  CKO_PUBLIC_KEY,
} from "pkcs11js";
import type { Handle } from "pkcs11js";

export const PKCS11_LIB =
  process.env.PKCS11_LIB ?? "/usr/lib/softhsm/libsofthsm2.so";
export const PKCS11_PIN = process.env.PKCS11_PIN ?? "1234";
export const TOKEN_LABEL = process.env.PKCS11_TOKEN ?? "eth-token";

export type Ctx = { p11: PKCS11; session: Handle };

/** セッションを開いてログイン → 処理 → 必ずクローズ */
export async function withSession<T>(fn: (ctx: Ctx) => Promise<T> | T): Promise<T> {
  const p11 = new PKCS11();
  p11.load(PKCS11_LIB);
  p11.C_Initialize();
  try {
    const slots = p11.C_GetSlotList(true);
    if (slots.length === 0) throw new Error("トークンが入ったスロットがありません");

    const slot =
      slots.find((s) => p11.C_GetTokenInfo(s).label.trim() === TOKEN_LABEL) ?? slots[0]!;

    const session = p11.C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION);
    try {
      p11.C_Login(session, CKU_USER, PKCS11_PIN);
      return await fn({ p11, session });
    } finally {
      try { p11.C_Logout(session); } catch { /* 未ログイン時は無視 */ }
      p11.C_CloseSession(session);
    }
  } finally {
    p11.C_Finalize();
  }
}

/** ラベルからオブジェクトを1件検索 */
export function findObject(
  { p11, session }: Ctx,
  label: string,
  klass: number,
): Handle {
  p11.C_FindObjectsInit(session, [
    { type: CKA_CLASS, value: klass },
    { type: CKA_LABEL, value: label },
  ]);
  try {
    const obj = p11.C_FindObjects(session);
    if (!obj) throw new Error(`鍵が見つかりません: label=${label}`);
    return obj;
  } finally {
    p11.C_FindObjectsFinal(session);
  }
}

export const findPrivateKey = (ctx: Ctx, label: string) =>
  findObject(ctx, label, CKO_PRIVATE_KEY);
export const findPublicKey = (ctx: Ctx, label: string) =>
  findObject(ctx, label, CKO_PUBLIC_KEY);