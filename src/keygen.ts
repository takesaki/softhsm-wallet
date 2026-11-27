import { randomBytes } from "node:crypto";
import {
  CKA_CLASS, CKA_KEY_TYPE, CKA_TOKEN, CKA_PRIVATE, CKA_LABEL, CKA_ID,
  CKA_EC_PARAMS, CKA_EC_POINT, CKA_VERIFY, CKA_SIGN, CKA_SENSITIVE,
  CKA_EXTRACTABLE, CKA_DERIVE, CKK_EC, CKO_PUBLIC_KEY, CKO_PRIVATE_KEY,
  CKM_EC_KEY_PAIR_GEN,
} from "pkcs11js";
import type { Address, Hex } from "viem";
import { publicKeyToAddress } from "viem/accounts";
import { withSession, type Ctx } from "./hsm";
import { decodeEcPoint } from "./decode";

/** secp256k1 = OID 1.3.132.0.10 の DER */
const SECP256K1_PARAMS = Buffer.from("06052b8104000a", "hex");

export type EthKey = { label: string; publicKey: Hex; address: Address };

export async function generateEthKey(label: string): Promise<EthKey> {
  return withSession(({ p11, session }: Ctx) => {
    const id = randomBytes(8);

    const publicKeyTemplate = [
      { type: CKA_CLASS,      value: CKO_PUBLIC_KEY },
      { type: CKA_KEY_TYPE,   value: CKK_EC },
      { type: CKA_TOKEN,      value: true },      // 永続化
      { type: CKA_PRIVATE,    value: false },
      { type: CKA_VERIFY,     value: true },
      { type: CKA_LABEL,      value: label },
      { type: CKA_ID,         value: id },
      { type: CKA_EC_PARAMS,  value: SECP256K1_PARAMS },
    ];

    const privateKeyTemplate = [
      { type: CKA_CLASS,       value: CKO_PRIVATE_KEY },
      { type: CKA_KEY_TYPE,    value: CKK_EC },
      { type: CKA_TOKEN,       value: true },
      { type: CKA_PRIVATE,     value: true },
      { type: CKA_SENSITIVE,   value: true },     // 平文で読み出し不可
      { type: CKA_EXTRACTABLE, value: false },    // エクスポート禁止
      { type: CKA_DERIVE,      value: false },
      { type: CKA_SIGN,        value: true },
      { type: CKA_LABEL,       value: label },
      { type: CKA_ID,          value: id },
    ];

    const keys = p11.C_GenerateKeyPair(
      session,
      { mechanism: CKM_EC_KEY_PAIR_GEN },
      publicKeyTemplate,
      privateKeyTemplate,
    );

    const [attr] = p11.C_GetAttributeValue(session, keys.publicKey, [
      { type: CKA_EC_POINT },
    ]);

    const publicKey = decodeEcPoint(attr!.value as Buffer); // 0x04 + X + Y
    const address = publicKeyToAddress(publicKey);              // EIP-55 チェックサム付き

    return { label, publicKey, address };
  });
}

/** 既存鍵のアドレスを取得 */
export async function getEthKey(label: string): Promise<EthKey> {
  const { findPublicKey } = await import("./hsm");
  return withSession((ctx) => {
    const pub = findPublicKey(ctx, label);
    const [attr] = ctx.p11.C_GetAttributeValue(ctx.session, pub, [
      { type: CKA_EC_POINT },
    ]);
    const publicKey = decodeEcPoint(attr!.value as Buffer);
    return { label, publicKey, address: publicKeyToAddress(publicKey) };
  });
}

// 実行: bun run src/keygen.ts my-eth-key-1
if (import.meta.main) {
  const label = process.argv[2] ?? "my-eth-key-1";
  const key = await generateEthKey(label);
  console.log("label     :", key.label);
  console.log("publicKey :", key.publicKey);        // 0x04...(130 hex)
  console.log("address   :", key.address);
}