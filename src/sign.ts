import { CKM_ECDSA, CKA_EC_POINT } from "pkcs11js";
import {
  hashMessage, hashTypedData, keccak256, numberToHex, recoverMessageAddress,
  recoverPublicKey, recoverTransactionAddress, serializeSignature,
  serializeTransaction, toBytes,
  type Hex, type SignableMessage, type TransactionSerializable, type TypedDataDefinition,
} from "viem";
import { publicKeyToAddress } from "viem/accounts";
import { withSession, findPrivateKey, findPublicKey, type Ctx } from "./hsm";
import { decodeEcPoint, decodeSignature } from "./decode";

const SECP256K1_N = BigInt(
  "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
);

/** viem の署名オブジェクト (r, s, yParity) */
export type HsmSignature = { r: Hex; s: Hex; yParity: 0 | 1 };

/** 32byte ダイジェストに署名して viem の署名 (r,s,yParity) を返す */
export async function signDigest(
  label: string,
  digest: Uint8Array | Hex,
): Promise<HsmSignature> {
  const digestBytes = Buffer.from(typeof digest === "string" ? toBytes(digest) : digest);
  if (digestBytes.length !== 32) throw new Error("digest は 32 バイト必須");
  const hash = `0x${digestBytes.toString("hex")}` as Hex;

  return withSession(async (ctx: Ctx) => {
    const { p11, session } = ctx;

    // --- HSM 内で署名（秘密鍵は外に出ない） ---
    const priv = findPrivateKey(ctx, label);
    p11.C_SignInit(session, { mechanism: CKM_ECDSA }, priv);
    const raw = p11.C_Sign(session, digestBytes, Buffer.alloc(64));

    let { r, s } = decodeSignature(raw);

    // --- EIP-2: low-s へ正規化 ---
    if (s > SECP256K1_N / 2n) s = SECP256K1_N - s;

    // --- 自分の公開鍵を取得（v の決定に使う） ---
    const pub = findPublicKey(ctx, label);
    const [attr] = p11.C_GetAttributeValue(session, pub, [{ type: CKA_EC_POINT }]);
    const expected = decodeEcPoint(attr!.value as Buffer).toLowerCase();

    // --- recovery id (yParity) を総当たりで特定 ---
    for (const yParity of [0, 1] as const) {
      const sig: HsmSignature = {
        r: numberToHex(r, { size: 32 }),
        s: numberToHex(s, { size: 32 }),
        yParity,
      };
      let recovered: string;
      try {
        recovered = (await recoverPublicKey({ hash, signature: sig })).toLowerCase();
      } catch {
        continue; // この yParity では復元できない
      }
      if (recovered === expected) return sig;
    }
    throw new Error("recovery id を決定できませんでした");
  });
}

/** EIP-191 personal_sign 形式 */
export async function signMessage(label: string, message: SignableMessage) {
  const sig = await signDigest(label, hashMessage(message));
  return serializeSignature(sig); // 0x + r(32) + s(32) + v(1)
}

/** EIP-712 */
export async function signTypedData(label: string, typedData: TypedDataDefinition) {
  const sig = await signDigest(label, hashTypedData(typedData));
  return serializeSignature(sig);
}

/** トランザクション署名（Type-2 / EIP-1559 など） */
export async function signTransaction(label: string, txRequest: TransactionSerializable) {
  const sig = await signDigest(label, keccak256(serializeTransaction(txRequest)));
  const raw = serializeTransaction(txRequest, sig);
  const from = await recoverTransactionAddress({ serializedTransaction: raw as any });
  return { raw, hash: keccak256(raw), from };
}

// --- デモ ---
if (import.meta.main) {
  const label = process.argv[2] ?? "my-eth-key-1";

  // 鍵のアドレス
  const address = await withSession((ctx) => {
    const pub = findPublicKey(ctx, label);
    const [a] = ctx.p11.C_GetAttributeValue(ctx.session, pub, [{ type: CKA_EC_POINT }]);
    return publicKeyToAddress(decodeEcPoint(a!.value as Buffer));
  });
  console.log("address :", address);

  // 1) メッセージ署名 + 検証
  const msg = "hello from SoftHSM";
  const msgSig = await signMessage(label, msg);
  const recovered = await recoverMessageAddress({ message: msg, signature: msgSig });
  console.log("signature :", msgSig);
  console.log("recovered :", recovered);
  console.log("match     :", recovered === address);

  // 2) トランザクション署名（Sepolia 例・ブロードキャストはしない）
  const { raw, hash, from } = await signTransaction(label, {
    type: "eip1559",
    chainId: 11155111,
    nonce: 0,
    to: "0x000000000000000000000000000000000000dEaD",
    value: 10n ** 16n,               // 0.01 ETH
    gas: 21000n,
    maxFeePerGas: 30n * 10n ** 9n,
    maxPriorityFeePerGas: 1n * 10n ** 9n,
  });
  console.log("txFrom :", from, from === address);
  console.log("txHash :", hash);
  console.log("rawTx  :", raw);
}
