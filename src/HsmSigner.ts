import { CKA_CLASS, CKA_EC_POINT, CKA_LABEL, CKO_PUBLIC_KEY } from "pkcs11js";
import {
  createPublicClient, createWalletClient, formatEther, getAddress, hashMessage,
  hashTypedData, http, isAddress, keccak256, parseEther, recoverAddress,
  serializeSignature, serializeTransaction,
  type Address, type Hex,
} from "viem";
import { toAccount, publicKeyToAddress } from "viem/accounts";
import { signDigest } from "./sign";
import { getEthKey } from "./keygen";
import { withSession } from "./hsm";
import { decodeEcPoint } from "./decode";

/**
 * HSM 内の鍵で署名する viem のカスタムアカウントを作る。
 * 秘密鍵は HSM から出ず、署名はすべて signDigest（PKCS#11）経由で行う。
 */
export async function createHsmAccount(label: string) {
  const { address } = await getEthKey(label);

  return toAccount({
    address,

    async signMessage({ message }) {
      return serializeSignature(await signDigest(label, hashMessage(message)));
    },

    async signTypedData(typedData) {
      const hash = hashTypedData(typedData as any);
      return serializeSignature(await signDigest(label, hash));
    },

    async signTransaction(transaction, options) {
      const serializer: (tx: any, sig?: any) => any = (options?.serializer ?? serializeTransaction) as any;
      const hash = keccak256(await serializer(transaction));
      const signature = await signDigest(label, hash);

      // 署名者がこのアカウントのアドレスと一致するか確認
      const signer = await recoverAddress({ hash, signature });
      if (signer.toLowerCase() !== address.toLowerCase()) {
        throw new Error(`署名者 ${signer} がアカウント ${address} と一致しません`);
      }
      return (await serializer(transaction, signature)) as Hex;
    },
  });
}

/** 送金元アドレス。環境変数 SENDER_ADDRESS が必須で、未設定や不正な値はエラーにする */
export function requireSenderAddress(): Address {
  const value = process.env.SENDER_ADDRESS;
  if (!value) throw new Error("環境変数 SENDER_ADDRESS を設定してください");
  if (!isAddress(value, { strict: true })) {
    throw new Error(`不正な SENDER_ADDRESS です: ${value}`);
  }
  return getAddress(value);
}

/** 送金先のネットワーク（既定は Sepolia。環境変数 RPC_URL で変更可） */
const DEFAULT_RPC_URL = "https://ethereum-sepolia-rpc.publicnode.com";

/**
 * アドレスに対応する HSM 鍵のラベルを探す。
 * 秘密鍵は PKCS#11 でログインしないと見えないため、withSession（ログイン付き）で
 * 公開鍵を走査し、そのアドレスを持つ公開鍵のラベルを返す。
 */
export async function findLabelByAddress(address: string): Promise<string> {
  const target = address.toLowerCase();
  return withSession(({ p11, session }) => {
    p11.C_FindObjectsInit(session, [{ type: CKA_CLASS, value: CKO_PUBLIC_KEY }]);
    try {
      for (let obj = p11.C_FindObjects(session); obj; obj = p11.C_FindObjects(session)) {
        const [label, point] = p11.C_GetAttributeValue(session, obj, [
          { type: CKA_LABEL },
          { type: CKA_EC_POINT },
        ]);
        const addr = publicKeyToAddress(decodeEcPoint(point!.value as Buffer)).toLowerCase();
        if (addr === target) return label!.value.toString("utf8");
      }
    } finally {
      p11.C_FindObjectsFinal(session);
    }
    throw new Error(`HSM 内に ${address} の鍵が見つかりません`);
  });
}

/**
 * SENDER_ADDRESS が持つ ETH を to に送金する。
 * amountEth を省略すると、ガス代を差し引いた全額を送る。
 */
export async function sendEth(to: string, amountEth?: string, rpcUrl = DEFAULT_RPC_URL) {
  const sender = requireSenderAddress();
  // チェックサム検証（大小文字混在の場合は不正なチェックサムを拒否）
  if (!isAddress(to, { strict: true })) throw new Error(`不正なアドレスです: ${to}`);
  const dest = getAddress(to);

  const transport = http(rpcUrl);
  const publicClient = createPublicClient({ transport });
  const label = await findLabelByAddress(sender);
  const account = await createHsmAccount(label);
  const walletClient = createWalletClient({ account, transport });

  const from = account.address;
  if (from.toLowerCase() !== sender.toLowerCase()) {
    throw new Error(`鍵のアドレス ${from} が送金元 ${sender} と一致しません`);
  }

  const [balance, fee, chainId] = await Promise.all([
    publicClient.getBalance({ address: from }),
    publicClient.estimateFeesPerGas(),
    publicClient.getChainId(),
  ]);
  if (fee.maxFeePerGas == null || fee.maxPriorityFeePerGas == null) {
    throw new Error("EIP-1559 の手数料情報を取得できませんでした");
  }

  // 送金先がコントラクトや EIP-7702 委任 EOA だと受け取り時にコードが走り 21000 では足りないので見積もる
  const estimated = await publicClient.estimateGas({
    account: from,
    to: dest,
    value: amountEth ? parseEther(amountEth) : 1n,
  });
  const gasLimit = (estimated * 120n) / 100n; // 20% の余裕
  const maxGasCost = gasLimit * fee.maxFeePerGas;
  const value = amountEth ? parseEther(amountEth) : balance - maxGasCost;

  if (value <= 0n) throw new Error(`残高不足: balance=${formatEther(balance)} ETH`);
  if (value + maxGasCost > balance) {
    throw new Error(
      `残高不足: balance=${formatEther(balance)} ETH, 必要=${formatEther(value + maxGasCost)} ETH`,
    );
  }

  console.log("chainId :", chainId);
  console.log("from    :", from);
  console.log("to      :", dest);
  console.log("balance :", formatEther(balance), "ETH");
  console.log("value   :", formatEther(value), "ETH");
  console.log("gas     :", gasLimit.toString(), `(estimated ${estimated})`);

  const hash = await walletClient.sendTransaction({
    chain: undefined,
    type: "eip1559",
    to: dest,
    value,
    gas: gasLimit,
    maxFeePerGas: fee.maxFeePerGas,
    maxPriorityFeePerGas: fee.maxPriorityFeePerGas,
  });
  console.log("txHash  :", hash);

  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  console.log("status  :", receipt.status === "success" ? "success" : "failed", `(block ${receipt.blockNumber})`);
  return hash;
}

// 実行: SENDER_ADDRESS=0x... bun run src/HsmSigner.ts <送金先アドレス> [金額(ETH)]
//   RPC_URL=https://... SENDER_ADDRESS=0x... bun run src/HsmSigner.ts 0x... 0.01
if (import.meta.main) {
  const [to, amount] = process.argv.slice(2);
  if (!to || !process.env.SENDER_ADDRESS) {
    console.error("usage: SENDER_ADDRESS=0x... bun run src/HsmSigner.ts <送金先アドレス> [金額(ETH)]");
    process.exit(1);
  }
  await sendEth(to, amount, process.env.RPC_URL ?? DEFAULT_RPC_URL);
}