#!/usr/bin/env bash
# devcontainer の postCreateCommand から実行される初期化スクリプト
set -euo pipefail

WORKSPACE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$WORKSPACE_DIR"

# --- システムパッケージ ---
# softhsm2: PKCS#11 ソフトウェアトークン
# opensc: pkcs11-tool による動作確認用
# procps: ps / top / pgrep などのプロセス確認用
# build-essential, python3: pkcs11js などのネイティブモジュールのビルド用
sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
  softhsm2 \
  opensc \
  procps \
  build-essential \
  python3

# --- トークン格納ディレクトリ ---
mkdir -p tokens

# --- 依存関係 ---
# トークンの初期化(softhsm2-util --init-token)は PIN を伴うため自動実行しない。
# README の手順に従って手動で実行すること。
if [ -f package.json ]; then
  bun install
fi
