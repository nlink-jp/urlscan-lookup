# urlscan-lookup

[urlscan.io](https://urlscan.io) API v1 を使って不審 URL を調査する CLI 兼
ローカル MCP サーバー。対象 URL を urlscan のサンドボックス・ブラウザに訪問させて
実挙動（最終 URL・読み込みリソース・観測された IP/ドメイン・脅威判定・スクリーンショット）
を取得する**能動スキャン**と、対象に一切触れず過去の公開スキャン DB を検索する
**受動検索**の 2 モードを持つ。

能動スキャンの可視性は既定 **private**（本人のみ閲覧）。スキャンを全世界＝攻撃者にも
公開・索引される `public` にするには `--visibility public` の明示指定が必要です。

cybersecurity-series の調査ルックアップ群の **URL 層**を担う姉妹品 —
`whois-lookup`（登録情報）・`asn-lookup`（帰属）・`abuse-lookup`（IP 評判）・
`tor-exit-lookup` / `icloud-relay-lookup`（出口 IP 判定）・`doh-lookup`（DNS 解決）。
抽出した IP / ドメインをこれらのツールへ渡します。

> **urlscan.io の無償プラン API キー**が必要です。
> <https://urlscan.io/user/profile/> で発行し、環境変数 `URLSCAN_API_KEY`
> で渡してください。

## インストール

Homebrew（Apple Silicon、notarize 済みプリビルドバイナリ）:

```bash
brew install nlink-jp/tap/urlscan-lookup
```

または [Releases](https://github.com/nlink-jp/urlscan-lookup/releases) から
プラットフォーム別のアーカイブを取得し、バイナリを `PATH` に置いてください。

## 使い方

```bash
export URLSCAN_API_KEY=あなたの無償プランキー

# 能動スキャン（既定 private）。完了まで poll:
urlscan-lookup scan https://suspicious.example/login

# submit のみ、UUID を即返し:
urlscan-lookup scan https://suspicious.example/ --no-wait

# 指定国の PoP からスキャン（地域限定フィッシング対策）:
urlscan-lookup scan https://suspicious.example/ --country jp

# 過去スキャンの受動検索（OpSec 安全）:
urlscan-lookup search 'domain:suspicious.example'
urlscan-lookup search 'page.ip:203.0.113.10'

# 既存スキャンの結果 / スクリーンショット取得:
urlscan-lookup result 01234567-89ab-cdef-0123-456789abcdef --json
urlscan-lookup screenshot 01234567-89ab-cdef-0123-456789abcdef -o shot.png

# 残 API クォータ確認（無償枠は低い）:
urlscan-lookup quota

# ローカル MCP サーバー起動（stdio）:
urlscan-lookup mcp
```

`scan` / `result` は既定で要点を人間可読に要約表示（最終 URL・判定・主 IP/ASN/国・
観測数）。`-j`/`--json` で正規化 JSON 全量。`--fail-on-malicious` を付けると
malicious 判定時に `scan` が exit 1（SOC スクリプト連携用）。

### MCP ツール

`scan_url` / `get_result` / `search` / `get_screenshot` / `get_quota` /
`get_usage`。スキャンは非同期で、`scan_url` は UUID を即返し、`get_result` で
ポーリングします（`processing` は正常状態）。詳細は `get_usage` を参照。

## ビルドとテスト

```bash
make build       # → dist/urlscan-lookup （go build を直接使わない）
make test        # go test -race -cover ./...
make build-all   # 全プラットフォームをクロスコンパイル
```

Go 1.25+。外部依存なし — 標準ライブラリのみ。

## 設定

urlscan.io API キーが必須です。平文 TOML に置くと秘密情報が保存時に露出するため、
**環境変数 `URLSCAN_API_KEY` を推奨**します。任意設定は
`~/.config/urlscan-lookup/config.toml`
（[config.example.toml](config.example.toml) 参照）。優先順位は
フラグ > env > config > 既定。

| 設定 | 環境変数 | 既定 |
|---|---|---|
| API キー | `URLSCAN_API_KEY` | （必須） |
| 既定可視性 | `URLSCAN_LOOKUP_VISIBILITY` | `private` |
| スキャン実行国 | `URLSCAN_LOOKUP_COUNTRY` | （urlscan 既定） |
| キャッシュ TTL（時間） | `URLSCAN_LOOKUP_CACHE_TTL_HOURS` | 24 |
| キャッシュ dir | `URLSCAN_LOOKUP_CACHE_DIR` | `~/.cache/urlscan-lookup` |
| ネットワークタイムアウト（秒） | `URLSCAN_LOOKUP_TIMEOUT_SECONDS` | 30 |

## データソース

[urlscan.io API v1](https://urlscan.io/docs/api/)。キーは `API-Key` ヘッダで送信し、
ログには一切出しません。無償プランのクォータは action 別（scan の public/unlisted/private、
search、retrieve）かつ低枠で、上限をハードコードせず `/user/quotas/` と
応答の `X-Rate-Limit-*` ヘッダから残枠を読み取ります。

## ライセンス

[MIT](LICENSE)
