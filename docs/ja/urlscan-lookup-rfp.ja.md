# RFP: urlscan-lookup

> Generated: 2026-07-17
> Status: Draft

## 1. Problem Statement

SOC / CSIRT・個人セキュリティ実務者が不審 URL（フィッシング・マルウェア配布・C2 等）を
調査する際、その URL に自分のブラウザで直接アクセスするのは危険であり、また「実際に何が
起きるか」（最終リダイレクト先・読み込まれるリソース・生成される Cookie・観測される IP /
ドメイン・検出された脅威タグ・スクリーンショット）を安全に観測する手段が要る。**urlscan-lookup は
urlscan.io の無償プラン API を介して、対象 URL を urlscan のサンドボックス・ブラウザに訪問させて
その実挙動を取得し（能動スキャン）、あわせて過去の公開スキャン DB を検索する（受動検索）ための
CLI 兼ローカル MCP サーバー**である。対象ユーザーは、不審 URL の実挙動を安全な OpSec で確認したい
CTI / IR 実務者と、それを MCP 経由で呼び出す調査エージェント。`whois-lookup`（登録情報）・
`asn-lookup`（帰属）・`abuse-lookup`（IP 評判）・`tor-exit-lookup` / `icloud-relay-lookup`（出口 IP 判定）・
`doh-lookup`（DNS 解決）に並ぶ cybersecurity-series の姉妹品であり、**URL 層**を担当して、そこから
抽出した IP / ドメインを既存の IP / ドメイン層ツール群へ渡す「調査チェーンの入口」に位置づく。

## 2. Functional Specification

### Commands / API Surface

**CLI サブコマンド**（姉妹ツール規約に準拠）:

- `urlscan-lookup scan <url>` — 主操作（能動）。対象 URL の新規スキャンを投入し、完了まで poll して結果を表示
  - `--visibility private|unlisted|public` — 可視性（**既定 `private`**。`public` は明示指定を要求）
  - `--no-wait` — submit のみ行い UUID を即返し（poll しない）
  - `--country <cc>` — スキャン実行国の PoP を指定（例 `jp`, `de`。地域限定フィッシングの回避用）
  - `--tags <t1,t2>` — スキャンに付与するタグ
  - `--referer <url>` / `--user-agent <ua>` — 送出 Referer / UA の上書き（フィッシングの遷移条件再現用）
  - `--json` — 構造化出力（生に近い正規化 JSON）
  - `--fail-on-malicious` — スキャンが malicious 判定なら exit 1（SOC スクリプト連携用、opt-in）
- `urlscan-lookup search <query>` — 過去スキャンを検索（受動・OpSec 安全）
  - `--size <n>` — 取得件数（既定 100）
  - `--search-after <sort>` — ページング（前ページ末尾の sort 値）
  - `--json` — JSONL 出力（1 ヒット 1 行）
- `urlscan-lookup result <uuid>` — 既存スキャン結果を取得（`--json`）
- `urlscan-lookup screenshot <uuid>` — スクリーンショット PNG を保存（`--output <path>`）
- `urlscan-lookup quota` — 残クォータ（action 別）を表示（`GET /user/quotas/`）
- `urlscan-lookup cache <status|clear>` — キャッシュの状態表示 / クリア
- `urlscan-lookup mcp` — ローカル MCP サーバーを起動（stdio）
- `urlscan-lookup --version`

**MCP ツール**（非同期ジョブ型。長時間ブロックしない）:

- `scan_url` — `{ url, visibility?, country?, tags?, referer?, user_agent? }` → **UUID を即返し**（決してブロックしない）。
  `visibility` 既定 `private`
- `get_result` — `{ uuid }` → 未完成なら `{ status:"processing", uuid, elapsed }`、完成なら正規化結果 + メタ。
  urlscan の 404（未完成）/ 410（削除済）を握って**通常応答**として返す（"処理中" は正常状態でありエラーではない）
- `search` — `{ query, size? }` → ヒット一覧（大量時は workspace ファイル経由）
- `get_screenshot` — `{ uuid, workspace_root }` → PNG を workspace へ保存しファイルパスを返す（画像バイトは返さない）
- `get_quota` — action 別の残クォータ
- `get_usage` — ツールリファレンスとエラー回復表

### Input / Output

- **入力検証ゲート（ネットワーク I/O 前に必須）**:
  - `scan` の URL: スキーム `http` / `https` のみ許可、制御文字・CRLF 混入を拒否、ホスト部の存在を確認。
    通過しなければ CLI exit 2 / MCP `{code:"invalid_input"}`
  - `result` / `screenshot` の UUID: urlscan の UUID 形式（RFC 4122）を検証してから API へ投げる
- **可視性の安全既定**: `scan` は既定 `private`（本人のみ閲覧）。`public`（全世界に公開・索引）は
  `--visibility public` の明示指定でのみ有効。調査対象 URL（攻撃者の資産・被害者を示すパラメータを含みうる）を
  不用意に公開しない OpSec 上の中核仕様
- **完了待ちのモード差**:
  - **CLI**: `scan` は内部で poll（**submit 後 10 秒待ち → 2 秒間隔**、`--poll-timeout` 上限、公式推奨に準拠）して
    結果まで返す。`--no-wait` で UUID 即返し
  - **MCP**: `scan_url` は UUID 即返しでブロックしない。`get_result` を呼び出してポーリング（MCP リクエストの
    timeout を回避する org 標準の非同期ジョブ型）
- **要約出力（既定・人間可読）**: 結果 JSON は情報量が大きいため、既定では要点に要約する:
  投入 URL → 最終 URL、overall verdict（malicious 有無 / score / brands / tags）、主 IP / ASN / 国 / server、
  ユニーク IP 数・ドメイン数・リクエスト数・malicious リクエスト数、スクリーンショット URL・レポート URL、
  主要な連絡先ドメイン / IP の抜粋
- **全量出力**: `--json`（正規化した構造化 JSON）で全フィールドを提供
- **正規化**: 抽出フィールド（`page.url`/`page.ip`/`page.asn`/`page.country`/`verdicts.overall`/`lists.ips`/
  `lists.domains`/`stats` 等）を一箇所（`internal/urlscan`）で正規化し、urlscan のスキーマ揺れを吸収
- **Exit code 契約**: `0` 成功 / `2` エラー。`--fail-on-malicious` 指定時のみ、malicious 判定で `1`

### Configuration

`~/.config/urlscan-lookup/config.toml`（sectioned TOML、任意）。`URLSCAN_LOOKUP_*` 環境変数が上書き。
API キーは秘密情報のため**環境変数 `URLSCAN_API_KEY` を正とし、TOML への平文記載は非推奨**
（ローカル利便のため受理はするが `config.example.toml` は必ずコメントアウト + プレースホルダ）。
precedence は **フラグ > env > config > 既定**。

```toml
[auth]
# api_key = ""                       # 非推奨。環境変数 URLSCAN_API_KEY を使うこと

[scan]
# default_visibility = "private"     # private | unlisted | public
# wait = true                        # CLI: submit 後に結果まで poll する
# poll_initial_delay_seconds = 10    # 公式推奨: 最初のポーリング前に 10 秒待つ
# poll_interval_seconds = 2          # 公式推奨: 2 秒間隔
# poll_timeout_seconds = 120         # poll の打ち切り上限
# country = ""                       # スキャン実行国 PoP (例: "jp")

[search]
# size = 100

[cache]
# ttl_seconds = 3600                 # result / search の TTL（scan はキャッシュしない）
# dir = "~/.cache/urlscan-lookup"

[network]
# timeout_seconds = 30
```

### External Dependencies

- **Go 標準ライブラリのみ**（`net/http` + `encoding/json`）。リトライ / バックオフも**自前実装**（nlk 不採用）。
- 外部サービスは **urlscan.io の公開 API のみ**。`API-Key` HTTP ヘッダによる認証（無償プランのキー 1 本）。
  他の依存・OAuth・IAM は一切なし。

## 3. Design Decisions

- **言語 = Go、外部依存最小。** シリーズ標準（whois / asn / abuse / tor / icloud-relay / doh と同一）。
  urlscan の JSON API は標準ライブラリだけで扱え、単一署名バイナリで配布できる。
- **nlk 不採用・バックオフは自前。** nlk の価値は LLM 入出力の防御（guard / jsonfix / validate）にあり、
  本ツールは LLM を積まない。backoff だけのために submodule 依存を増やすのは筋が悪いため、
  **標準ライブラリのみで指数バックオフ + ジッタ**を実装し、`Retry-After` / `X-Rate-Limit-Reset` を尊重する。
- **可視性の安全既定（`private`）が OpSec の中核。** 能動スキャンは対象 URL を第三者の基盤（urlscan）に
  記録する行為であり、`public` 既定だと調査が全世界に索引されて攻撃者に筒抜けになる。**既定 `private`・
  `public` は明示指定必須**という非対称を設計の中心に置く。
- **MCP は非同期ジョブ型。** urlscan は submit（UUID 即返し）と result（完成まで 404）が本質的に非同期。
  `scan_url`（submit）と `get_result`（poll）を別ツールに分離し、MCP リクエストの timeout を回避する
  （image-forge / voice-studio / video-studio の job 型と同じ思想。UUID をそのままジョブハンドルに使う）。
- **engine は CLI / MCP で共有**し挙動を分岐させない。HTTP クライアントは注入インターフェイスで
  テスト時にモックする（設計でのテスト容易性）。urlscan 応答は record したフィクスチャで pure な
  パーサ / フォーマッタをテストする。
- **クォータは動的取得、数値ハードコード禁止。** 無償プランは action 別（public / unlisted / private / search /
  result）に低い日次クォータを持つ。実際の枠は `GET /user/quotas/` と応答の `X-Rate-Limit-*` ヘッダ
  （Scope / Action / Limit / Remaining / Reset）から読み取り、`quota` サブコマンド / `get_quota` で可視化する。
- **キャッシュ**: `result` / `search` は TTL キャッシュ（クォータ節約、abuse-lookup と同思想）。
  `scan`（新規生成）はキャッシュ対象外。
- **姉妹ツールとの関係**: URL 層を担当し、スキャン結果から抽出した IP / ドメインの enrichment は
  `whois-lookup` / `asn-lookup` / `abuse-lookup` / `tor-exit-lookup` / `icloud-relay-lookup` へ委譲（UNIX 哲学）。
- **スコープ外（意図的）**:
  - urlscan **有償プラン専用機能**（類似スキャン検索 / 大量クォータ / ライブ検索 / Pro 相当機能）
  - 自前のブラウザレンダリング / スクレイピング（能動訪問は urlscan に委譲、本ツールは対象へ直接触れない）
  - 取得結果の **LLM 判定 / 要約**（素の取得に徹する。AI 分析が要るなら結果 JSON を上位ツール / エージェントへ渡す）
  - 継続監視 / スケジュール実行 / スキャン結果の永続 DB 化（単発調査に徹する）

## 4. Development Plan

### Phase 1: Core（受動系・CLI）— 独立レビュー可

- `internal/validate`: URL 検証ゲート（scheme / 制御文字 / CRLF / ホスト存在）、UUID 検証
- `internal/config`: sectioned TOML + `URLSCAN_LOOKUP_*` env + `URLSCAN_API_KEY` + フラグ（precedence 適用）
- `internal/urlscan`: HTTP クライアント（`API-Key` ヘッダ、**自前指数バックオフ + ジッタ**、
  `X-Rate-Limit-*` パース、429 / 5xx リトライ）、`search` / `result` / `quotas` エンドポイント、
  応答型の正規化
- `internal/cache`: `result` / `search` の TTL キャッシュ、atomic write
- `internal/engine`: validate → cache → fetch → normalize（要約フィールド抽出）
- `internal/app`: `search` / `result` / `quota` / `cache` サブコマンド、`--json`、要約 / 全量出力、exit code 契約
- モック HTTP + record フィクスチャによるテーブル駆動テスト一式

> **受動系（触らない機能）を先に固める**方針。能動 `scan` は基盤が固まってから Phase 2 で追加。

### Phase 2: Features（能動系 + MCP）— 独立レビュー可

- `internal/engine`: `scan`（submit → poll、可視性 / country / tags / referer / UA）、`screenshot` 取得
- `internal/app`: `scan` / `screenshot` サブコマンド、`--visibility`（既定 private）/ `--no-wait` /
  `--fail-on-malicious`、poll 制御（10 秒待ち → 2 秒間隔）
- `internal/mcp`: zero-dep stdio JSON-RPC 2.0、ツール `scan_url` / `get_result` / `search` /
  `get_screenshot` / `get_quota` / `get_usage`、構造化エラー `{code, message, details}`、
  大量結果 / 画像は workspace ファイル経由
- **実 API に対する E2E**（無償クォータ消費に配慮しレート制御）。
  **着手時に無償キーで private スキャンの実際の可否・日次枠を実測**し、想定と差異があれば
  フォールバック（既定を unlisted に落とす等）を設計に反映する

### Phase 3: Release

- README.md / README.ja.md / CHANGELOG.md / AGENTS.md / config.example.toml / docs/{en,ja}
- Makefile + scripts（codesign / notarize / brew）、build-all（linux amd64/arm64・darwin arm64・
  windows amd64）、darwin 署名 + notarize、homebrew-tap formula
- submodule 統合（cybersecurity-series umbrella）→ org profile + web-site catalog の 2 面同期 → check-org.sh

## 5. Required API Scopes / Permissions

OAuth スコープ / IAM ロールは**不要**。urlscan.io の無償プランで発行する **API キー 1 本**を
`API-Key` HTTP ヘッダ（厳密にこのヘッダ名。`x-api-key` は不可）で送るのみ。キーは環境変数
`URLSCAN_API_KEY` で供給する。

## 6. Series Placement

Series: **cybersecurity-series**
Reason: 不審 URL の実挙動を安全な OpSec で収集する CTI / IR 支援ツールであり、
`whois-lookup` / `asn-lookup` / `abuse-lookup` / `tor-exit-lookup` / `icloud-relay-lookup` / `doh-lookup` と同じ
「CLI 兼 MCP・単一署名バイナリの調査ルックアップ」ファミリーに属する。URL 層を担い、他の
IP / ドメイン層ツールへの入口になる。

## 7. External Platform Constraints

- **無償プランの低い action 別クォータ**（2026-07-17 実キーで実測・確定）: day/hour/minute の順で
  **public 5000/500/60・unlisted 1000/100/60・private 50/50/5・search 1000/1000/120・retrieve 10000/5000/120・
  livescan 0/0/0（無償では不可）**。加えて `search` の可視範囲は `queryVisibility: ["public"]`（公開スキャンのみ検索可）、
  保持 7 日、最大検索結果 1000 件。数値は変動しうるため**ハードコードせず** `GET /user/quotas/` と
  応答の `X-Rate-Limit-*`（Scope / Action / Limit / Remaining / Reset）から動的取得する。超過は HTTP 429。
  成功（200）のみがクォータを消費し、fixed-window（毎分 / 毎時 / UTC 深夜リセット）。
  **注意**: `/user/quotas/` の `limits` オブジェクトは action 別クォータと**プラン メタデータ（`features`/`queryableFields`/
  `maxSearchResults`/ネストした `files` オブジェクト等）が混在**するため、day 窓を持つオブジェクトのみを action として抽出する。
- **完了待ちの公式作法**: submit 後**最低 10 秒待ってから 2 秒間隔**で poll。`result` は未完成で HTTP 404、
  削除済みで HTTP 410。積極リトライ禁止・礼儀正しいペーシング。
- **認証ヘッダ名の厳密性**: `API-Key`（`x-api-key` 等は不可）。
- **可視性の非対称リスク**: `public` スキャンは urlscan フロントページ / 公開検索 / info ページに露出。
  `unlisted` は公開ページ / 検索には出ないが vetted security researcher には可視。`private` は本人のみ。
  → 既定 `private`・`public` 明示必須で担保。
- **取得アセットのエンドポイント**: スクリーンショット = `https://urlscan.io/screenshots/$uuid.png`、
  DOM = `https://urlscan.io/dom/$uuid/`。いずれも未生成で HTTP 404。
- ~~**要検証（Phase 2 着手時）**: 無償プランでの private スキャン可否・実日次枠。~~
  → **確定（2026-07-17 実測）**: 無償プランで **private スキャンは利用可能**、**日次 50 / 時 50 / 分 5**。
  既定 `private` の設計はそのまま成立し、フォールバック（既定を unlisted に落とす）は**不要**。

---

## Discussion Log

- **発端**: urlscan.io 無償プラン API で不審 URL を調査する CLI 兼 MCP サーバー案。cybersecurity-series の
  既存姉妹品（whois / abuse / tor-exit lookup）と同じ「CLI 兼 MCP・外部依存最小・署名 + notarize リリース」
  パターンを踏襲。
- **能動 / 受動の 2 系統を確認・合意**: urlscan は (A) 能動スキャン（対象 URL を実際に訪問させ新規生成）と
  (B) 受動検索（既存公開 DB を参照）に分かれる。**両方を実装**すると合意。
- **可視性の安全既定を合意**: 能動スキャンは既定 `private`、`public` は明示指定必須。中間の `unlisted` も
  選択可（`--visibility {private|unlisted|public}`、既定 private）。
- **モード別の完了待ちを設計**: CLI は内部 poll（`--no-wait` 可）、MCP は `scan_url`（UUID 即返し）+
  `get_result`（poll）の非同期ジョブ型で MCP timeout を回避。UUID をそのままジョブハンドルに使う。
- **機能仕様の決定**: 出力は要約テキスト既定 + `--json` 全量。認証は `URLSCAN_API_KEY` env + TOML、キー必須で統一。
  `result` / `search` は TTL キャッシュ、`scan` は非キャッシュ。
- **設計判断**: Go / 標準ライブラリ中心・外部依存最小。**nlk 不採用**（LLM を積まないため backoff は自前実装）。
  単一バイナリに CLI + MCP 同居（`mcp` サブコマンド）。MCP 骨格は data-toolbox-mcp を移植。**LLM 判定は不採用**
  （MCP でエージェントから使う前提のため、判断は上位に委ねる）。
- **開発順序**: 受動系（search / result）を Phase 1、能動 scan + MCP を Phase 2。Phase 1 / 2 は独立レビュー可。
- **外部制約を urlscan 公式ドキュメントで検証**: 可視性はプラン制限の記述なし（無償でも private 可の見込み、
  private ≈ 50/day 等の低枠）。クォータは action 別・`GET /user/quotas/` と `X-Rate-Limit-*` で動的取得、
  数値ハードコード禁止。poll は 10 秒待ち → 2 秒間隔、404 未完成 / 410 削除。認証ヘッダ名は厳密に `API-Key`。
  無償での private 実枠は Phase 2 着手時に実測して確定する。
- **追加機能**: `quota` サブコマンド / `get_quota` ツールで残クォータを可視化（低枠を使い切らないため）。
  `scan` に `--country` / `--referer` / `--user-agent`（地域限定 / 遷移条件付きフィッシングの再現）、
  `--fail-on-malicious`（SOC スクリプト連携の opt-in exit code）を追加。
- **Scaffold + 実 API E2E（2026-07-17）**: whois-lookup を canonical、abuse-lookup を API キー/レート制御の
  参照にして骨格を実装（`make build`/`go vet`/`gofmt`/`go test -race` 全通過、4プラットフォームビルド可）。
  実キーで E2E 実施: `quota`（メタ混在の `limits` パースを修正）→ `search`（公開スキャンのみ・正規化 OK）→
  `scan https://example.com`（private・submit→25s poll→完了、verdict/IP/ASN/screenshot 正規化 OK）→
  `result`（キャッシュヒット）→ `screenshot`（実 PNG 1600×1200）→ MCP `get_quota`/`get_result`（非同期経路 OK）。
  唯一の実データ差分は quota の `limits` 混在シェイプで、day 窓を持つオブジェクトのみ抽出する回帰テスト付きで修正済み。
