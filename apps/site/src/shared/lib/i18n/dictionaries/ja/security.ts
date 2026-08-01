import type { SecurityPageCopy } from "../../page-types";

export const security = {
  hero: {
    title: "セキュリティ",
    description:
      "不確実な状態に操作権限は与えません。GOCODE のセキュリティ境界は検証可能です。",
    eyebrow: "セキュリティ",
    heading: "不確実な状態に操作権限は与えない。",
    lead: "GOCODE は明示的な信頼境界、整合性チェック、証拠が不十分な場合の安全な停止によってローカル境界を構築します。",
    panelEyebrow: "ローカル境界",
    panelBody: "認証情報とエンドポイントはインターフェースへ渡されません。",
  },
  trust: {
    eyebrow: "信頼マップ",
    heading: "すべての境界は何を信頼すべきかを知っている。",
    lead: "所有者、チャネル、整合性のチェックは状態変更前に行われます。",
    cards: [
      {
        title: "インターフェース",
        body: "サニタイズ済みの型付きデータのみを受信します。",
        label: "シークレットを保存しない",
      },
      {
        title: "ローカルプロファイル",
        body: "Unix/macOS プレビューでは所有者、ファイルモード、loopback アドレスを確認します。",
        label: "Windows: ネイティブ ACL まで拒否",
      },
      {
        title: "イベントジャーナル",
        body: "順序、整合性、cursor を検証します。",
        label: "永続記録",
      },
    ],
  },
  mechanisms: {
    eyebrow: "検証可能な仕組み",
    heading: "保護は具体的な拒否から作られる。",
    lead: "単一の項目で将来の独立したセキュリティレビューを代替することはできません。",
    cards: [
      {
        title: "再生の整合性",
        body: "HMAC cursor、high-water mark、シーケンス検証。",
      },
      {
        title: "アトミックな復旧",
        body: "配信確認前に投影と cursor をコミットします。",
      },
      {
        title: "安全でない起動をブロック",
        body: "認定済み Phase 6B プロファイルが存在するまで、プロセス起動は拒否されます。",
      },
      {
        title: "シークレット broker",
        body: "認可、バージョン、可用性、失効を確認します。",
      },
      { title: "冪等性", body: "再配信されても重複した状態は作成されません。" },
      {
        title: "権限のないプロバイダー",
        body: "現在の決定論的プロバイダーにはネットワーク、ファイル、プロセスへのアクセス権がありません。",
      },
    ],
  },
  boundary: {
    eyebrow: "正直な境界",
    heading: "これは運用上のセキュリティ認証ではありません。",
    lead: "Phase 6B のネイティブ分離、Windows/Linux の適格性確認、実際のプロバイダー、独立レビューはまだ完了していません。",
    items: [
      "ネイティブ分離",
      "クロスプラットフォーム適格性確認",
      "独立した最終判定",
    ],
    roadmapCta: "ロードマップを見る",
  },
} satisfies SecurityPageCopy;
