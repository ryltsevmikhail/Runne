import type { StatusPageCopy } from "../../page-types";

export const status = {
  hero: {
    title: "開発ステータス",
    description: "検証済み GOCODE 実装の証拠と、現在のプレビューの正確な境界。",
    eyebrow: "開発ステータス",
    heading: "今動くもの、これからのもの。",
    lead: "検証済み実装を、目標機能、プラットフォーム対応、リリース準備と分けて示します。",
    panelLabel: "● ローカルで検証済み",
    panelTitle: "現在のスナップショット",
    panelBody:
      "会話の再生と継続、および保護されたローカル runtime ライフサイクル。",
    platform: "macOS arm64 · 開発用特別ビルド",
  },
  snapshot: {
    eyebrow: "実装スナップショット",
    heading: "基盤は組み立てられ、ローカルで検証済みです。",
    lead: "これは macOS、Windows、Linux の運用サポートの証拠ではありません。",
    cards: [
      { title: "デスクトップシェル", body: "Tauri 2 · Vue 3 · TypeScript" },
      { title: "ストレージ", body: "SQLite · ジャーナル · 投影" },
      { title: "会話", body: "作成 · 生成 · 再生 · 継続" },
      {
        title: "ローカル runtime",
        body: "保護された socket · セッション · 再起動",
      },
    ],
  },
  boundaries: {
    eyebrow: "ステータス境界",
    heading: "実装済みはリリース済みではない。",
    lead: "将来の機能は、それぞれ個別に検証されるまで計画のままです。",
    current: {
      label: "現在",
      title: "実装済み",
      items: [
        "ライフサイクルと認証済み handshake",
        "永続イベントジャーナル",
        "会話の再生と継続",
        "安全なリトライと同期状態",
      ],
    },
    open: {
      label: "未解決",
      title: "未検証",
      items: [
        "実際のプロバイダーとツール",
        "デスクトップアプリの TaskRun / Audit",
        "Windows/Linux と運用可能な macOS ビルド",
        "署名済みインストーラーと公開リリース",
      ],
    },
  },
  platforms: {
    eyebrow: "プラットフォーム境界",
    heading: "対象プラットフォームはサポート対象プラットフォームではない。",
    lead: "特定のリリース候補をパッケージレベルで検証した後にのみ、ステータスは変わります。",
    items: [
      { name: "macOS arm64", status: "● ローカルで検証済み" },
      { name: "Windows", status: "● 適格性確認が必要" },
      { name: "Linux", status: "● 適格性確認が必要" },
    ],
  },
} satisfies StatusPageCopy;
