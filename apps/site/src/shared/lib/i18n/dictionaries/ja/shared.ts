import type { SharedCopy } from "../../types";

export const shared = {
  siteDescription: "AI エージェントと信頼して作業するためのローカル runtime。",
  skipToContent: "コンテンツへ移動",
  homeAriaLabel: "GOCODE ホーム",
  primaryNavAriaLabel: "メインナビゲーション",
  footerNavAriaLabel: "フッターナビゲーション",
  languageLabel: "言語",
  waitlistCta: "ウェイトリストに参加",
  nav: {
    product: "製品",
    architecture: "アーキテクチャ",
    security: "セキュリティ",
    roadmap: "ロードマップ",
    status: "ステータス",
  },
  footer: {
    description: "AI エージェントのためのローカル runtime。",
    privacy: "プライバシー",
    preview: "letsgocode.dev · プレビュー",
  },
  waitlist: {
    eyebrow: "GOCODE と前へ進む",
    heading: "非公開プレビューに参加。",
    body: "このリンクは情報提供用です。フォームは無効で、連絡先データは収集しません。",
    statusLink: "開発ステータスを読む",
  },
  notFound: {
    title: "ページが見つかりません",
    description: "指定された GOCODE ページは存在しません。",
    eyebrow: "404",
    heading: "ルートが見つかりません。",
    body: "このページに公開済みのアドレスはありません。",
    backHome: "ホームへ戻る",
  },
} satisfies SharedCopy;
