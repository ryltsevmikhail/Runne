import type { HomePageCopy } from "../../page-types";

export const home = {
  hero: {
    title: "AI コーディングエージェント — あなたの管理下に",
    description:
      "GOCODE は、検証可能な境界を持つローカル runtime に支えられた AI エージェント向けデスクトップコントロールセンターです。",
    eyebrow: "プレビュー",
    heading: "AI コーディングエージェント — あなたの管理下に。",
    lead: "GOCODE はデスクトップコントロールセンターと provider-neutral Rust runtime です。権威ある状態を保持し、再起動後に会話を復元します。",
    cta: "ウェイトリストに参加",
    mockup: {
      ariaLabel: "GOCODE インターフェースの例",
      topLabel: "GOCODE · ローカル runtime",
      status: "● runtime 準備完了",
      railTitle: "プロジェクト",
      project: "agent-runtime",
      railItems: ["crates", "docs · tests"],
      chatTitle: "エージェントとの会話",
      state: "LEAD · 復元済み",
      message: "runtime の境界を確認し、安全な変更計画を準備しました。",
      input: "GOCODE にプロジェクト作業を依頼…",
    },
  },
  why: {
    eyebrow: "GOCODE を選ぶ理由",
    heading:
      "エージェントのワークフローはウィンドウとともに消えるべきではありません。",
    lead: "GOCODE は便利なデスクトップアプリと権威ある状態を分離します。作業は壊れやすい UI セッションではなく runtime の一部として継続します。",
    items: [
      {
        title: "再起動してもプロセスは終わらない",
        body: "会話とイベントを永続ストリームから復元します。",
      },
      {
        title: "インターフェースが真実を所有しない",
        body: "runtime が公開するのは確認済みの投影だけです。",
      },
      {
        title: "不確実な状態は操作を止める",
        body: "変更は確認後にのみ始まります。",
      },
    ],
  },
  architecture: {
    eyebrow: "アーキテクチャ",
    heading: "一つの runtime。一つの信頼できる情報源。",
    lead: "デスクトップアプリは公開 runtime client と contract API だけを呼び出します。実装内部はプロセス境界の向こう側にあります。",
    flow: [
      { title: "アプリ", body: "インターフェース" },
      { title: "Tauri host", body: "信頼境界" },
      { title: "runtime-client", body: "公開 API" },
      { title: "GOCODE runtime", body: "権威ある状態" },
      { title: "イベントジャーナル", body: "永続記録" },
    ],
  },
  preview: {
    eyebrow: "プレビュー",
    heading: "実モデルを接続する前に基盤を証明する。",
    lead: "現在の証拠: macOS arm64 · 開発用特別ビルド。",
    verified: {
      label: "● 検証済み",
      title: "現バージョンで動作するもの",
      items: [
        "認証済み runtime ライフサイクル",
        "永続ジャーナルとイベント再生",
        "会話の復元と継続",
        "Vue + Tauri デスクトップシェル",
      ],
    },
    review: {
      label: "● レビュー中",
      title: "正直なバージョン境界",
      items: [
        "実モデルではなく決定論的プロバイダー",
        "署名済みインストーラーなし",
        "Windows/Linux での運用準備なし",
      ],
    },
  },
  roadmap: {
    eyebrow: "ロードマップ",
    heading: "まず証拠、次に拡張。",
    lead: "カレンダー上の約束はしません。各段階は検証可能なリリース基準を満たして完了します。",
    cards: [
      {
        label: "01 · 現在の段階",
        title: "Runtime 基盤の完了",
        body: "ライフサイクル、イベントジャーナル、会話復旧、デスクトップシェル。",
      },
      {
        label: "02 · 次",
        title: "実際のエージェントプロセス",
        body: "実際のプロバイダー、TaskRun/Audit ストリーム、拡張ワークスペース。",
      },
      {
        label: "03 · リリース前",
        title: "準備状況の適格性確認",
        body: "ネイティブ分離、署名、プラットフォーム適格性確認、独立した判定。",
      },
    ],
  },
} satisfies HomePageCopy;
