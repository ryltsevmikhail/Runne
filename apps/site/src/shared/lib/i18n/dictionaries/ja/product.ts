import type { ProductPageCopy } from "../../page-types";

export const product = {
  hero: {
    title: "製品",
    description:
      "GOCODE はローカルプロジェクト、会話、runtime の状態を一つのデスクトップアプリにまとめます。",
    eyebrow: "製品",
    heading: "AI エージェント作業のための一つのコントロールセンター。",
    lead: "ローカルプロジェクトを開き、会話を続け、再起動後にも継続します。権威ある状態を保持するのはアプリのウィンドウではなく GOCODE runtime です。",
    boundary:
      "● プレビュー: macOS arm64、決定論的プロバイダー、本番モデル実行なし。",
    cta: "ウェイトリストに参加",
    mockup: {
      ariaLabel: "GOCODE ローカルプロジェクトインターフェース",
      topLabel: "GOCODE · ローカルプロジェクト",
      status: "● runtime 準備完了",
      railTitle: "プロジェクト",
      project: "gocode",
      railItems: ["crates", "docs"],
      chatTitle: "エージェントとの会話",
      state: "LEAD · 復元済み",
      message: "確認済み状態から重複なく会話を継続しました。",
      input: "GOCODE にプロジェクト作業を依頼…",
    },
  },
  workflow: {
    eyebrow: "ワークフロー",
    heading: "ローカルフォルダから継続可能な会話へ。",
    lead: "フォルダはデバイス上に残ります。GOCODE はローカルプロジェクト記録と作業状態を保存します。",
    steps: [
      {
        title: "プロジェクトを開く",
        body: "デバイス上のローカルフォルダを選択します。",
      },
      {
        title: "会話を始める",
        body: "現在のローカル会話でリクエストを送ります。",
      },
      {
        title: "状態をコミットする",
        body: "イベントは runtime ジャーナルに永続化されます。",
      },
      { title: "作業を続ける", body: "再起動または切断後に戻れます。" },
    ],
  },
  workspace: {
    eyebrow: "ワークスペース",
    heading: "プロジェクト、会話、runtime の状態を一つのウィンドウに。",
    lead: "インターフェースは型付け済みでサニタイズされたデータのみを表示します。シークレットと raw runtime エラーが view model に入ることはありません。",
    items: [
      {
        title: "ローカルプロジェクト",
        body: "最近の作業フォルダと明示的なプロジェクト選択。",
      },
      { title: "継続可能な会話", body: "再生、ライブフィード、安全な同期。" },
      { title: "Runtime の状態", body: "起動、準備、再起動、劣化、復旧。" },
    ],
  },
} satisfies ProductPageCopy;
