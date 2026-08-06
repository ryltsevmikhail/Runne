import type { PrivacyPageCopy } from "../../page-types";

export const privacy = {
  hero: {
    title: "プライバシー",
    description: "静的 GOCODE サイトビルドのプライバシー情報。",
    eyebrow: "プライバシー",
    heading: "この静的サイトは連絡先データを収集しません。",
    lead: "フォームは無効です。メール送信、登録、その他の連絡先データ収集はありません。",
    panelLabel: "● データ送信なし",
    panelTitle: "情報提供リンク",
    panelBody:
      "ウェイトリストブロックは申請を作成せず、第三者に情報を送りません。",
  },
  boundary: {
    eyebrow: "ページの境界",
    heading:
      "連絡先データを入力しないでください。サイトには送信先がありません。",
    items: [
      {
        title: "アカウントなし",
        body: "静的ビルドは登録もサインインも提供しません。",
      },
      {
        title: "有効なフォームなし",
        body: "ウェイトリストは情報ブロックにすぎません。",
      },
      {
        title: "後で別途規約が必要",
        body: "将来のデスクトップ製品とサービスには、明示的に公開されたポリシーが必要です。",
      },
    ],
  },
} satisfies PrivacyPageCopy;
