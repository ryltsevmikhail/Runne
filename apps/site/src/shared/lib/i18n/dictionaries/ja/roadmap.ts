import type { RoadmapPageCopy } from "../../page-types";

export const roadmap = {
  hero: {
    title: "ロードマップ",
    description:
      "GOCODE のロードマップはリリースより証拠を優先し、未検証の可用性を約束しません。",
    eyebrow: "ロードマップ",
    heading: "まず証拠、次にリリース。",
    lead: "日付が機能を準備完了にするわけではありません。前進には実装、プラットフォームの証拠、独立レビューが必要です。",
    panelLabel: "● プレビュー",
    panelTitle: "現在の境界",
    panelBody: "ローカルの macOS arm64 パスは開発用特別ビルドで検証済みです。",
    warning: "⚠ これは運用準備完了でも公開リリースでもありません。",
  },
  stages: {
    eyebrow: "3 段階",
    heading: "すべての段階は検証によって完了する。",
    lead: "まだ存在しないタイムラインを公開することはありません。",
    cards: [
      {
        label: "01 · ローカルで検証済み",
        title: "Runtime 基盤の完了",
        body: "永続的な会話、再生と継続、再起動後の復旧。\nmacOS arm64 · 開発用特別ビルド",
      },
      {
        label: "02 · 次",
        title: "実際のエージェントプロセス",
        body: "実際のプロバイダー、TaskRun/Audit ストリーム、拡張ワークスペース。\n基準: contract + 復旧",
      },
      {
        label: "03 · 公開リリース前",
        title: "運用準備",
        body: "ネイティブ分離、署名、Windows/Linux 適格性確認、独立した判定。",
      },
    ],
  },
  exclusions: {
    eyebrow: "まだ約束しないこと",
    heading: "計画は利用可能な機能の一覧ではありません。",
    items: [
      {
        title: "実モデルでの本番実行なし",
        body: "現在のプロバイダーは決定論的かつローカルです。",
      },
      {
        title: "公開ダウンロードなし",
        body: "署名、インストーラー、適格性確認は未完了です。",
      },
      {
        title: "検証済みクロスプラットフォーム対応なし",
        body: "Windows/Linux には個別の証拠が必要です。",
      },
    ],
  },
  legend: {
    eyebrow: "ステータスの読み方",
    heading: "色は証拠の種類を示す。",
    cards: [
      {
        label: "● ローカルで検証済み",
        title: "",
        body: "指定環境に対する実装と正確な証拠があります。",
      },
      {
        label: "● 次",
        title: "",
        body: "このスライスは定義済みですが、まだ利用可能な機能ではありません。",
      },
      {
        label: "● 公開リリース前",
        title: "",
        body: "必須の適格性確認およびリリース条件です。",
      },
    ],
  },
} satisfies RoadmapPageCopy;
