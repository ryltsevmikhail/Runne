import type { ArchitecturePageCopy } from "../../page-types";

export const architecture = {
  hero: {
    title: "アーキテクチャ",
    description:
      "GOCODE runtime が状態を所有し、インターフェースは検証可能な公開契約を通じてのみ制御します。",
    eyebrow: "アーキテクチャ",
    heading: "runtime が状態を所有し、インターフェースが制御する。",
    lead: "GOCODE は権威ある状態、公開契約、プレゼンテーションを分離します。デスクトップアプリは runtime client を迂回せず、実装内部を import しません。",
    status: "● 単一の信頼できる情報源",
    cards: [
      { title: "Vue / Tauri", body: "制御" },
      { title: "runtime-client", body: "公開契約" },
      { title: "GOCODE runtime", body: "権威ある状態" },
      { title: "SQLite イベントジャーナル", body: "永続記録" },
    ],
  },
  flow: {
    eyebrow: "データフロー",
    heading: "コマンドは一つの検証可能な境界を越える。",
    lead: "HTTP、ストレージ、またはインターフェースの状態を経由する迂回路はありません。",
    items: [
      { title: "コマンド", body: "CLI / デスクトップアプリ" },
      { title: "runtime-client", body: "認証" },
      { title: "RuntimeHandle", body: "受入と実行" },
      { title: "イベントジャーナル", body: "イベントコミット" },
      { title: "投影", body: "サニタイズ済み DTO" },
    ],
  },
  boundary: {
    eyebrow: "責任境界",
    heading: "インターフェースは投影を読み、runtime が決定する。",
    lead: "認証情報とエンドポイントは Tauri host に留まります。Vue はシークレットや生の runtime エラーを含まない型付き DTO を受け取ります。",
    desktop: {
      title: "デスクトップアプリ",
      body: "ユーザー意図 · 表示 · リトライ",
      status: "状態を所有しない",
    },
    runtime: {
      title: "GOCODE runtime",
      body: "イベント · cursor · 投影 · 復旧",
      status: "権威ある状態",
    },
  },
  replay: {
    eyebrow: "再生と継続",
    heading: "継続は確認済みの位置から始まる。",
    lead: "cursor はアトミックにコミットされ、重複は冪等に処理されます。",
    steps: [
      {
        title: "High-water mark",
        body: "利用可能なイベント境界を取得します。",
      },
      { title: "Catch-up stream", body: "境界までのイベントを返します。" },
      {
        title: "アトミックコミット",
        body: "投影と cursor を同時に保存します。",
      },
      { title: "ライブ継続", body: "位置を失わずにストリームが始まります。" },
    ],
  },
} satisfies ArchitecturePageCopy;
