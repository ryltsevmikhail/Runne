import type { StatusPageCopy } from "../../page-types";

export const status = {
  hero: {
    title: "开发状态",
    description: "已验证的 GOCODE 实现证据，以及当前预览版的精确边界。",
    eyebrow: "开发状态",
    heading: "现在能做什么，未来还有什么。",
    lead: "我们将已验证的实现与目标能力、平台支持和发布就绪状态分开呈现。",
    panelLabel: "● 本地已验证",
    panelTitle: "当前快照",
    panelBody: "对话回放与继续，以及受保护的本地 runtime 生命周期。",
    platform: "macOS arm64 · 开发专用构建",
  },
  snapshot: {
    eyebrow: "实现快照",
    heading: "基础已组装并在本地验证。",
    lead: "这不是 macOS、Windows 或 Linux 运营支持的证据。",
    cards: [
      { title: "桌面壳层", body: "Tauri 2 · Vue 3 · TypeScript" },
      { title: "存储", body: "SQLite · 日志 · 投影" },
      { title: "对话", body: "创建 · 生成 · 回放 · 继续" },
      { title: "本地 runtime", body: "受保护的 socket · 会话 · 重启" },
    ],
  },
  boundaries: {
    eyebrow: "状态边界",
    heading: "已实现不等于已发布。",
    lead: "每一项未来能力在单独验证前都仍是计划。",
    current: {
      label: "当前",
      title: "已实现",
      items: [
        "生命周期与已认证握手",
        "持久事件日志",
        "对话回放与继续",
        "安全重试与同步状态",
      ],
    },
    open: {
      label: "开放项",
      title: "尚未验证",
      items: [
        "真实提供方和工具",
        "桌面应用中的 TaskRun / Audit",
        "Windows/Linux 及可运营的 macOS 构建",
        "签名安装程序和公开发布",
      ],
    },
  },
  platforms: {
    eyebrow: "平台边界",
    heading: "目标平台不是受支持的平台。",
    lead: "只有对特定发布候选版本完成包级验证后，状态才会改变。",
    items: [
      { name: "macOS arm64", status: "● 本地已验证" },
      { name: "Windows", status: "● 需要资格验证" },
      { name: "Linux", status: "● 需要资格验证" },
    ],
  },
} satisfies StatusPageCopy;
