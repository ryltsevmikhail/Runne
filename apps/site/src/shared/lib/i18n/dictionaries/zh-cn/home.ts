import type { HomePageCopy } from "../../page-types";

export const home = {
  hero: {
    title: "AI 编程智能体 — 由你掌控",
    description:
      "GOCODE 是 AI 智能体的桌面控制中心，由具有可验证边界的本地 runtime 支撑。",
    eyebrow: "预览",
    heading: "AI 编程智能体 — 由你掌控。",
    lead: "GOCODE 是桌面控制中心和与提供商无关的 Rust runtime。它保留权威状态，并在重启后恢复对话。",
    cta: "加入候补名单",
    mockup: {
      ariaLabel: "GOCODE 界面示例",
      topLabel: "GOCODE · 本地 runtime",
      status: "● runtime 已就绪",
      railTitle: "项目",
      project: "agent-runtime",
      railItems: ["crates", "docs · tests"],
      chatTitle: "智能体对话",
      state: "LEAD · 已恢复",
      message: "已检查 runtime 边界，并准备了安全的变更计划。",
      input: "请 GOCODE 为项目开展工作…",
    },
  },
  why: {
    eyebrow: "为什么选择 GOCODE",
    heading: "智能体工作流不应随窗口关闭而消失。",
    lead: "GOCODE 将便捷的桌面应用与权威状态分离。工作由 runtime 持续，而非依赖脆弱的 UI 会话。",
    items: [
      { title: "重启不会终止进程", body: "从持久化流中恢复对话和事件。" },
      { title: "界面不掌握真相", body: "runtime 只公开已确认的投影。" },
      { title: "不确定状态会阻止操作", body: "只有确认后才会开始变更。" },
    ],
  },
  architecture: {
    eyebrow: "架构",
    heading: "一个 runtime，一个事实来源。",
    lead: "桌面应用只调用公开的 runtime client 和 contract API。实现内部细节始终位于进程边界之后。",
    flow: [
      { title: "应用", body: "界面" },
      { title: "Tauri host", body: "信任边界" },
      { title: "runtime-client", body: "公开 API" },
      { title: "GOCODE runtime", body: "权威状态" },
      { title: "事件日志", body: "持久记录" },
    ],
  },
  preview: {
    eyebrow: "预览",
    heading: "在连接真实模型之前先验证基础。",
    lead: "当前证据：macOS arm64 · 开发专用构建。",
    verified: {
      label: "● 已验证",
      title: "当前版本可用功能",
      items: [
        "已认证的 runtime 生命周期",
        "持久日志与事件回放",
        "对话恢复与继续",
        "Vue + Tauri 桌面壳层",
      ],
    },
    review: {
      label: "● 审核中",
      title: "版本的明确边界",
      items: [
        "使用确定性 provider，而非真实模型",
        "没有签名安装程序",
        "尚未具备 Windows/Linux 运行条件",
      ],
    },
  },
  roadmap: {
    eyebrow: "路线图",
    heading: "先有证据，再谈扩展。",
    lead: "不作日程承诺：每个阶段都以可验证的发布标准完成。",
    cards: [
      {
        label: "01 · 当前阶段",
        title: "Runtime 基础已完成",
        body: "生命周期、事件日志、对话恢复和桌面壳层。",
      },
      {
        label: "02 · 下一步",
        title: "真实智能体进程",
        body: "真实提供方、TaskRun/Audit 流，以及扩展的工作区。",
      },
      {
        label: "03 · 发布前",
        title: "就绪资格验证",
        body: "原生隔离、签名、平台资格验证和独立结论。",
      },
    ],
  },
} satisfies HomePageCopy;
