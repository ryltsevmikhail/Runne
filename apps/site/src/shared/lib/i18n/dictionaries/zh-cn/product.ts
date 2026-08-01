import type { ProductPageCopy } from "../../page-types";

export const product = {
  hero: {
    title: "产品",
    description: "GOCODE 在一个桌面应用中汇集本地项目、对话与 runtime 状态。",
    eyebrow: "产品",
    heading: "一个 AI 智能体工作控制中心。",
    lead: "打开本地项目，延续对话，并在重启后继续。保留权威状态的是 GOCODE runtime，而不是应用窗口。",
    boundary: "● 预览：macOS arm64、确定性提供方，不执行生产模型。",
    cta: "加入候补名单",
    mockup: {
      ariaLabel: "GOCODE 本地项目界面",
      topLabel: "GOCODE · 本地项目",
      status: "● runtime 已就绪",
      railTitle: "项目",
      project: "gocode",
      railItems: ["crates", "docs"],
      chatTitle: "智能体对话",
      state: "LEAD · 已恢复",
      message: "对话从已确认状态继续，不会产生重复项。",
      input: "请 GOCODE 为项目开展工作…",
    },
  },
  workflow: {
    eyebrow: "工作流",
    heading: "从本地文件夹到可继续的对话。",
    lead: "文件夹始终保留在设备上。GOCODE 存储本地项目记录和工作状态。",
    steps: [
      { title: "打开项目", body: "选择设备上的本地文件夹。" },
      { title: "开始对话", body: "在当前本地对话中发送请求。" },
      { title: "提交状态", body: "事件会持久化到 runtime 日志。" },
      { title: "继续工作", body: "在重启或断连后返回。" },
    ],
  },
  workspace: {
    eyebrow: "工作区",
    heading: "项目、对话与 runtime 状态 — 同在一个窗口。",
    lead: "界面仅显示已类型化且经清理的数据。密钥和原始 runtime 错误绝不会进入视图模型。",
    items: [
      { title: "本地项目", body: "最近使用的工作文件夹和显式项目选择。" },
      { title: "可继续的对话", body: "回放、实时流和安全同步。" },
      { title: "Runtime 状态", body: "启动、就绪、重启、降级和恢复。" },
    ],
  },
} satisfies ProductPageCopy;
