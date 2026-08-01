import type { ArchitecturePageCopy } from "../../page-types";

export const architecture = {
  hero: {
    title: "架构",
    description:
      "GOCODE runtime 拥有状态，而界面只能通过可验证的公开 contract 进行控制。",
    eyebrow: "架构",
    heading: "runtime 拥有状态，界面拥有控制。",
    lead: "GOCODE 将权威状态、公开 contract 与呈现层分开。桌面应用不会绕过 runtime client，也不会导入实现内部细节。",
    status: "● 单一事实来源",
    cards: [
      { title: "Vue / Tauri", body: "控制" },
      { title: "runtime-client", body: "公开契约" },
      { title: "GOCODE runtime", body: "权威状态" },
      { title: "SQLite 事件日志", body: "持久记录" },
    ],
  },
  flow: {
    eyebrow: "数据流",
    heading: "一个命令跨越一个可验证边界。",
    lead: "不存在通过 HTTP、存储或界面状态绕过的路径。",
    items: [
      { title: "命令", body: "CLI / 桌面应用" },
      { title: "runtime-client", body: "认证" },
      { title: "RuntimeHandle", body: "准入与执行" },
      { title: "事件日志", body: "提交事件" },
      { title: "投影", body: "已清理的 DTO" },
    ],
  },
  boundary: {
    eyebrow: "职责边界",
    heading: "界面读取投影，runtime 作出决定。",
    lead: "凭据和端点留在 Tauri host 内。Vue 接收不含密钥或原始错误的已类型化 DTO。",
    desktop: {
      title: "桌面应用",
      body: "用户意图 · 呈现 · 重试",
      status: "不拥有状态",
    },
    runtime: {
      title: "GOCODE runtime",
      body: "事件 · cursor · 投影 · 恢复",
      status: "权威状态",
    },
  },
  replay: {
    eyebrow: "回放与继续",
    heading: "从已确认的位置开始继续。",
    lead: "cursor 以原子方式提交，重复项会按幂等方式处理。",
    steps: [
      { title: "高水位标记", body: "记录可用事件边界。" },
      { title: "追赶流", body: "返回边界内的事件。" },
      { title: "原子提交", body: "投影与 cursor 一同存储。" },
      { title: "实时继续", body: "流在不丢失位置的情况下开始。" },
    ],
  },
} satisfies ArchitecturePageCopy;
