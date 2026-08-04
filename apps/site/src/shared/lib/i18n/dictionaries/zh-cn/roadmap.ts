import type { RoadmapPageCopy } from "../../page-types";

export const roadmap = {
  hero: {
    title: "路线图",
    description: "GOCODE 路线图将证据置于发布之前，不作未经验证的可用性承诺。",
    eyebrow: "路线图",
    heading: "先有证据，再谈发布。",
    lead: "日期不会让能力就绪。前进需要实现、平台证据和独立审查。",
    panelLabel: "● 预览",
    panelTitle: "当前边界",
    panelBody: "本地 macOS arm64 路径已在开发专用构建中验证。",
    warning: "⚠ 这不代表可运营就绪，也不是公开发布。",
  },
  stages: {
    eyebrow: "三个阶段",
    heading: "每个阶段都以验证完成。",
    lead: "我们不会发布尚不存在的时间表。",
    cards: [
      {
        label: "01 · 本地已验证",
        title: "Runtime 基础已完成",
        body: "持久对话、回放与继续，以及重启后的恢复。\nmacOS arm64 · 开发专用构建",
      },
      {
        label: "02 · 下一步",
        title: "真实智能体进程",
        body: "真实提供方、TaskRun/Audit 流和扩展的工作区。\n标准：契约 + 恢复",
      },
      {
        label: "03 · 公开发布前",
        title: "运营就绪",
        body: "原生隔离、签名、Windows/Linux 资格验证和独立结论。",
      },
    ],
  },
  exclusions: {
    eyebrow: "我们尚未承诺的内容",
    heading: "计划不是可用能力的清单。",
    items: [
      {
        title: "不使用真实模型进行生产执行",
        body: "当前提供方是确定性的本地提供方。",
      },
      { title: "没有公开下载", body: "签名、安装程序和资格验证尚未完成。" },
      {
        title: "没有经验证的跨平台支持",
        body: "Windows/Linux 需要单独的证据。",
      },
    ],
  },
  legend: {
    eyebrow: "如何理解状态",
    heading: "颜色表示证据的类型。",
    cards: [
      {
        label: "● 本地已验证",
        title: "",
        body: "指定环境已有实现和精确证据。",
      },
      {
        label: "● 下一步",
        title: "",
        body: "该切片已定义，但尚不是可用能力。",
      },
      {
        label: "● 公开发布前",
        title: "",
        body: "一项强制性的资格验证和发布条件。",
      },
    ],
  },
} satisfies RoadmapPageCopy;
