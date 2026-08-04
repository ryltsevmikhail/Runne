import type { SharedCopy } from "../../types";

export const shared = {
  siteDescription: "用于可靠 AI 智能体工作的本地 runtime。",
  skipToContent: "跳至内容",
  homeAriaLabel: "GOCODE 首页",
  primaryNavAriaLabel: "主导航",
  footerNavAriaLabel: "页脚导航",
  languageLabel: "语言",
  waitlistCta: "加入候补名单",
  nav: {
    product: "产品",
    architecture: "架构",
    security: "安全",
    roadmap: "路线图",
    status: "状态",
  },
  footer: {
    description: "面向 AI 智能体的本地 runtime。",
    privacy: "隐私",
    preview: "letsgocode.dev · 预览版",
  },
  waitlist: {
    eyebrow: "与 GOCODE 一同前行",
    heading: "加入私密预览。",
    body: "此链接仅供参考：表单未启用，且不会收集联系信息。",
    statusLink: "查看开发状态",
  },
  notFound: {
    title: "未找到页面",
    description: "请求的 GOCODE 页面不存在。",
    eyebrow: "404",
    heading: "未找到路由。",
    body: "此页面没有已发布的地址。",
    backHome: "返回首页",
  },
} satisfies SharedCopy;
