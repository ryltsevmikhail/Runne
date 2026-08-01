import type { PrivacyPageCopy } from "../../page-types";

export const privacy = {
  hero: {
    title: "隐私",
    description: "静态 GOCODE 站点构建的隐私信息。",
    eyebrow: "隐私",
    heading: "此静态站点不收集联系信息。",
    lead: "表单未启用：没有电子邮件提交、注册或其他联系信息收集。",
    panelLabel: "● 不提交数据",
    panelTitle: "信息链接",
    panelBody: "候补名单区块不会创建申请，也不会向第三方发送信息。",
  },
  boundary: {
    eyebrow: "页面边界",
    heading: "请勿输入联系信息：此站点无处发送这些信息。",
    items: [
      { title: "没有账户", body: "静态构建不提供注册或登录。" },
      { title: "没有启用的表单", body: "候补名单仅为信息区块。" },
      {
        title: "未来需要单独的条款",
        body: "未来的桌面产品和服务将需要明确发布的政策。",
      },
    ],
  },
} satisfies PrivacyPageCopy;
