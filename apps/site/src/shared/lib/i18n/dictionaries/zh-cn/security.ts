import type { SecurityPageCopy } from "../../page-types";

export const security = {
  hero: {
    title: "安全",
    description: "不确定状态无权执行操作：GOCODE 的安全边界可验证。",
    eyebrow: "安全",
    heading: "不确定状态无权执行操作。",
    lead: "GOCODE 通过明确的信任边界、完整性检查，以及在证据不足时安全停机来建立本地边界。",
    panelEyebrow: "本地边界",
    panelBody: "凭据和端点不会传递给界面。",
  },
  trust: {
    eyebrow: "信任图",
    heading: "每个边界都知道该信任什么。",
    lead: "所有者、通道和完整性检查均在状态变更前进行。",
    cards: [
      {
        title: "界面",
        body: "只接收已清理且已类型化的数据。",
        label: "不存储密钥",
      },
      {
        title: "本地 profile",
        body: "在 Unix/macOS 预览中，检查所有者、文件模式和 loopback 地址。",
        label: "Windows：在原生 ACL 前拒绝",
      },
      {
        title: "事件日志",
        body: "验证顺序、完整性和 cursor。",
        label: "持久记录",
      },
    ],
  },
  mechanisms: {
    eyebrow: "可验证机制",
    heading: "保护源自具体的拒绝。",
    lead: "没有任何单一项目可以取代未来的独立安全审查。",
    cards: [
      { title: "回放完整性", body: "HMAC cursor、高水位标记和序列验证。" },
      { title: "原子恢复", body: "在确认交付前，投影和 cursor 已提交。" },
      {
        title: "阻止不安全启动",
        body: "在具备已认证的 Phase 6B 配置前，进程启动将被拒绝。",
      },
      { title: "密钥 broker", body: "检查授权、版本、可用性和撤销。" },
      { title: "幂等性", body: "重复投递不会创建重复状态。" },
      {
        title: "没有权限的提供方",
        body: "当前确定性提供方没有网络、文件或进程访问权限。",
      },
    ],
  },
  boundary: {
    eyebrow: "明确边界",
    heading: "这不是可运营的安全认证。",
    lead: "Phase 6B 原生隔离、Windows/Linux 资格验证、真实提供方和独立审查尚未完成。",
    items: ["原生隔离", "跨平台资格验证", "独立最终结论"],
    roadmapCta: "查看路线图",
  },
} satisfies SecurityPageCopy;
