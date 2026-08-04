import type { SharedCopy } from "../../types";

export const shared = {
  siteDescription: "A local runtime for reliable work with AI agents.",
  skipToContent: "Skip to content",
  homeAriaLabel: "GOCODE home",
  primaryNavAriaLabel: "Primary navigation",
  footerNavAriaLabel: "Footer navigation",
  languageLabel: "Language",
  waitlistCta: "Join the waitlist",
  nav: {
    product: "Product",
    architecture: "Architecture",
    security: "Security",
    roadmap: "Roadmap",
    status: "Status",
  },
  footer: {
    description: "A local runtime for AI agents.",
    privacy: "Privacy",
    preview: "letsgocode.dev · preview",
  },
  waitlist: {
    eyebrow: "Move forward with GOCODE",
    heading: "Join the private preview.",
    body: "This link is informational: the form is inactive and no contact data is collected.",
    statusLink: "Read development status",
  },
  notFound: {
    title: "Page not found",
    description: "The requested GOCODE page does not exist.",
    eyebrow: "404",
    heading: "Route not found.",
    body: "This page has no published address.",
    backHome: "Back to home",
  },
} satisfies SharedCopy;
