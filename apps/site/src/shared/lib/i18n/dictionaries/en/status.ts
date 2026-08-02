import type { StatusPageCopy } from "../../page-types";

export const status = {
  hero: {
    title: "Development status",
    description:
      "Verified GOCODE implementation evidence and exact boundaries of the current preview.",
    eyebrow: "Development status",
    heading: "What works now. What is still ahead.",
    lead: "We show verified implementation separately from target capabilities, platform support, and release readiness.",
    panelLabel: "● locally verified",
    panelTitle: "Current snapshot",
    panelBody:
      "Conversation replay and continuation, plus a protected local runtime lifecycle.",
    platform: "macOS arm64 · development special build",
  },
  snapshot: {
    eyebrow: "Implementation snapshot",
    heading: "The foundation is assembled and locally verified.",
    lead: "This is not evidence of operational support for macOS, Windows, or Linux.",
    cards: [
      { title: "Desktop shell", body: "Tauri 2 · Vue 3 · TypeScript" },
      { title: "Storage", body: "SQLite · journal · projections" },
      {
        title: "Conversation",
        body: "Create · generate · replay · continue",
      },
      {
        title: "Local runtime",
        body: "Protected socket · session · restart",
      },
    ],
  },
  boundaries: {
    eyebrow: "Status boundaries",
    heading: "Implemented does not mean released.",
    lead: "Every future capability remains a plan until it is separately verified.",
    current: {
      label: "Current",
      title: "Implemented",
      items: [
        "Lifecycle and authenticated handshake",
        "Durable event journal",
        "Conversation replay and continuation",
        "Safe retry and synchronization states",
      ],
    },
    open: {
      label: "Open",
      title: "Not yet verified",
      items: [
        "Real provider and tools",
        "TaskRun / Audit in the desktop app",
        "Windows/Linux and an operational macOS build",
        "Signed installers and public release",
      ],
    },
  },
  platforms: {
    eyebrow: "Platform boundary",
    heading: "A target platform is not a supported platform.",
    lead: "Status changes only after package-level verification of a specific release candidate.",
    items: [
      { name: "macOS arm64", status: "● locally verified" },
      { name: "Windows", status: "● requires qualification" },
      { name: "Linux", status: "● requires qualification" },
    ],
  },
} satisfies StatusPageCopy;
