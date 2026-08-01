import type { ProductPageCopy } from "../../page-types";

export const product = {
  hero: {
    title: "Product",
    description:
      "GOCODE brings the local project, conversation, and runtime state together in one desktop app.",
    eyebrow: "Product",
    heading: "One control center for working with AI agents.",
    lead: "Open a local project, carry on a conversation, and continue after a restart. The GOCODE runtime—not the app window—retains authoritative state.",
    boundary:
      "● Preview: macOS arm64, deterministic provider, no production model execution.",
    cta: "Join the waitlist",
    mockup: {
      ariaLabel: "GOCODE local project interface",
      topLabel: "GOCODE · local project",
      status: "● runtime ready",
      railTitle: "PROJECTS",
      project: "gocode",
      railItems: ["crates", "docs"],
      chatTitle: "Agent conversation",
      state: "LEAD · RESTORED",
      message:
        "Conversation continued from confirmed state without duplicates.",
      input: "Ask GOCODE to work on the project…",
    },
  },
  workflow: {
    eyebrow: "Workflow",
    heading: "From a local folder to a continued conversation.",
    lead: "The folder stays on the device. GOCODE stores a local project record and the work state.",
    steps: [
      {
        title: "Open the project",
        body: "Choose a local folder on the device.",
      },
      {
        title: "Start a conversation",
        body: "Send a request in the current local conversation.",
      },
      {
        title: "Commit the state",
        body: "Events are persisted in the runtime journal.",
      },
      {
        title: "Continue working",
        body: "Return after a restart or disconnection.",
      },
    ],
  },
  workspace: {
    eyebrow: "Workspace",
    heading: "Project, conversation, and runtime state—in one window.",
    lead: "The interface displays only typed, sanitized data. Secrets and raw runtime errors never enter the view model.",
    items: [
      {
        title: "Local projects",
        body: "Recent working folders and explicit project selection.",
      },
      {
        title: "Continuable conversation",
        body: "Replay, live feed, and safe synchronization.",
      },
      {
        title: "Runtime state",
        body: "Startup, readiness, restart, degradation, and recovery.",
      },
    ],
  },
} satisfies ProductPageCopy;
