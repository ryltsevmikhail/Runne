import type { HomePageCopy } from "../../page-types";

export const home = {
  hero: {
    title: "AI coding agents — under your control",
    description:
      "GOCODE is a desktop control center for AI agents, backed by a local runtime with verifiable boundaries.",
    eyebrow: "Preview",
    heading: "AI coding agents — under your control.",
    lead: "GOCODE is a desktop control center and provider-neutral Rust runtime. It retains authoritative state and restores the conversation after a restart.",
    cta: "Join the waitlist",
    mockup: {
      ariaLabel: "Example of the GOCODE interface",
      topLabel: "GOCODE · local runtime",
      status: "● runtime ready",
      railTitle: "PROJECTS",
      project: "agent-runtime",
      railItems: ["crates", "docs · tests"],
      chatTitle: "Agent conversation",
      state: "LEAD · RESTORED",
      message:
        "Checked the runtime boundaries and prepared a safe change plan.",
      input: "Ask GOCODE to work on the project…",
    },
  },
  why: {
    eyebrow: "Why GOCODE",
    heading: "An agent workflow should not vanish with its window.",
    lead: "GOCODE separates a convenient desktop app from authoritative state. Work continues as part of the runtime, not as a fragile UI session.",
    items: [
      {
        title: "A restart does not end the process",
        body: "The conversation and events are restored from a durable stream.",
      },
      {
        title: "The interface does not own the truth",
        body: "The runtime exposes only confirmed projections.",
      },
      {
        title: "Uncertain state blocks action",
        body: "A change begins only after confirmation.",
      },
    ],
  },
  architecture: {
    eyebrow: "Architecture",
    heading: "One runtime. One source of truth.",
    lead: "The desktop app calls only the public runtime client and contract APIs. Implementation internals stay behind the process boundary.",
    flow: [
      { title: "App", body: "interface" },
      { title: "Tauri host", body: "trust boundary" },
      { title: "runtime-client", body: "public API" },
      { title: "GOCODE runtime", body: "authoritative state" },
      { title: "Event journal", body: "durable record" },
    ],
  },
  preview: {
    eyebrow: "Preview",
    heading: "Proving the foundation before connecting real models.",
    lead: "Current evidence: macOS arm64 · development special build.",
    verified: {
      label: "● verified",
      title: "Works in the current version",
      items: [
        "Authenticated runtime lifecycle",
        "Durable journal and event replay",
        "Conversation restoration and continuation",
        "Vue + Tauri desktop shell",
      ],
    },
    review: {
      label: "● under review",
      title: "Honest version boundaries",
      items: [
        "Deterministic provider instead of real models",
        "No signed installer",
        "Not ready for operation on Windows/Linux",
      ],
    },
  },
  roadmap: {
    eyebrow: "Roadmap",
    heading: "Evidence first. Scale second.",
    lead: "No calendar promises: every stage closes against verifiable release criteria.",
    cards: [
      {
        label: "01 · current stage",
        title: "Runtime foundation complete",
        body: "Lifecycle, event journal, conversation recovery, and desktop shell.",
      },
      {
        label: "02 · next",
        title: "Real agent processes",
        body: "A real provider, TaskRun/Audit streams, and an expanded workspace.",
      },
      {
        label: "03 · before release",
        title: "Readiness qualification",
        body: "Native isolation, signing, platform qualification, and an independent verdict.",
      },
    ],
  },
} satisfies HomePageCopy;
