export const site = {
  name: "Runne",
  url: "https://runne.run",
} as const;

export const navLinks = [
  { label: "Architecture", href: "#architecture" },
  { label: "Capabilities", href: "#capabilities" },
  { label: "Philosophy", href: "#philosophy" },
  { label: "Status", href: "#status" },
] as const;

export const hero = {
  headline: "The agent runtime that survives its own window.",
  subtitle:
    "Runne is an open-source Rust runtime for AI coding agents. Execution state is durable, completion requires verification evidence, and every dangerous action needs a capability grant. The chat window is a view. The runtime is the truth.",
  trustStrip:
    "Rust · 40 crates · ~3,400 tests · 25 documented subsystems · one local process · no telemetry",
  mascotLabel: "TaskRun · active",
} as const;

export const bento = {
  daemon: "runned daemon (Rust)",
  daemonCaption: "RUNTIME AUTHORITY · CONFIRMED PROJECTIONS ONLY",
  live: "runned · live",
  clientsLabel: "CLIENTS",
  clients: [
    { name: "Desktop", state: "connected" },
    { name: "CLI", state: "connected" },
    { name: "API", state: "connected" },
  ],
  journalLabel: "Event Journal",
  journalCaption: "ORDERED · DURABLE · REPLAYABLE",
  entries: [
    {
      id: "TR-0184",
      status: "Completed · evidence attached",
      tone: "ok" as const,
      title: "Acceptance verification",
      detail: "cursor 184 · acknowledged",
    },
    {
      id: "TR-0185",
      status: "RecoveryBlocked",
      tone: "blocked" as const,
      title: "Workspace mutation",
      detail: "cursor 185 · explicit state",
    },
  ],
  workspacesLabel: "ISOLATED WORKSPACES",
  workspaces: ["workspace/alpha", "workspace/beta", "workspace/gamma"],
} as const;

export type ComicPanel = {
  n: string;
  kicker: string;
  speech: string;
  title: string;
  body: string;
  image: string;
};

export const comic = {
  eyebrow: "RUNNE FIELD NOTES · ISSUE 001",
  headline: "A coding task walks into a runtime.",
  intro:
    "Follow Runne through the moment a request becomes durable, controlled, and provably complete.",
  chips: ["6 PANELS", "1 SOURCE OF TRUTH"],
  panels: [
    {
      n: "01",
      kicker: "THE REQUEST",
      speech: "Got it. First, I make it durable.",
      title: "A task arrives.",
      body: "Runne turns the prompt into a TaskRun with an identity, a timeline, and a budget.",
      image: "/mascots/panel-01.png",
    },
    {
      n: "02",
      kicker: "THE INTERRUPTION",
      speech: "Window gone? I’m still here.",
      title: "The window disappears.",
      body: "The UI can close. The provider can stall. The authoritative run keeps its place.",
      image: "/mascots/panel-02.png",
    },
    {
      n: "03",
      kicker: "THE RECOVERY",
      speech: "Found the last safe step.",
      title: "Nothing is lost.",
      body: "Runne replays the journal and resumes from confirmed state—not from a hopeful guess.",
      image: "/mascots/panel-03.png",
    },
    {
      n: "04",
      kicker: "THE BOUNDARY",
      speech: "Show me the grant first.",
      title: "Tools ask permission.",
      body: "Files, shells, networks, and secrets stay behind explicit capability grants.",
      image: "/mascots/panel-04.png",
    },
    {
      n: "05",
      kicker: "THE PROOF",
      speech: "Nice claim. Where’s the proof?",
      title: "“Done” is challenged.",
      body: "Tests, checks, and artifacts become verification evidence attached to the run.",
      image: "/mascots/panel-05.png",
    },
    {
      n: "06",
      kicker: "THE OUTCOME",
      speech: "Verified. Recorded. Done.",
      title: "Now it can ship.",
      body: "You get a completed task with chronology, evidence, and an audit trail clients can trust.",
      image: "/mascots/panel-06.png",
    },
  ] satisfies ComicPanel[],
  closing: {
    headline: "The chat is a view. Runne is the continuity.",
    detail: "Durable execution · capability security · verification evidence",
  },
  guarantees: {
    eyebrow: "THE THREE GUARANTEES",
    headline: "Not a character trait. A runtime contract.",
    items: [
      { n: "01", name: "DURABLE", body: "The run survives its window." },
      { n: "02", name: "CONTROLLED", body: "Every dangerous action needs a grant." },
      { n: "03", name: "VERIFIED", body: "Completion carries evidence." },
    ],
  },
  chapter2: {
    eyebrow: "THE STORY GETS BIGGER · ISSUE 002",
    headline: "One run becomes a whole operating system.",
    intro:
      "The same runtime boundary keeps working as clients, providers, budgets, and histories multiply.",
    panels: [
      {
        n: "07",
        kicker: "MANY CLIENTS",
        runtimeLabel: "ONE RUNTIME",
        speech: "Different windows. Same run.",
        title: "Everyone sees the same truth.",
        body: "Desktop, CLI, and API clients read confirmed runtime projections instead of inventing their own state.",
      },
      {
        n: "09",
        kicker: "BOUNDED WORK",
        speech: "That’s the limit. We stop here.",
        title: "The budget has a guardian.",
        body: "Token, time, and tool limits are enforced while accounting remains visible and attributable.",
      },
    ],
    budget: {
      header: "RUN BUDGET",
      rows: [
        { label: "TOKENS", value: "78%", pct: 78 },
        { label: "TIME", value: "42%", pct: 42 },
        { label: "TOOLS", value: "3 / 5", pct: 60 },
      ],
      limit: "LIMIT ACTIVE",
    },
  },
} as const;

export const demo = {
  eyebrow: "LIVE RUNTIME",
  headline: "See the run. Not just the chat.",
  body:
    "Every step is backed by the journal: state, permissions, budget, and verification evidence live in one place.",
  chip: "TR-0184 · RUNNING",
  task: "TASKRUN / TR-0184",
  active: "ACTIVE",
  steps: [
    { n: "01", label: "Request accepted", done: true, active: false },
    { n: "02", label: "Workspace prepared", done: true, active: false },
    { n: "03", label: "Agent working", done: true, active: true },
    { n: "04", label: "Verification queued", done: false, active: false },
  ],
  runState: {
    heading: "RUN STATE",
    metrics: [
      { label: "Capability grants", value: "3 / 3" },
      { label: "Budget used", value: "78%" },
      { label: "Journal cursor", value: "184" },
    ],
  },
  command: "runne task inspect TR-0184",
} as const;

export const contract = {
  eyebrow: "UNDER THE PANELS",
  headline: "The simple shape behind every Runne story.",
  body:
    "Clients request work. The runtime decides what is allowed, records what actually happened, and publishes only confirmed state.",
  notes: ["LOCAL-FIRST", "PROVIDER-NEUTRAL", "CONTRACT-DRIVEN"],
  nodes: [
    { title: "Clients", caption: "DESKTOP · CLI · API", tone: "light" as const },
    { title: "runned", caption: "AUTHORITATIVE RUST RUNTIME", tone: "dark" as const },
    { title: "Event journal", caption: "SQLITE · ORDERED · REPLAYABLE", tone: "light" as const },
  ],
} as const;

export const cta = {
  headline: "Read the contracts. Run the runtime.",
  body: "Runne is open source, local-first, and designed to be inspected.",
} as const;

export const footer = {
  proposition: "A proof-carrying runtime for AI coding agents.",
  columns: [
    { heading: "PRODUCT", links: ["Runtime", "Desktop", "CLI"] },
    { heading: "RESOURCES", links: ["Documentation", "Architecture", "GitHub"] },
    { heading: "PROJECT", links: ["Principles", "Security", "Roadmap"] },
  ],
  copyright: "© 2025 Runne · Open source",
  status: "RUNTIME STATUS · OPERATIONAL",
} as const;
