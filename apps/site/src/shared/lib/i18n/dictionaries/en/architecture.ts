import type { ArchitecturePageCopy } from "../../page-types";

export const architecture = {
  hero: {
    title: "Architecture",
    description:
      "The GOCODE runtime owns state, while the interface controls it only through a verifiable public contract.",
    eyebrow: "Architecture",
    heading: "The runtime owns state. The interface owns control.",
    lead: "GOCODE separates authoritative state, public contracts, and presentation. The desktop app does not bypass the runtime client or import implementation internals.",
    status: "● single source of truth",
    cards: [
      { title: "Vue / Tauri", body: "control" },
      { title: "runtime-client", body: "public contract" },
      { title: "GOCODE runtime", body: "authoritative state" },
      { title: "SQLite event journal", body: "durable record" },
    ],
  },
  flow: {
    eyebrow: "Data flow",
    heading: "A command crosses one verifiable boundary.",
    lead: "There is no bypass through HTTP, storage, or interface state.",
    items: [
      { title: "Command", body: "CLI / desktop app" },
      { title: "runtime-client", body: "authentication" },
      { title: "RuntimeHandle", body: "admission and execution" },
      { title: "Event journal", body: "event commit" },
      { title: "Projection", body: "sanitized DTOs" },
    ],
  },
  boundary: {
    eyebrow: "Responsibility boundary",
    heading: "The interface reads a projection. The runtime decides.",
    lead: "Credentials and the endpoint stay in the Tauri host. Vue receives typed DTOs without secrets or raw errors.",
    desktop: {
      title: "Desktop app",
      body: "User intent · presentation · retry",
      status: "does not own state",
    },
    runtime: {
      title: "GOCODE runtime",
      body: "Events · cursor · projections · recovery",
      status: "authoritative state",
    },
  },
  replay: {
    eyebrow: "Replay and continuation",
    heading: "Continuation starts from a confirmed position.",
    lead: "The cursor is committed atomically, and duplicates are handled idempotently.",
    steps: [
      {
        title: "High-water mark",
        body: "Captures the available event boundary.",
      },
      {
        title: "Catch-up stream",
        body: "Returns events through the boundary.",
      },
      {
        title: "Atomic commit",
        body: "Projection and cursor are stored together.",
      },
      {
        title: "Live continuation",
        body: "The stream begins without losing position.",
      },
    ],
  },
} satisfies ArchitecturePageCopy;
