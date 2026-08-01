import type { SecurityPageCopy } from "../../page-types";

export const security = {
  hero: {
    title: "Security",
    description:
      "Uncertain state receives no permission to act: GOCODE security boundaries are verifiable.",
    eyebrow: "Security",
    heading: "Uncertain state receives no permission to act.",
    lead: "GOCODE builds a local boundary with explicit trust boundaries, integrity checks, and safe shutdown when evidence is insufficient.",
    panelEyebrow: "Local boundary",
    panelBody: "Credentials and the endpoint are not passed to the interface.",
  },
  trust: {
    eyebrow: "Trust map",
    heading: "Every boundary knows what to trust.",
    lead: "Owner, channel, and integrity checks happen before state changes.",
    cards: [
      {
        title: "Interface",
        body: "Receives only sanitized, typed data.",
        label: "does not store secrets",
      },
      {
        title: "Local profile",
        body: "In the Unix/macOS preview, checks the owner, file mode, and loopback address.",
        label: "Windows: deny until native ACL",
      },
      {
        title: "Event journal",
        body: "Verifies ordering, integrity, and cursor.",
        label: "durable record",
      },
    ],
  },
  mechanisms: {
    eyebrow: "Verifiable mechanisms",
    heading: "Protection is built from concrete refusals.",
    lead: "No single item replaces a future independent security review.",
    cards: [
      {
        title: "Replay integrity",
        body: "HMAC cursor, high-water mark, and sequence validation.",
      },
      {
        title: "Atomic recovery",
        body: "Projection and cursor are committed before delivery is acknowledged.",
      },
      {
        title: "Unsafe launch blocked",
        body: "Process launch is rejected until a certified Phase 6B profile exists.",
      },
      {
        title: "Secret broker",
        body: "Checks authorization, version, availability, and revocation.",
      },
      {
        title: "Idempotency",
        body: "Redelivery does not create duplicate state.",
      },
      {
        title: "Provider without authority",
        body: "The current deterministic provider has no network, file, or process access.",
      },
    ],
  },
  boundary: {
    eyebrow: "Honest boundary",
    heading: "This is not an operational security certification.",
    lead: "Phase 6B native isolation, Windows/Linux qualification, real providers, and an independent review are not yet complete.",
    items: [
      "Native isolation",
      "Cross-platform qualification",
      "Independent final verdict",
    ],
    roadmapCta: "View roadmap",
  },
} satisfies SecurityPageCopy;
