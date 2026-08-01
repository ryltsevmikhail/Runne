import type { RoadmapPageCopy } from "../../page-types";

export const roadmap = {
  hero: {
    title: "Roadmap",
    description:
      "The GOCODE roadmap puts evidence before release, without unverified availability promises.",
    eyebrow: "Roadmap",
    heading: "Evidence first. Release second.",
    lead: "A date does not make a capability ready. Moving forward requires implementation, platform evidence, and an independent review.",
    panelLabel: "● preview",
    panelTitle: "Current boundary",
    panelBody:
      "A local macOS arm64 path is verified in a development special build.",
    warning: "⚠ This is not operational readiness or a public release.",
  },
  stages: {
    eyebrow: "Three stages",
    heading: "Every stage closes with verification.",
    lead: "We do not publish timelines that do not exist yet.",
    cards: [
      {
        label: "01 · locally verified",
        title: "Runtime foundation complete",
        body: "Durable conversation, replay and continuation, and recovery after restart.\nmacOS arm64 · development special build",
      },
      {
        label: "02 · next",
        title: "Real agent processes",
        body: "A real provider, TaskRun/Audit streams, and an expanded workspace.\ncriterion: contracts + recovery",
      },
      {
        label: "03 · before public release",
        title: "Operational readiness",
        body: "Native isolation, signing, Windows/Linux qualification, and an independent verdict.",
      },
    ],
  },
  exclusions: {
    eyebrow: "What we do not promise yet",
    heading: "A plan is not a list of available capabilities.",
    items: [
      {
        title: "No production execution with a real model",
        body: "The current provider is deterministic and local.",
      },
      {
        title: "No public download",
        body: "Signing, the installer, and qualification are incomplete.",
      },
      {
        title: "No verified cross-platform support",
        body: "Windows/Linux require separate evidence.",
      },
    ],
  },
  legend: {
    eyebrow: "How to read statuses",
    heading: "Color identifies the kind of evidence.",
    cards: [
      {
        label: "● locally verified",
        title: "",
        body: "Implementation and exact evidence exist for the named environment.",
      },
      {
        label: "● next",
        title: "",
        body: "The slice is defined, but it is not yet an available capability.",
      },
      {
        label: "● before public release",
        title: "",
        body: "A mandatory qualification and release condition.",
      },
    ],
  },
} satisfies RoadmapPageCopy;
