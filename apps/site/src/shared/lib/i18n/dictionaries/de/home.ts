import type { HomePageCopy } from "../../page-types";

export const home = {
  hero: {
    title: "AI-Coding-Agenten — unter Ihrer Kontrolle",
    description:
      "GOCODE ist eine Desktop-Leitstelle für AI-Agenten, gestützt auf eine lokale Runtime mit überprüfbaren Grenzen.",
    eyebrow: "Vorschau",
    heading: "AI-Coding-Agenten — unter Ihrer Kontrolle.",
    lead: "GOCODE ist eine Desktop-Leitstelle und eine providerneutrale Rust-Runtime. Sie bewahrt den autoritativen Zustand und stellt die Unterhaltung nach einem Neustart wieder her.",
    cta: "Zur Warteliste",
    mockup: {
      ariaLabel: "Beispiel der GOCODE-Oberfläche",
      topLabel: "GOCODE · lokale Runtime",
      status: "● Runtime bereit",
      railTitle: "PROJEKTE",
      project: "agent-runtime",
      railItems: ["crates", "docs · Tests"],
      chatTitle: "Agentenunterhaltung",
      state: "LEAD · WIEDERHERGESTELLT",
      message:
        "Die Runtime-Grenzen wurden geprüft und ein sicherer Änderungsplan erstellt.",
      input: "GOCODE mit dem Projekt beauftragen…",
    },
  },
  why: {
    eyebrow: "Warum GOCODE",
    heading: "Ein Agenten-Workflow sollte nicht mit seinem Fenster verschwinden.",
    lead: "GOCODE trennt eine komfortable Desktop-App vom autoritativen Zustand. Die Arbeit läuft als Teil der Runtime weiter, nicht als fragile UI-Sitzung.",
    items: [
      {
        title: "Ein Neustart beendet den Prozess nicht",
        body: "Unterhaltung und Ereignisse werden aus einem dauerhaften Stream wiederhergestellt.",
      },
      {
        title: "Die Oberfläche besitzt nicht die Wahrheit",
        body: "Die Runtime stellt nur bestätigte Projektionen bereit.",
      },
      {
        title: "Ungewisser Zustand blockiert Handlungen",
        body: "Eine Änderung beginnt erst nach Bestätigung.",
      },
    ],
  },
  architecture: {
    eyebrow: "Architektur",
    heading: "Eine Runtime. Eine Quelle der Wahrheit.",
    lead: "Die Desktop-App ruft nur die öffentlichen APIs von runtime-client und Vertrag auf. Implementierungsdetails bleiben hinter der Prozessgrenze.",
    flow: [
      { title: "App", body: "Oberfläche" },
      { title: "Tauri-Host", body: "Vertrauensgrenze" },
      { title: "runtime-client", body: "öffentliche API" },
      { title: "GOCODE Runtime", body: "autoritärer Zustand" },
      { title: "Ereignisjournal", body: "dauerhafte Aufzeichnung" },
    ],
  },
  preview: {
    eyebrow: "Vorschau",
    heading: "Die Grundlage beweisen, bevor echte Modelle verbunden werden.",
    lead: "Aktuelle Evidenz: macOS arm64 · spezielle Entwicklungs-Build.",
    verified: {
      label: "● überprüft",
      title: "Funktioniert in der aktuellen Version",
      items: [
        "Authentifizierter Runtime-Lebenszyklus",
        "Dauerhaftes Journal und Ereignis-Replay",
        "Wiederherstellung und Fortsetzung von Unterhaltungen",
        "Vue + Tauri Desktop-Shell",
      ],
    },
    review: {
      label: "● in Prüfung",
      title: "Ehrliche Versionsgrenzen",
      items: [
        "Deterministischer Provider statt echter Modelle",
        "Kein signiertes Installationsprogramm",
        "Nicht bereit für den Betrieb unter Windows/Linux",
      ],
    },
  },
  roadmap: {
    eyebrow: "Roadmap",
    heading: "Zuerst Evidenz. Dann Skalierung.",
    lead: "Keine Kalenderzusagen: Jede Phase endet anhand überprüfbarer Release-Kriterien.",
    cards: [
      {
        label: "01 · aktuelle Phase",
        title: "Runtime-Grundlage abgeschlossen",
        body: "Lebenszyklus, Ereignisjournal, Gesprächswiederherstellung und Desktop-Shell.",
      },
      {
        label: "02 · als Nächstes",
        title: "Echte Agentenprozesse",
        body: "Ein echter Provider, TaskRun/Audit-Streams und ein erweiterter Arbeitsbereich.",
      },
      {
        label: "03 · vor dem Release",
        title: "Bereitschaftsqualifizierung",
        body: "Native Isolation, Signierung, Plattformqualifizierung und ein unabhängiges Urteil.",
      },
    ],
  },
} satisfies HomePageCopy;
