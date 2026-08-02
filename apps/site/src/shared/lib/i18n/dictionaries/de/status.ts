import type { StatusPageCopy } from "../../page-types";

export const status = {
  hero: {
    title: "Entwicklungsstatus",
    description: "Überprüfte GOCODE-Implementierungsevidenz und genaue Grenzen der aktuellen Vorschau.",
    eyebrow: "Entwicklungsstatus",
    heading: "Was jetzt funktioniert. Was noch bevorsteht.",
    lead: "Wir zeigen überprüfte Implementierung getrennt von Zielfähigkeiten, Plattformunterstützung und Release-Bereitschaft.",
    panelLabel: "● lokal überprüft",
    panelTitle: "Aktuelle Momentaufnahme",
    panelBody: "Unterhaltungs-Replay und -Fortsetzung sowie ein geschützter lokaler Runtime-Lebenszyklus.",
    platform: "macOS arm64 · spezielle Entwicklungs-Build",
  },
  snapshot: {
    eyebrow: "Implementierungsstand",
    heading: "Die Grundlage ist aufgebaut und lokal überprüft.",
    lead: "Dies ist kein Nachweis für operative Unterstützung von macOS, Windows oder Linux.",
    cards: [
      { title: "Desktop-Shell", body: "Tauri 2 · Vue 3 · TypeScript" },
      { title: "Speicher", body: "SQLite · Journal · Projektionen" },
      { title: "Unterhaltung", body: "Erstellen · Generieren · Replay · Fortsetzen" },
      { title: "Lokale Runtime", body: "Geschützter Socket · Sitzung · Neustart" },
    ],
  },
  boundaries: {
    eyebrow: "Statusgrenzen",
    heading: "Implementiert bedeutet nicht veröffentlicht.",
    lead: "Jede zukünftige Fähigkeit bleibt ein Plan, bis sie separat überprüft wurde.",
    current: {
      label: "Aktuell",
      title: "Implementiert",
      items: ["Lebenszyklus und authentifizierter Handshake", "Dauerhaftes Ereignisjournal", "Unterhaltungs-Replay und -Fortsetzung", "Sichere Wiederholungs- und Synchronisierungszustände"],
    },
    open: {
      label: "Offen",
      title: "Noch nicht überprüft",
      items: ["Echter Provider und Tools", "TaskRun / Audit in der Desktop-App", "Windows/Linux und eine operative macOS-Build", "Signierte Installationsprogramme und öffentliches Release"],
    },
  },
  platforms: {
    eyebrow: "Plattformgrenze",
    heading: "Eine Zielplattform ist keine unterstützte Plattform.",
    lead: "Der Status ändert sich erst nach einer paketbezogenen Überprüfung eines bestimmten Release-Kandidaten.",
    items: [
      { name: "macOS arm64", status: "● lokal überprüft" },
      { name: "Windows", status: "● Qualifizierung erforderlich" },
      { name: "Linux", status: "● Qualifizierung erforderlich" },
    ],
  },
} satisfies StatusPageCopy;
