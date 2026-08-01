import type { RoadmapPageCopy } from "../../page-types";

export const roadmap = {
  hero: {
    title: "Roadmap",
    description: "Die GOCODE-Roadmap stellt Evidenz vor Release, ohne ungeprüfte Verfügbarkeitszusagen.",
    eyebrow: "Roadmap",
    heading: "Zuerst Evidenz. Dann Release.",
    lead: "Ein Datum macht eine Fähigkeit nicht bereit. Fortschritt erfordert Implementierung, Plattform-Evidenz und eine unabhängige Prüfung.",
    panelLabel: "● Vorschau",
    panelTitle: "Aktuelle Grenze",
    panelBody: "Ein lokaler macOS-arm64-Pfad ist in einer speziellen Entwicklungs-Build überprüft.",
    warning: "⚠ Dies ist weder operative Bereitschaft noch ein öffentliches Release.",
  },
  stages: {
    eyebrow: "Drei Phasen",
    heading: "Jede Phase endet mit Überprüfung.",
    lead: "Wir veröffentlichen keine Zeitpläne, die noch nicht existieren.",
    cards: [
      { label: "01 · lokal überprüft", title: "Runtime-Grundlage abgeschlossen", body: "Dauerhafte Unterhaltung, Replay und Fortsetzung sowie Wiederherstellung nach Neustart.\nmacOS arm64 · spezielle Entwicklungs-Build" },
      { label: "02 · als Nächstes", title: "Echte Agentenprozesse", body: "Ein echter Provider, TaskRun/Audit-Streams und ein erweiterter Arbeitsbereich.\nKriterium: Verträge + Wiederherstellung" },
      { label: "03 · vor öffentlichem Release", title: "Operative Bereitschaft", body: "Native Isolation, Signierung, Windows/Linux-Qualifizierung und ein unabhängiges Urteil." },
    ],
  },
  exclusions: {
    eyebrow: "Was wir noch nicht versprechen",
    heading: "Ein Plan ist keine Liste verfügbarer Fähigkeiten.",
    items: [
      { title: "Keine Produktionsausführung mit einem echten Modell", body: "Der aktuelle Provider ist deterministisch und lokal." },
      { title: "Kein öffentlicher Download", body: "Signierung, Installationsprogramm und Qualifizierung sind unvollständig." },
      { title: "Keine überprüfte plattformübergreifende Unterstützung", body: "Windows/Linux benötigen separate Evidenz." },
    ],
  },
  legend: {
    eyebrow: "Status lesen",
    heading: "Die Farbe kennzeichnet die Art der Evidenz.",
    cards: [
      { label: "● lokal überprüft", title: "", body: "Für die benannte Umgebung liegen Implementierung und exakte Evidenz vor." },
      { label: "● als Nächstes", title: "", body: "Der Ausschnitt ist definiert, aber noch keine verfügbare Fähigkeit." },
      { label: "● vor öffentlichem Release", title: "", body: "Eine verpflichtende Qualifizierungs- und Release-Bedingung." },
    ],
  },
} satisfies RoadmapPageCopy;
