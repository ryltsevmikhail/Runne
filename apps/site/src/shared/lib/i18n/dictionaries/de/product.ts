import type { ProductPageCopy } from "../../page-types";

export const product = {
  hero: {
    title: "Produkt",
    description:
      "GOCODE vereint lokales Projekt, Unterhaltung und Runtime-Zustand in einer Desktop-App.",
    eyebrow: "Produkt",
    heading: "Eine Leitstelle für die Arbeit mit AI-Agenten.",
    lead: "Öffnen Sie ein lokales Projekt, führen Sie eine Unterhaltung fort und machen Sie nach einem Neustart weiter. Die GOCODE Runtime — nicht das App-Fenster — bewahrt den autoritativen Zustand.",
    boundary:
      "● Vorschau: macOS arm64, deterministischer Provider, keine Modellausführung in Produktion.",
    cta: "Zur Warteliste",
    mockup: {
      ariaLabel: "GOCODE-Oberfläche für ein lokales Projekt",
      topLabel: "GOCODE · lokales Projekt",
      status: "● Runtime bereit",
      railTitle: "PROJEKTE",
      project: "gocode",
      railItems: ["crates", "docs"],
      chatTitle: "Agentenunterhaltung",
      state: "LEAD · WIEDERHERGESTELLT",
      message: "Unterhaltung ohne Duplikate aus dem bestätigten Zustand fortgesetzt.",
      input: "GOCODE mit dem Projekt beauftragen…",
    },
  },
  workflow: {
    eyebrow: "Workflow",
    heading: "Von einem lokalen Ordner zu einer fortsetzbaren Unterhaltung.",
    lead: "Der Ordner bleibt auf dem Gerät. GOCODE speichert einen lokalen Projektdatensatz und den Arbeitszustand.",
    steps: [
      { title: "Projekt öffnen", body: "Wählen Sie einen lokalen Ordner auf dem Gerät." },
      {
        title: "Unterhaltung starten",
        body: "Senden Sie eine Anfrage in der aktuellen lokalen Unterhaltung.",
      },
      {
        title: "Zustand speichern",
        body: "Ereignisse werden im Runtime-Journal persistiert.",
      },
      {
        title: "Weiterarbeiten",
        body: "Nach einem Neustart oder einer Unterbrechung zurückkehren.",
      },
    ],
  },
  workspace: {
    eyebrow: "Arbeitsbereich",
    heading: "Projekt, Unterhaltung und Runtime-Zustand — in einem Fenster.",
    lead: "Die Oberfläche zeigt nur typisierte, bereinigte Daten. Geheimnisse und rohe Runtime-Fehler gelangen nie in das View-Modell.",
    items: [
      { title: "Lokale Projekte", body: "Letzte Arbeitsordner und explizite Projektauswahl." },
      { title: "Fortsetzbare Unterhaltung", body: "Replay, Live-Feed und sichere Synchronisierung." },
      { title: "Runtime-Zustand", body: "Start, Bereitschaft, Neustart, Degradation und Wiederherstellung." },
    ],
  },
} satisfies ProductPageCopy;
