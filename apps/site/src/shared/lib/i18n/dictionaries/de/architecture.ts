import type { ArchitecturePageCopy } from "../../page-types";

export const architecture = {
  hero: {
    title: "Architektur",
    description:
      "Die GOCODE Runtime besitzt den Zustand; die Oberfläche steuert ihn nur über einen überprüfbaren öffentlichen Vertrag.",
    eyebrow: "Architektur",
    heading: "Die Runtime besitzt den Zustand. Die Oberfläche besitzt die Steuerung.",
    lead: "GOCODE trennt autoritativen Zustand, öffentliche Verträge und Darstellung. Die Desktop-App umgeht weder den Runtime-Client noch importiert sie interne Implementierungsdetails.",
    status: "● einzige Quelle der Wahrheit",
    cards: [
      { title: "Vue / Tauri", body: "Steuerung" },
      { title: "runtime-client", body: "öffentlicher Vertrag" },
      { title: "GOCODE Runtime", body: "autoritärer Zustand" },
      { title: "SQLite-Ereignisjournal", body: "dauerhafte Aufzeichnung" },
    ],
  },
  flow: {
    eyebrow: "Datenfluss",
    heading: "Ein Befehl überquert eine überprüfbare Grenze.",
    lead: "Es gibt keine Umgehung über HTTP, Speicher oder Oberflächenzustand.",
    items: [
      { title: "Befehl", body: "CLI / Desktop-App" },
      { title: "runtime-client", body: "Authentifizierung" },
      { title: "RuntimeHandle", body: "Zulassung und Ausführung" },
      { title: "Ereignisjournal", body: "Ereignis-Commit" },
      { title: "Projektion", body: "bereinigte DTOs" },
    ],
  },
  boundary: {
    eyebrow: "Verantwortungsgrenze",
    heading: "Die Oberfläche liest eine Projektion. Die Runtime entscheidet.",
    lead: "Anmeldedaten und Endpoint bleiben im Tauri-Host. Vue erhält typisierte DTOs ohne Geheimnisse oder rohe Fehler.",
    desktop: {
      title: "Desktop-App",
      body: "Nutzerabsicht · Darstellung · Wiederholung",
      status: "besitzt den Zustand nicht",
    },
    runtime: {
      title: "GOCODE Runtime",
      body: "Ereignisse · Cursor · Projektionen · Wiederherstellung",
      status: "autoritärer Zustand",
    },
  },
  replay: {
    eyebrow: "Replay und Fortsetzung",
    heading: "Die Fortsetzung beginnt an einer bestätigten Position.",
    lead: "Der Cursor wird atomar gespeichert, und Duplikate werden idempotent behandelt.",
    steps: [
      { title: "Hochwassermarke", body: "Erfasst die verfügbare Ereignisgrenze." },
      { title: "Aufhol-Stream", body: "Liefert Ereignisse bis zu dieser Grenze." },
      { title: "Atomarer Commit", body: "Projektion und Cursor werden zusammen gespeichert." },
      { title: "Live-Fortsetzung", body: "Der Stream startet ohne Positionsverlust." },
    ],
  },
} satisfies ArchitecturePageCopy;
