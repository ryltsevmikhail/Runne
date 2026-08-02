import type { SecurityPageCopy } from "../../page-types";

export const security = {
  hero: {
    title: "Sicherheit",
    description:
      "Ungewisser Zustand erhält keine Berechtigung zu handeln: Die Sicherheitsgrenzen von GOCODE sind überprüfbar.",
    eyebrow: "Sicherheit",
    heading: "Ungewisser Zustand erhält keine Berechtigung zu handeln.",
    lead: "GOCODE bildet eine lokale Grenze mit expliziten Vertrauensgrenzen, Integritätsprüfungen und sicherem Herunterfahren, wenn die Evidenz nicht ausreicht.",
    panelEyebrow: "Lokale Grenze",
    panelBody: "Anmeldedaten und Endpoint werden nicht an die Oberfläche weitergegeben.",
  },
  trust: {
    eyebrow: "Vertrauenskarte",
    heading: "Jede Grenze weiß, was sie vertrauen darf.",
    lead: "Prüfungen von Eigentümer, Kanal und Integrität erfolgen vor Zustandsänderungen.",
    cards: [
      { title: "Oberfläche", body: "Erhält nur bereinigte, typisierte Daten.", label: "speichert keine Geheimnisse" },
      {
        title: "Lokales Profil",
        body: "In der Unix/macOS-Vorschau werden Eigentümer, Dateimodus und Loopback-Adresse geprüft.",
        label: "Windows: verweigern bis native ACL",
      },
      { title: "Ereignisjournal", body: "Prüft Reihenfolge, Integrität und Cursor.", label: "dauerhafte Aufzeichnung" },
    ],
  },
  mechanisms: {
    eyebrow: "Überprüfbare Mechanismen",
    heading: "Schutz entsteht aus konkreten Verweigerungen.",
    lead: "Kein einzelnes Element ersetzt eine zukünftige unabhängige Sicherheitsprüfung.",
    cards: [
      { title: "Replay-Integrität", body: "HMAC-Cursor, Hochwassermarke und Sequenzvalidierung." },
      { title: "Atomare Wiederherstellung", body: "Projektion und Cursor werden gespeichert, bevor die Zustellung bestätigt wird." },
      { title: "Unsicherer Start blockiert", body: "Der Prozessstart wird abgelehnt, bis ein zertifiziertes Phase-6B-Profil vorhanden ist." },
      { title: "Secret-Broker", body: "Prüft Autorisierung, Version, Verfügbarkeit und Widerruf." },
      { title: "Idempotenz", body: "Erneute Zustellung erzeugt keinen doppelten Zustand." },
      { title: "Provider ohne Autorität", body: "Der aktuelle deterministische Provider hat keinen Netzwerk-, Datei- oder Prozesszugriff." },
    ],
  },
  boundary: {
    eyebrow: "Ehrliche Grenze",
    heading: "Dies ist keine operative Sicherheitszertifizierung.",
    lead: "Native Isolation der Phase 6B, Windows/Linux-Qualifizierung, echte Provider und eine unabhängige Prüfung sind noch nicht abgeschlossen.",
    items: ["Native Isolation", "Plattformübergreifende Qualifizierung", "Unabhängiges Abschlussurteil"],
    roadmapCta: "Roadmap ansehen",
  },
} satisfies SecurityPageCopy;
