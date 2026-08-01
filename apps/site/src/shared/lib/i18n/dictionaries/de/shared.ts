import type { SharedCopy } from "../../types";

export const shared = {
  siteDescription: "Eine lokale Runtime für zuverlässige Arbeit mit AI-Agenten.",
  skipToContent: "Zum Inhalt springen",
  homeAriaLabel: "GOCODE-Startseite",
  primaryNavAriaLabel: "Hauptnavigation",
  footerNavAriaLabel: "Fußzeilennavigation",
  languageLabel: "Sprache",
  waitlistCta: "Zur Warteliste",
  nav: {
    product: "Produkt",
    architecture: "Architektur",
    security: "Sicherheit",
    roadmap: "Roadmap",
    status: "Status",
  },
  footer: {
    description: "Eine lokale Runtime für AI-Agenten.",
    privacy: "Datenschutz",
    preview: "letsgocode.dev · Vorschau",
  },
  waitlist: {
    eyebrow: "Mit GOCODE vorankommen",
    heading: "An der privaten Vorschau teilnehmen.",
    body: "Dieser Link dient nur zur Information: Das Formular ist inaktiv und es werden keine Kontaktdaten erhoben.",
    statusLink: "Entwicklungsstatus ansehen",
  },
  notFound: {
    title: "Seite nicht gefunden",
    description: "Die angeforderte GOCODE-Seite existiert nicht.",
    eyebrow: "404",
    heading: "Route nicht gefunden.",
    body: "Diese Seite hat keine veröffentlichte Adresse.",
    backHome: "Zurück zur Startseite",
  },
} satisfies SharedCopy;
