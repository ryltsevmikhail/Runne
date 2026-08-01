import type { PrivacyPageCopy } from "../../page-types";

export const privacy = {
  hero: {
    title: "Datenschutz",
    description: "Datenschutzinformationen für die statische GOCODE-Site-Build.",
    eyebrow: "Datenschutz",
    heading: "Diese statische Website erhebt keine Kontaktdaten.",
    lead: "Das Formular ist inaktiv: Es gibt keine E-Mail-Übermittlung, Registrierung oder sonstige Erhebung von Kontaktdaten.",
    panelLabel: "● keine Datenübermittlung",
    panelTitle: "Informationslink",
    panelBody: "Der Wartelistenblock erstellt keine Anmeldung und sendet keine Informationen an Dritte.",
  },
  boundary: {
    eyebrow: "Seitengrenze",
    heading: "Geben Sie keine Kontaktdaten ein: Die Website kann sie nirgends senden.",
    items: [
      { title: "Kein Konto", body: "Die statische Build bietet keine Registrierung oder Anmeldung." },
      { title: "Kein aktives Formular", body: "Die Warteliste ist nur ein Informationsblock." },
      { title: "Später sind separate Bedingungen nötig", body: "Künftige Desktop-Produkte und -Dienste erfordern ausdrücklich veröffentlichte Richtlinien." },
    ],
  },
} satisfies PrivacyPageCopy;
