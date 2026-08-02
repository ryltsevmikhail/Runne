import type { SharedCopy } from "../../types";

export const shared = {
  siteDescription: "Un runtime local pour travailler de manière fiable avec des agents AI.",
  skipToContent: "Aller au contenu",
  homeAriaLabel: "Accueil GOCODE",
  primaryNavAriaLabel: "Navigation principale",
  footerNavAriaLabel: "Navigation du pied de page",
  languageLabel: "Langue",
  waitlistCta: "Rejoindre la liste d'attente",
  nav: { product: "Produit", architecture: "Architecture", security: "Sécurité", roadmap: "Feuille de route", status: "État" },
  footer: { description: "Un runtime local pour les agents AI.", privacy: "Confidentialité", preview: "letsgocode.dev · aperçu" },
  waitlist: {
    eyebrow: "Avancer avec GOCODE",
    heading: "Rejoignez l'aperçu privé.",
    body: "Ce lien est informatif : le formulaire est inactif et aucune donnée de contact n'est collectée.",
    statusLink: "Voir l'état du développement",
  },
  notFound: {
    title: "Page introuvable",
    description: "La page GOCODE demandée n'existe pas.",
    eyebrow: "404",
    heading: "Route introuvable.",
    body: "Cette page n'a pas d'adresse publiée.",
    backHome: "Retour à l'accueil",
  },
} satisfies SharedCopy;
