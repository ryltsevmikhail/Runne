import type { ProductPageCopy } from "../../page-types";

export const product = {
  hero: {
    title: "Produit",
    description: "GOCODE réunit le projet local, la conversation et l'état du runtime dans une seule application de bureau.",
    eyebrow: "Produit",
    heading: "Un centre de contrôle pour travailler avec des agents AI.",
    lead: "Ouvrez un projet local, poursuivez une conversation et reprenez après un redémarrage. Le runtime GOCODE — et non la fenêtre de l'application — conserve l'état autoritatif.",
    boundary: "● Aperçu : macOS arm64, fournisseur déterministe, aucune exécution de modèle en production.",
    cta: "Rejoindre la liste d'attente",
    mockup: { ariaLabel: "Interface de projet local GOCODE", topLabel: "GOCODE · projet local", status: "● runtime prêt", railTitle: "PROJETS", project: "gocode", railItems: ["crates", "docs"], chatTitle: "Conversation avec l'agent", state: "LEAD · RESTAURÉ", message: "Conversation poursuivie depuis l'état confirmé sans doublons.", input: "Demander à GOCODE de travailler sur le projet…" },
  },
  workflow: {
    eyebrow: "Flux de travail",
    heading: "D'un dossier local à une conversation continue.",
    lead: "Le dossier reste sur l'appareil. GOCODE stocke un enregistrement local du projet et l'état du travail.",
    steps: [
      { title: "Ouvrir le projet", body: "Choisissez un dossier local sur l'appareil." },
      { title: "Démarrer une conversation", body: "Envoyez une demande dans la conversation locale actuelle." },
      { title: "Valider l'état", body: "Les événements sont persistés dans le journal du runtime." },
      { title: "Poursuivre le travail", body: "Revenez après un redémarrage ou une déconnexion." },
    ],
  },
  workspace: {
    eyebrow: "Espace de travail",
    heading: "Projet, conversation et état du runtime — dans une seule fenêtre.",
    lead: "L'interface n'affiche que des données typées et assainies. Les secrets et erreurs brutes du runtime n'atteignent jamais le modèle de vue.",
    items: [
      { title: "Projets locaux", body: "Dossiers de travail récents et sélection explicite du projet." },
      { title: "Conversation poursuivable", body: "Replay, flux en direct et synchronisation sûre." },
      { title: "État du runtime", body: "Démarrage, disponibilité, redémarrage, dégradation et récupération." },
    ],
  },
} satisfies ProductPageCopy;
