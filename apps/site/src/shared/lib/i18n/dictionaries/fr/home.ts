import type { HomePageCopy } from "../../page-types";

export const home = {
  hero: {
    title: "Agents de programmation AI — sous votre contrôle",
    description: "GOCODE est un centre de contrôle de bureau pour les agents AI, soutenu par un runtime local aux limites vérifiables.",
    eyebrow: "Aperçu",
    heading: "Agents de programmation AI — sous votre contrôle.",
    lead: "GOCODE est un centre de contrôle de bureau et un runtime Rust neutre vis-à-vis des fournisseurs. Il conserve l'état autoritatif et restaure la conversation après un redémarrage.",
    cta: "Rejoindre la liste d'attente",
    mockup: {
      ariaLabel: "Exemple de l'interface GOCODE",
      topLabel: "GOCODE · runtime local",
      status: "● runtime prêt",
      railTitle: "PROJETS",
      project: "agent-runtime",
      railItems: ["crates", "docs · tests"],
      chatTitle: "Conversation avec l'agent",
      state: "LEAD · RESTAURÉ",
      message: "Les limites du runtime ont été vérifiées et un plan de changement sûr a été préparé.",
      input: "Demander à GOCODE de travailler sur le projet…",
    },
  },
  why: {
    eyebrow: "Pourquoi GOCODE",
    heading: "Un flux de travail d'agent ne doit pas disparaître avec sa fenêtre.",
    lead: "GOCODE sépare une application de bureau pratique de l'état autoritatif. Le travail continue dans le runtime, et non dans une session d'UI fragile.",
    items: [
      { title: "Un redémarrage ne termine pas le processus", body: "La conversation et les événements sont restaurés depuis un flux durable." },
      { title: "L'interface ne détient pas la vérité", body: "Le runtime n'expose que des projections confirmées." },
      { title: "Un état incertain bloque l'action", body: "Un changement ne commence qu'après confirmation." },
    ],
  },
  architecture: {
    eyebrow: "Architecture",
    heading: "Un runtime. Une source de vérité.",
    lead: "L'application de bureau appelle uniquement les API publiques du runtime-client et du contrat. Les détails d'implémentation restent derrière la limite du processus.",
    flow: [
      { title: "App", body: "interface" },
      { title: "Hôte Tauri", body: "limite de confiance" },
      { title: "runtime-client", body: "API publique" },
      { title: "Runtime GOCODE", body: "état autoritatif" },
      { title: "Journal d'événements", body: "enregistrement durable" },
    ],
  },
  preview: {
    eyebrow: "Aperçu",
    heading: "Prouver les fondations avant de connecter de vrais modèles.",
    lead: "Éléments vérifiés actuellement : macOS arm64 · build spéciale de développement.",
    verified: {
      label: "● vérifié",
      title: "Fonctionne dans la version actuelle",
      items: ["Cycle de vie authentifié du runtime", "Journal durable et replay d'événements", "Restauration et poursuite des conversations", "Shell de bureau Vue + Tauri"],
    },
    review: {
      label: "● en cours d'examen",
      title: "Limites honnêtes de la version",
      items: ["Fournisseur déterministe au lieu de vrais modèles", "Pas d'installeur signé", "Pas prêt pour l'exploitation sous Windows/Linux"],
    },
  },
  roadmap: {
    eyebrow: "Feuille de route",
    heading: "D'abord les preuves. Ensuite l'échelle.",
    lead: "Aucune promesse calendaire : chaque étape se clôt selon des critères de livraison vérifiables.",
    cards: [
      { label: "01 · étape actuelle", title: "Fondation du runtime terminée", body: "Cycle de vie, journal d'événements, reprise des conversations et shell de bureau." },
      { label: "02 · suivant", title: "Vrais processus d'agents", body: "Un vrai fournisseur, des flux TaskRun/Audit et un espace de travail étendu." },
      { label: "03 · avant la sortie", title: "Qualification de préparation", body: "Isolation native, signature, qualification des plateformes et avis indépendant." },
    ],
  },
} satisfies HomePageCopy;
