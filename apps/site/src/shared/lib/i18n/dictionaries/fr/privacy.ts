import type { PrivacyPageCopy } from "../../page-types";

export const privacy = {
  hero: { title: "Confidentialité", description: "Informations de confidentialité pour la build statique du site GOCODE.", eyebrow: "Confidentialité", heading: "Ce site statique ne collecte pas de données de contact.", lead: "Le formulaire est inactif : aucun e-mail n'est envoyé, aucune inscription ni autre collecte de données de contact n'a lieu.", panelLabel: "● aucune soumission de données", panelTitle: "Lien informatif", panelBody: "Le bloc de liste d'attente ne crée pas de demande et n'envoie aucune information à des tiers." },
  boundary: { eyebrow: "Limite de la page", heading: "N'entrez pas de données de contact : le site ne peut les envoyer nulle part.", items: [{ title: "Aucun compte", body: "La build statique n'offre ni inscription ni connexion." }, { title: "Aucun formulaire actif", body: "La liste d'attente est seulement un bloc informatif." }, { title: "Des conditions distinctes seront nécessaires plus tard", body: "Les futurs produits et services de bureau exigeront des politiques explicitement publiées." }] },
} satisfies PrivacyPageCopy;
