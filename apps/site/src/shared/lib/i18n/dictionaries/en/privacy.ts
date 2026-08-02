import type { PrivacyPageCopy } from "../../page-types";

export const privacy = {
  hero: {
    title: "Privacy",
    description: "Privacy information for the static GOCODE site build.",
    eyebrow: "Privacy",
    heading: "This static site does not collect contact data.",
    lead: "The form is inactive: there is no email submission, registration, or other collection of contact data.",
    panelLabel: "● no data submission",
    panelTitle: "Informational link",
    panelBody:
      "The waitlist block does not create an application or send information to third parties.",
  },
  boundary: {
    eyebrow: "Page boundary",
    heading: "Do not enter contact data: the site has nowhere to send it.",
    items: [
      {
        title: "No account",
        body: "The static build offers no registration or sign-in.",
      },
      {
        title: "No active form",
        body: "The waitlist is only an informational block.",
      },
      {
        title: "Separate terms will be required later",
        body: "Future desktop products and services will require explicitly published policies.",
      },
    ],
  },
} satisfies PrivacyPageCopy;
