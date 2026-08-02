import type { SharedCopy } from "../../types";

export const shared = {
  siteDescription: "Un runtime local para trabajar con AI de forma fiable.",
  skipToContent: "Saltar al contenido",
  homeAriaLabel: "Inicio de GOCODE",
  primaryNavAriaLabel: "Navegación principal",
  footerNavAriaLabel: "Navegación del pie de página",
  languageLabel: "Idioma",
  waitlistCta: "Unirse a la lista de espera",
  nav: {
    product: "Producto",
    architecture: "Arquitectura",
    security: "Seguridad",
    roadmap: "Hoja de ruta",
    status: "Estado",
  },
  footer: {
    description: "Un runtime local para agentes de AI.",
    privacy: "Privacidad",
    preview: "letsgocode.dev · vista previa",
  },
  waitlist: {
    eyebrow: "Avanza con GOCODE",
    heading: "Únete a la vista previa privada.",
    body: "Este enlace es informativo: el formulario está inactivo y no se recopilan datos de contacto.",
    statusLink: "Ver el estado del desarrollo",
  },
  notFound: {
    title: "Página no encontrada",
    description: "La página solicitada de GOCODE no existe.",
    eyebrow: "404",
    heading: "Ruta no encontrada.",
    body: "Esta página no tiene una dirección publicada.",
    backHome: "Volver al inicio",
  },
} satisfies SharedCopy;
