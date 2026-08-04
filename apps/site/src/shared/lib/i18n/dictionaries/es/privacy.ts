import type { PrivacyPageCopy } from "../../page-types";

export const privacy = {
  hero: {
    title: "Privacidad",
    description:
      "Información de privacidad para la compilación estática del sitio de GOCODE.",
    eyebrow: "Privacidad",
    heading: "Este sitio estático no recopila datos de contacto.",
    lead: "El formulario está inactivo: no hay envío de correo electrónico, registro ni otra recopilación de datos de contacto.",
    panelLabel: "● sin envío de datos",
    panelTitle: "Enlace informativo",
    panelBody:
      "El bloque de lista de espera no crea una solicitud ni envía información a terceros.",
  },
  boundary: {
    eyebrow: "Límite de la página",
    heading: "No introduzcas datos de contacto: el sitio no tiene dónde enviarlos.",
    items: [
      {
        title: "Sin cuenta",
        body: "La compilación estática no ofrece registro ni inicio de sesión.",
      },
      {
        title: "Sin formulario activo",
        body: "La lista de espera es solo un bloque informativo.",
      },
      {
        title: "Más adelante se necesitarán condiciones independientes",
        body: "Los futuros productos y servicios de escritorio requerirán políticas publicadas explícitamente.",
      },
    ],
  },
} satisfies PrivacyPageCopy;
