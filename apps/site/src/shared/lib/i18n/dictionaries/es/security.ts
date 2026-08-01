import type { SecurityPageCopy } from "../../page-types";

export const security = {
  hero: {
    title: "Seguridad",
    description:
      "El estado incierto no recibe permiso para actuar: los límites de seguridad de GOCODE son verificables.",
    eyebrow: "Seguridad",
    heading: "El estado incierto no recibe permiso para actuar.",
    lead: "GOCODE construye un límite local con límites de confianza explícitos, comprobaciones de integridad y apagado seguro cuando la evidencia es insuficiente.",
    panelEyebrow: "Límite local",
    panelBody: "Las credenciales y el endpoint no se transfieren a la interfaz.",
  },
  trust: {
    eyebrow: "Mapa de confianza",
    heading: "Cada límite sabe en qué confiar.",
    lead: "Las comprobaciones de propietario, canal e integridad se realizan antes de los cambios de estado.",
    cards: [
      {
        title: "Interfaz",
        body: "Recibe únicamente datos tipados y saneados.",
        label: "no almacena secretos",
      },
      {
        title: "Perfil local",
        body: "En la vista previa de Unix/macOS, comprueba el propietario, el modo de archivo y la dirección de loopback.",
        label: "Windows: denegar hasta ACL nativa",
      },
      {
        title: "Diario de eventos",
        body: "Comprueba el orden, la integridad y el cursor.",
        label: "registro duradero",
      },
    ],
  },
  mechanisms: {
    eyebrow: "Mecanismos verificables",
    heading: "La protección se construye con rechazos concretos.",
    lead: "Ningún elemento por sí solo sustituye una futura revisión de seguridad independiente.",
    cards: [
      {
        title: "Integridad de replay",
        body: "Cursor HMAC, marca de agua y validación de secuencia.",
      },
      {
        title: "Recuperación atómica",
        body: "La proyección y el cursor se confirman antes de reconocer la entrega.",
      },
      {
        title: "Inicio inseguro bloqueado",
        body: "El lanzamiento de procesos se rechaza hasta que exista un perfil Phase 6B certificado.",
      },
      {
        title: "Broker de secretos",
        body: "Comprueba autorización, versión, disponibilidad y revocación.",
      },
      {
        title: "Idempotencia",
        body: "La reentrega no crea estado duplicado.",
      },
      {
        title: "Proveedor sin autoridad",
        body: "El proveedor determinista actual no tiene acceso a red, archivos ni procesos.",
      },
    ],
  },
  boundary: {
    eyebrow: "Límite honesto",
    heading: "Esto no es una certificación de seguridad operativa.",
    lead: "El aislamiento nativo de Phase 6B, la cualificación de Windows/Linux, los proveedores reales y una revisión independiente todavía no están completados.",
    items: [
      "Aislamiento nativo",
      "Cualificación multiplataforma",
      "Dictamen final independiente",
    ],
    roadmapCta: "Ver hoja de ruta",
  },
} satisfies SecurityPageCopy;
