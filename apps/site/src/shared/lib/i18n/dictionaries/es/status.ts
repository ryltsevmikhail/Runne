import type { StatusPageCopy } from "../../page-types";

export const status = {
  hero: {
    title: "Estado del desarrollo",
    description:
      "Evidencia verificada de la implementación de GOCODE y límites exactos de la vista previa actual.",
    eyebrow: "Estado del desarrollo",
    heading: "Qué funciona ahora. Qué sigue pendiente.",
    lead: "Mostramos la implementación verificada por separado de las capacidades objetivo, el soporte de plataforma y la preparación para el lanzamiento.",
    panelLabel: "● verificado localmente",
    panelTitle: "Resumen actual",
    panelBody:
      "Replay y continuación de conversaciones, además de un ciclo de vida protegido del runtime local.",
    platform: "macOS arm64 · compilación especial de desarrollo",
  },
  snapshot: {
    eyebrow: "Resumen de implementación",
    heading: "La base está montada y verificada localmente.",
    lead: "Esto no demuestra soporte operativo para macOS, Windows o Linux.",
    cards: [
      { title: "Shell de escritorio", body: "Tauri 2 · Vue 3 · TypeScript" },
      { title: "Almacenamiento", body: "SQLite · diario · proyecciones" },
      {
        title: "Conversación",
        body: "Crear · generar · reproducir · continuar",
      },
      {
        title: "Runtime local",
        body: "Socket protegido · sesión · reinicio",
      },
    ],
  },
  boundaries: {
    eyebrow: "Límites de estado",
    heading: "Implementado no significa lanzado.",
    lead: "Toda capacidad futura sigue siendo un plan hasta que se verifique por separado.",
    current: {
      label: "Actual",
      title: "Implementado",
      items: [
        "Ciclo de vida y handshake autenticado",
        "Diario de eventos duradero",
        "Replay y continuación de conversaciones",
        "Estados seguros de reintento y sincronización",
      ],
    },
    open: {
      label: "Pendiente",
      title: "Aún no verificado",
      items: [
        "Proveedor y herramientas reales",
        "TaskRun / Audit en la aplicación de escritorio",
        "Windows/Linux y una compilación operativa de macOS",
        "Instaladores firmados y lanzamiento público",
      ],
    },
  },
  platforms: {
    eyebrow: "Límite de plataforma",
    heading: "Una plataforma objetivo no es una plataforma compatible.",
    lead: "El estado cambia solo después de la verificación a nivel de paquete de un candidato de lanzamiento específico.",
    items: [
      { name: "macOS arm64", status: "● verificado localmente" },
      { name: "Windows", status: "● requiere cualificación" },
      { name: "Linux", status: "● requiere cualificación" },
    ],
  },
} satisfies StatusPageCopy;
