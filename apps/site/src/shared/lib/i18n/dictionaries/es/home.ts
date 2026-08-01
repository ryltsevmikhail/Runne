import type { HomePageCopy } from "../../page-types";

export const home = {
  hero: {
    title: "Agentes de programación con AI — bajo tu control",
    description:
      "GOCODE es un centro de control de escritorio para agentes de AI, respaldado por un runtime local con límites verificables.",
    eyebrow: "Vista previa",
    heading: "Agentes de programación con AI — bajo tu control.",
    lead: "GOCODE es un centro de control de escritorio y un runtime Rust neutral respecto a proveedores. Conserva el estado autoritativo y restaura la conversación después de reiniciar.",
    cta: "Unirse a la lista de espera",
    mockup: {
      ariaLabel: "Ejemplo de la interfaz de GOCODE",
      topLabel: "GOCODE · runtime local",
      status: "● runtime listo",
      railTitle: "PROYECTOS",
      project: "agent-runtime",
      railItems: ["crates", "docs · pruebas"],
      chatTitle: "Conversación con el agente",
      state: "LEAD · RESTAURADO",
      message:
        "Se revisaron los límites del runtime y se preparó un plan de cambios seguro.",
      input: "Pide a GOCODE que trabaje en el proyecto…",
    },
  },
  why: {
    eyebrow: "Por qué GOCODE",
    heading: "Un flujo de trabajo con agentes no debería desaparecer con su ventana.",
    lead: "GOCODE separa una aplicación de escritorio cómoda del estado autoritativo. El trabajo continúa como parte del runtime, no como una frágil sesión de UI.",
    items: [
      {
        title: "Reiniciar no termina el proceso",
        body: "La conversación y los eventos se restauran desde un flujo duradero.",
      },
      {
        title: "La interfaz no es dueña de la verdad",
        body: "El runtime expone solo proyecciones confirmadas.",
      },
      {
        title: "El estado incierto bloquea la acción",
        body: "Un cambio comienza solo después de confirmarlo.",
      },
    ],
  },
  architecture: {
    eyebrow: "Arquitectura",
    heading: "Un runtime. Una fuente de verdad.",
    lead: "La aplicación de escritorio llama únicamente a las API públicas del runtime-client y del contrato. Los detalles internos de implementación permanecen tras el límite del proceso.",
    flow: [
      { title: "App", body: "interfaz" },
      { title: "Host Tauri", body: "límite de confianza" },
      { title: "runtime-client", body: "API pública" },
      { title: "Runtime GOCODE", body: "estado autoritativo" },
      { title: "Diario de eventos", body: "registro duradero" },
    ],
  },
  preview: {
    eyebrow: "Vista previa",
    heading: "Probamos la base antes de conectar modelos reales.",
    lead: "Evidencia actual: macOS arm64 · compilación especial de desarrollo.",
    verified: {
      label: "● verificado",
      title: "Funciona en la versión actual",
      items: [
        "Ciclo de vida autenticado del runtime",
        "Diario duradero y replay de eventos",
        "Restauración y continuación de conversaciones",
        "Shell de escritorio Vue + Tauri",
      ],
    },
    review: {
      label: "● en revisión",
      title: "Límites honestos de la versión",
      items: [
        "Proveedor determinista en lugar de modelos reales",
        "Sin instalador firmado",
        "No está listo para operar en Windows/Linux",
      ],
    },
  },
  roadmap: {
    eyebrow: "Hoja de ruta",
    heading: "Primero evidencia. Después escala.",
    lead: "Sin promesas de calendario: cada etapa se cierra con criterios de entrega verificables.",
    cards: [
      {
        label: "01 · etapa actual",
        title: "Base del runtime completada",
        body: "Ciclo de vida, diario de eventos, recuperación de conversaciones y shell de escritorio.",
      },
      {
        label: "02 · siguiente",
        title: "Procesos de agentes reales",
        body: "Un proveedor real, flujos TaskRun/Audit y un espacio de trabajo ampliado.",
      },
      {
        label: "03 · antes del lanzamiento",
        title: "Cualificación de preparación",
        body: "Aislamiento nativo, firma, cualificación de plataforma y un dictamen independiente.",
      },
    ],
  },
} satisfies HomePageCopy;
