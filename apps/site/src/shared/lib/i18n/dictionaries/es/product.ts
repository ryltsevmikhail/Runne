import type { ProductPageCopy } from "../../page-types";

export const product = {
  hero: {
    title: "Producto",
    description:
      "GOCODE reúne el proyecto local, la conversación y el estado del runtime en una sola aplicación de escritorio.",
    eyebrow: "Producto",
    heading: "Un centro de control para trabajar con agentes de AI.",
    lead: "Abre un proyecto local, continúa una conversación y retómala después de reiniciar. El runtime GOCODE, no la ventana de la aplicación, conserva el estado autoritativo.",
    boundary:
      "● Vista previa: macOS arm64, proveedor determinista, sin ejecución de modelos en producción.",
    cta: "Unirse a la lista de espera",
    mockup: {
      ariaLabel: "Interfaz de proyecto local de GOCODE",
      topLabel: "GOCODE · proyecto local",
      status: "● runtime listo",
      railTitle: "PROYECTOS",
      project: "gocode",
      railItems: ["crates", "docs"],
      chatTitle: "Conversación con el agente",
      state: "LEAD · RESTAURADO",
      message: "La conversación continuó desde el estado confirmado sin duplicados.",
      input: "Pide a GOCODE que trabaje en el proyecto…",
    },
  },
  workflow: {
    eyebrow: "Flujo de trabajo",
    heading: "De una carpeta local a una conversación continua.",
    lead: "La carpeta permanece en el dispositivo. GOCODE almacena un registro local del proyecto y el estado del trabajo.",
    steps: [
      { title: "Abre el proyecto", body: "Elige una carpeta local en el dispositivo." },
      {
        title: "Inicia una conversación",
        body: "Envía una solicitud en la conversación local actual.",
      },
      {
        title: "Confirma el estado",
        body: "Los eventos se persisten en el diario del runtime.",
      },
      {
        title: "Sigue trabajando",
        body: "Vuelve después de reiniciar o desconectarte.",
      },
    ],
  },
  workspace: {
    eyebrow: "Espacio de trabajo",
    heading: "Proyecto, conversación y estado del runtime, en una ventana.",
    lead: "La interfaz muestra solo datos tipados y saneados. Los secretos y errores sin procesar del runtime nunca llegan al modelo de vista.",
    items: [
      {
        title: "Proyectos locales",
        body: "Carpetas de trabajo recientes y selección explícita del proyecto.",
      },
      {
        title: "Conversación continuable",
        body: "Replay, feed en vivo y sincronización segura.",
      },
      {
        title: "Estado del runtime",
        body: "Inicio, preparación, reinicio, degradación y recuperación.",
      },
    ],
  },
} satisfies ProductPageCopy;
