import type { ArchitecturePageCopy } from "../../page-types";

export const architecture = {
  hero: {
    title: "Arquitectura",
    description:
      "El runtime de GOCODE es dueño del estado, mientras que la interfaz lo controla únicamente mediante un contrato público verificable.",
    eyebrow: "Arquitectura",
    heading: "El runtime es dueño del estado. La interfaz es dueña del control.",
    lead: "GOCODE separa el estado autoritativo, los contratos públicos y la presentación. La aplicación de escritorio no evita el cliente del runtime ni importa detalles internos de implementación.",
    status: "● fuente única de verdad",
    cards: [
      { title: "Vue / Tauri", body: "control" },
      { title: "runtime-client", body: "contrato público" },
      { title: "Runtime GOCODE", body: "estado autoritativo" },
      { title: "Diario de eventos SQLite", body: "registro duradero" },
    ],
  },
  flow: {
    eyebrow: "Flujo de datos",
    heading: "Un comando atraviesa un límite verificable.",
    lead: "No hay atajos a través de HTTP, almacenamiento o estado de la interfaz.",
    items: [
      { title: "Comando", body: "CLI / aplicación de escritorio" },
      { title: "runtime-client", body: "autenticación" },
      { title: "RuntimeHandle", body: "admisión y ejecución" },
      { title: "Diario de eventos", body: "commit de eventos" },
      { title: "Proyección", body: "DTO saneados" },
    ],
  },
  boundary: {
    eyebrow: "Límite de responsabilidades",
    heading: "La interfaz lee una proyección. El runtime decide.",
    lead: "Las credenciales y el endpoint permanecen en el host Tauri. Vue recibe DTO tipados sin secretos ni errores sin procesar.",
    desktop: {
      title: "Aplicación de escritorio",
      body: "Intención del usuario · presentación · reintento",
      status: "no es dueña del estado",
    },
    runtime: {
      title: "Runtime GOCODE",
      body: "Eventos · cursor · proyecciones · recuperación",
      status: "estado autoritativo",
    },
  },
  replay: {
    eyebrow: "Replay y continuación",
    heading: "La continuación comienza desde una posición confirmada.",
    lead: "El cursor se confirma de forma atómica y los duplicados se gestionan de manera idempotente.",
    steps: [
      { title: "Marca de agua", body: "Captura el límite de eventos disponibles." },
      { title: "Flujo de puesta al día", body: "Devuelve eventos hasta el límite." },
      {
        title: "Commit atómico",
        body: "La proyección y el cursor se almacenan juntos.",
      },
      {
        title: "Continuación en vivo",
        body: "El flujo comienza sin perder la posición.",
      },
    ],
  },
} satisfies ArchitecturePageCopy;
