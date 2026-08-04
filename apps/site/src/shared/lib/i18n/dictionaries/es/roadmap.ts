import type { RoadmapPageCopy } from "../../page-types";

export const roadmap = {
  hero: {
    title: "Hoja de ruta",
    description:
      "La hoja de ruta de GOCODE antepone la evidencia al lanzamiento, sin promesas de disponibilidad sin verificar.",
    eyebrow: "Hoja de ruta",
    heading: "Primero evidencia. Después lanzamiento.",
    lead: "Una fecha no hace que una capacidad esté lista. Avanzar requiere implementación, evidencia de plataforma y una revisión independiente.",
    panelLabel: "● vista previa",
    panelTitle: "Límite actual",
    panelBody:
      "Se ha verificado una ruta local de macOS arm64 en una compilación especial de desarrollo.",
    warning: "⚠ Esto no es preparación operativa ni un lanzamiento público.",
  },
  stages: {
    eyebrow: "Tres etapas",
    heading: "Cada etapa se cierra con verificación.",
    lead: "No publicamos calendarios que todavía no existen.",
    cards: [
      {
        label: "01 · verificado localmente",
        title: "Base del runtime completada",
        body: "Conversación duradera, replay y continuación, y recuperación tras reiniciar.\nmacOS arm64 · compilación especial de desarrollo",
      },
      {
        label: "02 · siguiente",
        title: "Procesos de agentes reales",
        body: "Un proveedor real, flujos TaskRun/Audit y un espacio de trabajo ampliado.\ncriterio: contratos + recuperación",
      },
      {
        label: "03 · antes del lanzamiento público",
        title: "Preparación operativa",
        body: "Aislamiento nativo, firma, cualificación de Windows/Linux y un dictamen independiente.",
      },
    ],
  },
  exclusions: {
    eyebrow: "Lo que todavía no prometemos",
    heading: "Un plan no es una lista de capacidades disponibles.",
    items: [
      {
        title: "Sin ejecución en producción con un modelo real",
        body: "El proveedor actual es determinista y local.",
      },
      {
        title: "Sin descarga pública",
        body: "La firma, el instalador y la cualificación están incompletos.",
      },
      {
        title: "Sin soporte multiplataforma verificado",
        body: "Windows/Linux requieren evidencia independiente.",
      },
    ],
  },
  legend: {
    eyebrow: "Cómo leer los estados",
    heading: "El color identifica el tipo de evidencia.",
    cards: [
      {
        label: "● verificado localmente",
        title: "",
        body: "Existe implementación y evidencia exacta para el entorno indicado.",
      },
      {
        label: "● siguiente",
        title: "",
        body: "La parte está definida, pero aún no es una capacidad disponible.",
      },
      {
        label: "● antes del lanzamiento público",
        title: "",
        body: "Una condición obligatoria de cualificación y lanzamiento.",
      },
    ],
  },
} satisfies RoadmapPageCopy;
