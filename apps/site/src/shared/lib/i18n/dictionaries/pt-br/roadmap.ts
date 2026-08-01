import type { RoadmapPageCopy } from "../../page-types";

export const roadmap = {
  hero: {
    title: "Roteiro",
    description:
      "O roteiro do GOCODE coloca a evidência antes do lançamento, sem promessas de disponibilidade não verificadas.",
    eyebrow: "Roteiro",
    heading: "Evidência primeiro. Lançamento depois.",
    lead: "Uma data não torna uma capacidade pronta. Avançar requer implementação, evidência de plataforma e revisão independente.",
    panelLabel: "● prévia",
    panelTitle: "Limite atual",
    panelBody:
      "Um caminho local para macOS arm64 foi verificado em uma build especial de desenvolvimento.",
    warning: "⚠ Isto não é prontidão operacional nem um lançamento público.",
  },
  stages: {
    eyebrow: "Três etapas",
    heading: "Cada etapa se encerra com verificação.",
    lead: "Não publicamos cronogramas que ainda não existem.",
    cards: [
      {
        label: "01 · verificado localmente",
        title: "Base do runtime concluída",
        body: "Conversa durável, replay e continuação, e recuperação após reinicialização.\nmacOS arm64 · build especial de desenvolvimento",
      },
      {
        label: "02 · próximo",
        title: "Processos de agentes reais",
        body: "Um provedor real, fluxos TaskRun/Audit e um espaço de trabalho ampliado.\ncritério: contratos + recuperação",
      },
      {
        label: "03 · antes do lançamento público",
        title: "Prontidão operacional",
        body: "Isolamento nativo, assinatura, qualificação de Windows/Linux e um parecer independente.",
      },
    ],
  },
  exclusions: {
    eyebrow: "O que ainda não prometemos",
    heading: "Um plano não é uma lista de capacidades disponíveis.",
    items: [
      {
        title: "Sem execução em produção com um modelo real",
        body: "O provedor atual é determinístico e local.",
      },
      {
        title: "Sem download público",
        body: "Assinatura, instalador e qualificação estão incompletos.",
      },
      {
        title: "Sem suporte multiplataforma verificado",
        body: "Windows/Linux exigem evidência separada.",
      },
    ],
  },
  legend: {
    eyebrow: "Como ler os status",
    heading: "A cor identifica o tipo de evidência.",
    cards: [
      {
        label: "● verificado localmente",
        title: "",
        body: "Existem implementação e evidência exata para o ambiente indicado.",
      },
      {
        label: "● próximo",
        title: "",
        body: "A parte está definida, mas ainda não é uma capacidade disponível.",
      },
      {
        label: "● antes do lançamento público",
        title: "",
        body: "Uma condição obrigatória de qualificação e lançamento.",
      },
    ],
  },
} satisfies RoadmapPageCopy;
