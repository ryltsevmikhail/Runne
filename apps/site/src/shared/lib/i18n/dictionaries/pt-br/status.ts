import type { StatusPageCopy } from "../../page-types";

export const status = {
  hero: {
    title: "Status de desenvolvimento",
    description:
      "Evidência verificada da implementação do GOCODE e limites exatos da prévia atual.",
    eyebrow: "Status de desenvolvimento",
    heading: "O que funciona agora. O que ainda está por vir.",
    lead: "Mostramos a implementação verificada separadamente de capacidades-alvo, suporte de plataforma e prontidão para lançamento.",
    panelLabel: "● verificado localmente",
    panelTitle: "Panorama atual",
    panelBody:
      "Replay e continuação de conversas, além de um ciclo de vida protegido do runtime local.",
    platform: "macOS arm64 · build especial de desenvolvimento",
  },
  snapshot: {
    eyebrow: "Panorama da implementação",
    heading: "A base está montada e verificada localmente.",
    lead: "Isto não é evidência de suporte operacional para macOS, Windows ou Linux.",
    cards: [
      { title: "Shell desktop", body: "Tauri 2 · Vue 3 · TypeScript" },
      { title: "Armazenamento", body: "SQLite · diário · projeções" },
      {
        title: "Conversa",
        body: "Criar · gerar · reproduzir · continuar",
      },
      {
        title: "Runtime local",
        body: "Socket protegido · sessão · reinicialização",
      },
    ],
  },
  boundaries: {
    eyebrow: "Limites de status",
    heading: "Implementado não significa lançado.",
    lead: "Toda capacidade futura permanece um plano até ser verificada separadamente.",
    current: {
      label: "Atual",
      title: "Implementado",
      items: [
        "Ciclo de vida e handshake autenticado",
        "Diário de eventos durável",
        "Replay e continuação de conversas",
        "Estados seguros de repetição e sincronização",
      ],
    },
    open: {
      label: "Em aberto",
      title: "Ainda não verificado",
      items: [
        "Provedor e ferramentas reais",
        "TaskRun / Audit no aplicativo desktop",
        "Windows/Linux e uma build operacional de macOS",
        "Instaladores assinados e lançamento público",
      ],
    },
  },
  platforms: {
    eyebrow: "Limite de plataforma",
    heading: "Uma plataforma-alvo não é uma plataforma com suporte.",
    lead: "O status muda somente após verificação no nível do pacote de um candidato específico a lançamento.",
    items: [
      { name: "macOS arm64", status: "● verificado localmente" },
      { name: "Windows", status: "● requer qualificação" },
      { name: "Linux", status: "● requer qualificação" },
    ],
  },
} satisfies StatusPageCopy;
