import type { HomePageCopy } from "../../page-types";

export const home = {
  hero: {
    title: "Agentes de programação com AI — sob seu controle",
    description:
      "GOCODE é um centro de controle desktop para agentes de AI, apoiado por um runtime local com limites verificáveis.",
    eyebrow: "Prévia",
    heading: "Agentes de programação com AI — sob seu controle.",
    lead: "GOCODE é um centro de controle desktop e um runtime Rust neutro a provedores. Ele mantém o estado autoritativo e restaura a conversa após uma reinicialização.",
    cta: "Entrar na lista de espera",
    mockup: {
      ariaLabel: "Exemplo da interface do GOCODE",
      topLabel: "GOCODE · runtime local",
      status: "● runtime pronto",
      railTitle: "PROJETOS",
      project: "agent-runtime",
      railItems: ["crates", "docs · testes"],
      chatTitle: "Conversa com o agente",
      state: "LEAD · RESTAURADO",
      message:
        "Verificou os limites do runtime e preparou um plano seguro de alterações.",
      input: "Peça ao GOCODE para trabalhar no projeto…",
    },
  },
  why: {
    eyebrow: "Por que GOCODE",
    heading: "Um fluxo de trabalho com agentes não deve desaparecer junto com a janela.",
    lead: "GOCODE separa um aplicativo desktop conveniente do estado autoritativo. O trabalho continua como parte do runtime, não como uma sessão de UI frágil.",
    items: [
      {
        title: "Uma reinicialização não encerra o processo",
        body: "A conversa e os eventos são restaurados de um fluxo durável.",
      },
      {
        title: "A interface não é dona da verdade",
        body: "O runtime expõe somente projeções confirmadas.",
      },
      {
        title: "Estado incerto bloqueia ações",
        body: "Uma alteração só começa após confirmação.",
      },
    ],
  },
  architecture: {
    eyebrow: "Arquitetura",
    heading: "Um runtime. Uma fonte de verdade.",
    lead: "O aplicativo desktop chama somente as APIs públicas do runtime-client e do contrato. Os detalhes de implementação permanecem atrás do limite do processo.",
    flow: [
      { title: "App", body: "interface" },
      { title: "Host Tauri", body: "limite de confiança" },
      { title: "runtime-client", body: "API pública" },
      { title: "Runtime GOCODE", body: "estado autoritativo" },
      { title: "Diário de eventos", body: "registro durável" },
    ],
  },
  preview: {
    eyebrow: "Prévia",
    heading: "Comprovando a base antes de conectar modelos reais.",
    lead: "Evidência atual: macOS arm64 · build especial de desenvolvimento.",
    verified: {
      label: "● verificado",
      title: "Funciona na versão atual",
      items: [
        "Ciclo de vida autenticado do runtime",
        "Diário durável e replay de eventos",
        "Restauração e continuação de conversas",
        "Shell desktop Vue + Tauri",
      ],
    },
    review: {
      label: "● em análise",
      title: "Limites honestos da versão",
      items: [
        "Provedor determinístico em vez de modelos reais",
        "Sem instalador assinado",
        "Não está pronto para operar em Windows/Linux",
      ],
    },
  },
  roadmap: {
    eyebrow: "Roteiro",
    heading: "Evidência primeiro. Escala depois.",
    lead: "Sem promessas de calendário: cada etapa se encerra com critérios de entrega verificáveis.",
    cards: [
      {
        label: "01 · etapa atual",
        title: "Base do runtime concluída",
        body: "Ciclo de vida, diário de eventos, recuperação de conversas e shell desktop.",
      },
      {
        label: "02 · próximo",
        title: "Processos de agentes reais",
        body: "Um provedor real, fluxos TaskRun/Audit e um espaço de trabalho ampliado.",
      },
      {
        label: "03 · antes do lançamento",
        title: "Qualificação de prontidão",
        body: "Isolamento nativo, assinatura, qualificação de plataforma e um parecer independente.",
      },
    ],
  },
} satisfies HomePageCopy;
