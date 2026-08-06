import type { ProductPageCopy } from "../../page-types";

export const product = {
  hero: {
    title: "Produto",
    description:
      "GOCODE reúne o projeto local, a conversa e o estado do runtime em um único aplicativo desktop.",
    eyebrow: "Produto",
    heading: "Um centro de controle para trabalhar com agentes de AI.",
    lead: "Abra um projeto local, continue uma conversa e retome após reiniciar. O runtime GOCODE — e não a janela do aplicativo — mantém o estado autoritativo.",
    boundary:
      "● Prévia: macOS arm64, provedor determinístico, sem execução de modelos em produção.",
    cta: "Entrar na lista de espera",
    mockup: {
      ariaLabel: "Interface de projeto local do GOCODE",
      topLabel: "GOCODE · projeto local",
      status: "● runtime pronto",
      railTitle: "PROJETOS",
      project: "gocode",
      railItems: ["crates", "docs"],
      chatTitle: "Conversa com o agente",
      state: "LEAD · RESTAURADO",
      message: "Conversa continuada a partir do estado confirmado, sem duplicatas.",
      input: "Peça ao GOCODE para trabalhar no projeto…",
    },
  },
  workflow: {
    eyebrow: "Fluxo de trabalho",
    heading: "De uma pasta local a uma conversa contínua.",
    lead: "A pasta permanece no dispositivo. O GOCODE armazena um registro local do projeto e o estado do trabalho.",
    steps: [
      { title: "Abra o projeto", body: "Escolha uma pasta local no dispositivo." },
      {
        title: "Inicie uma conversa",
        body: "Envie uma solicitação na conversa local atual.",
      },
      {
        title: "Confirme o estado",
        body: "Os eventos são persistidos no diário do runtime.",
      },
      {
        title: "Continue trabalhando",
        body: "Retorne após uma reinicialização ou desconexão.",
      },
    ],
  },
  workspace: {
    eyebrow: "Espaço de trabalho",
    heading: "Projeto, conversa e estado do runtime — em uma janela.",
    lead: "A interface mostra apenas dados tipados e sanitizados. Segredos e erros brutos do runtime nunca chegam ao modelo de visualização.",
    items: [
      {
        title: "Projetos locais",
        body: "Pastas de trabalho recentes e seleção explícita de projeto.",
      },
      {
        title: "Conversa continuável",
        body: "Replay, feed ao vivo e sincronização segura.",
      },
      {
        title: "Estado do runtime",
        body: "Inicialização, prontidão, reinício, degradação e recuperação.",
      },
    ],
  },
} satisfies ProductPageCopy;
