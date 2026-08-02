import type { ArchitecturePageCopy } from "../../page-types";

export const architecture = {
  hero: {
    title: "Arquitetura",
    description:
      "O runtime GOCODE é dono do estado, enquanto a interface o controla apenas por meio de um contrato público verificável.",
    eyebrow: "Arquitetura",
    heading: "O runtime é dono do estado. A interface é dona do controle.",
    lead: "GOCODE separa estado autoritativo, contratos públicos e apresentação. O aplicativo desktop não ignora o cliente do runtime nem importa detalhes internos da implementação.",
    status: "● fonte única de verdade",
    cards: [
      { title: "Vue / Tauri", body: "controle" },
      { title: "runtime-client", body: "contrato público" },
      { title: "Runtime GOCODE", body: "estado autoritativo" },
      { title: "Diário de eventos SQLite", body: "registro durável" },
    ],
  },
  flow: {
    eyebrow: "Fluxo de dados",
    heading: "Um comando atravessa um limite verificável.",
    lead: "Não há atalho via HTTP, armazenamento ou estado da interface.",
    items: [
      { title: "Comando", body: "CLI / aplicativo desktop" },
      { title: "runtime-client", body: "autenticação" },
      { title: "RuntimeHandle", body: "admissão e execução" },
      { title: "Diário de eventos", body: "commit de eventos" },
      { title: "Projeção", body: "DTOs sanitizados" },
    ],
  },
  boundary: {
    eyebrow: "Limite de responsabilidades",
    heading: "A interface lê uma projeção. O runtime decide.",
    lead: "Credenciais e endpoint permanecem no host Tauri. O Vue recebe DTOs tipados sem segredos ou erros brutos.",
    desktop: {
      title: "Aplicativo desktop",
      body: "Intenção do usuário · apresentação · repetição",
      status: "não é dono do estado",
    },
    runtime: {
      title: "Runtime GOCODE",
      body: "Eventos · cursor · projeções · recuperação",
      status: "estado autoritativo",
    },
  },
  replay: {
    eyebrow: "Replay e continuação",
    heading: "A continuação começa de uma posição confirmada.",
    lead: "O cursor é confirmado atomicamente e duplicatas são tratadas de forma idempotente.",
    steps: [
      { title: "Marca d'água", body: "Captura o limite de eventos disponíveis." },
      { title: "Fluxo de atualização", body: "Retorna eventos até o limite." },
      {
        title: "Commit atômico",
        body: "A projeção e o cursor são armazenados juntos.",
      },
      {
        title: "Continuação ao vivo",
        body: "O fluxo começa sem perder a posição.",
      },
    ],
  },
} satisfies ArchitecturePageCopy;
