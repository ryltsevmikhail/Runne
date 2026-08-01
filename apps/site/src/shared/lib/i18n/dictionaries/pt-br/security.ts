import type { SecurityPageCopy } from "../../page-types";

export const security = {
  hero: {
    title: "Segurança",
    description:
      "Estado incerto não recebe permissão para agir: os limites de segurança do GOCODE são verificáveis.",
    eyebrow: "Segurança",
    heading: "Estado incerto não recebe permissão para agir.",
    lead: "GOCODE constrói um limite local com limites de confiança explícitos, verificações de integridade e encerramento seguro quando a evidência é insuficiente.",
    panelEyebrow: "Limite local",
    panelBody: "Credenciais e endpoint não são repassados à interface.",
  },
  trust: {
    eyebrow: "Mapa de confiança",
    heading: "Cada limite sabe em que confiar.",
    lead: "Verificações de proprietário, canal e integridade ocorrem antes de mudanças de estado.",
    cards: [
      {
        title: "Interface",
        body: "Recebe somente dados tipados e sanitizados.",
        label: "não armazena segredos",
      },
      {
        title: "Perfil local",
        body: "Na prévia Unix/macOS, verifica o proprietário, o modo de arquivo e o endereço de loopback.",
        label: "Windows: negar até ACL nativa",
      },
      {
        title: "Diário de eventos",
        body: "Verifica ordenação, integridade e cursor.",
        label: "registro durável",
      },
    ],
  },
  mechanisms: {
    eyebrow: "Mecanismos verificáveis",
    heading: "A proteção é construída com recusas concretas.",
    lead: "Nenhum item isolado substitui uma futura revisão de segurança independente.",
    cards: [
      {
        title: "Integridade do replay",
        body: "Cursor HMAC, marca d'água e validação de sequência.",
      },
      {
        title: "Recuperação atômica",
        body: "Projeção e cursor são confirmados antes de reconhecer a entrega.",
      },
      {
        title: "Inicialização insegura bloqueada",
        body: "O lançamento de processos é rejeitado até que exista um perfil Phase 6B certificado.",
      },
      {
        title: "Broker de segredos",
        body: "Verifica autorização, versão, disponibilidade e revogação.",
      },
      {
        title: "Idempotência",
        body: "A reentrega não cria estado duplicado.",
      },
      {
        title: "Provedor sem autoridade",
        body: "O provedor determinístico atual não tem acesso à rede, a arquivos ou a processos.",
      },
    ],
  },
  boundary: {
    eyebrow: "Limite honesto",
    heading: "Isto não é uma certificação de segurança operacional.",
    lead: "O isolamento nativo da Phase 6B, a qualificação para Windows/Linux, provedores reais e uma revisão independente ainda não estão concluídos.",
    items: [
      "Isolamento nativo",
      "Qualificação multiplataforma",
      "Parecer final independente",
    ],
    roadmapCta: "Ver roteiro",
  },
} satisfies SecurityPageCopy;
