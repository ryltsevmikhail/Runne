/** Renderer-safe provider catalog. Runtime remains the owner of selection. */

export const PROVIDER_CATALOG = [
  { id: 'deterministic', displayName: 'Deterministic', billing: 'local', support: 'implemented', credential: false, enrollment: false },
  { id: 'anthropic', displayName: 'Anthropic', billing: 'payg', support: 'planned', credential: true, enrollment: true },
  { id: 'ant-ling', displayName: 'Ant Ling', billing: 'payg', support: 'planned', credential: true, enrollment: true },
  { id: 'azure-openai-responses', displayName: 'Azure OpenAI Responses', billing: 'payg', support: 'planned', credential: true, enrollment: true },
  { id: 'openai', displayName: 'OpenAI', billing: 'payg', support: 'implemented', credential: true, enrollment: true },
  { id: 'openai-background', displayName: 'OpenAI Background Responses', billing: 'payg', support: 'implemented', credential: true, enrollment: true },
  { id: 'deepseek', displayName: 'DeepSeek', billing: 'payg', support: 'implemented', credential: true, enrollment: true },
  { id: 'nvidia', displayName: 'NVIDIA NIM', billing: 'payg', support: 'planned', credential: true, enrollment: true },
  { id: 'google', displayName: 'Google Gemini', billing: 'payg', support: 'planned', credential: true, enrollment: true },
  { id: 'amazon-bedrock', displayName: 'Amazon Bedrock', billing: 'payg', support: 'planned', credential: true, enrollment: true },
  { id: 'mistral', displayName: 'Mistral', billing: 'payg', support: 'implemented', credential: true, enrollment: true },
  { id: 'groq', displayName: 'Groq', billing: 'payg', support: 'planned', credential: true, enrollment: true },
  { id: 'cerebras', displayName: 'Cerebras', billing: 'payg', support: 'planned', credential: true, enrollment: true },
  { id: 'cloudflare-ai-gateway', displayName: 'Cloudflare AI Gateway', billing: 'payg', support: 'planned', credential: true, enrollment: true },
  { id: 'cloudflare-workers-ai', displayName: 'Cloudflare Workers AI', billing: 'payg', support: 'planned', credential: true, enrollment: true },
  { id: 'xai', displayName: 'xAI', billing: 'payg', support: 'planned', credential: true, enrollment: true },
  { id: 'openrouter', displayName: 'OpenRouter', billing: 'payg', support: 'planned', credential: true, enrollment: true },
  { id: 'vercel-ai-gateway', displayName: 'Vercel AI Gateway', billing: 'payg', support: 'planned', credential: true, enrollment: true },
  { id: 'zai', displayName: 'Z.AI', billing: 'subscription', support: 'planned', credential: true, enrollment: true },
  { id: 'zai-coding-cn', displayName: 'Z.AI Coding CN', billing: 'subscription', support: 'planned', credential: true, enrollment: true },
  { id: 'openai-codex', displayName: 'OpenAI Codex', billing: 'subscription', support: 'planned', credential: true, enrollment: true },
  { id: 'github-copilot', displayName: 'GitHub Copilot', billing: 'subscription', support: 'planned', credential: true, enrollment: true },
  { id: 'google-vertex', displayName: 'Google Vertex AI', billing: 'payg', support: 'planned', credential: true, enrollment: true },
  { id: 'opencode', displayName: 'OpenCode Zen', billing: 'payg', support: 'planned', credential: true, enrollment: true },
  { id: 'opencode-go', displayName: 'OpenCode Go', billing: 'subscription', support: 'implemented', credential: true, enrollment: true },
  { id: 'radius', displayName: 'Radius', billing: 'subscription', support: 'planned', credential: true, enrollment: true },
  { id: 'huggingface', displayName: 'Hugging Face', billing: 'payg', support: 'planned', credential: true, enrollment: true },
  { id: 'fireworks', displayName: 'Fireworks', billing: 'payg', support: 'implemented', credential: true, enrollment: true },
  { id: 'together', displayName: 'Together AI', billing: 'payg', support: 'planned', credential: true, enrollment: true },
  { id: 'baseten', displayName: 'Baseten', billing: 'payg', support: 'planned', credential: true, enrollment: true },
  { id: 'kimi-coding', displayName: 'Kimi For Coding', billing: 'subscription', support: 'planned', credential: true, enrollment: true },
  { id: 'minimax', displayName: 'MiniMax', billing: 'payg', support: 'planned', credential: true, enrollment: true },
  { id: 'minimax-cn', displayName: 'MiniMax (China)', billing: 'payg', support: 'planned', credential: true, enrollment: true },
  { id: 'moonshotai', displayName: 'Moonshot AI', billing: 'payg', support: 'planned', credential: true, enrollment: true },
  { id: 'moonshotai-cn', displayName: 'Moonshot AI CN', billing: 'payg', support: 'planned', credential: true, enrollment: true },
  { id: 'qwen-token-plan', displayName: 'Qwen Token Plan', billing: 'subscription', support: 'planned', credential: true, enrollment: true },
  { id: 'qwen-token-plan-individual', displayName: 'Qwen Token Plan (Individual)', billing: 'subscription', support: 'planned', credential: true, enrollment: true },
  { id: 'qwen-token-plan-cn', displayName: 'Qwen Token Plan (China)', billing: 'subscription', support: 'planned', credential: true, enrollment: true },
  { id: 'xiaomi', displayName: 'Xiaomi MiMo', billing: 'payg', support: 'planned', credential: true, enrollment: true },
  { id: 'xiaomi-token-plan-cn', displayName: 'Xiaomi MiMo Token Plan (China)', billing: 'subscription', support: 'planned', credential: true, enrollment: true },
  { id: 'xiaomi-token-plan-ams', displayName: 'Xiaomi MiMo Token Plan (Amsterdam)', billing: 'subscription', support: 'planned', credential: true, enrollment: true },
  { id: 'xiaomi-token-plan-sgp', displayName: 'Xiaomi MiMo Token Plan (Singapore)', billing: 'subscription', support: 'planned', credential: true, enrollment: true },
] as const

export type ProviderCatalogEntry = (typeof PROVIDER_CATALOG)[number]
export type ProviderId = ProviderCatalogEntry['id']
export type ProviderCredentialProvider = Extract<ProviderCatalogEntry, { credential: true }>['id']
export type ProviderBilling = ProviderCatalogEntry['billing']
export type ProviderSupport = ProviderCatalogEntry['support']

export const CREDENTIAL_PROVIDER_IDS = PROVIDER_CATALOG
  .filter((entry): entry is Extract<ProviderCatalogEntry, { enrollment: true }> => entry.enrollment)
  .map(entry => entry.id) as readonly ProviderCredentialProvider[]

export function providerDefinition(providerId: string): ProviderCatalogEntry | undefined {
  return PROVIDER_CATALOG.find(entry => entry.id === providerId)
}

export function isProviderId(value: unknown): value is ProviderId {
  return typeof value === 'string' && providerDefinition(value) !== undefined
}

export function isCredentialProvider(value: unknown): value is ProviderCredentialProvider {
  const definition = typeof value === 'string' ? providerDefinition(value) : undefined
  return definition?.credential === true
}

export function isEnrollableProvider(value: unknown): value is ProviderCredentialProvider {
  const definition = typeof value === 'string' ? providerDefinition(value) : undefined
  return definition?.enrollment === true
}

export function providerDisplayName(providerId: ProviderId): string {
  return providerDefinition(providerId)?.displayName ?? providerId
}
