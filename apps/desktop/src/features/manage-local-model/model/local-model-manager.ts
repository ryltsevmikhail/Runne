import {
  admitLocalModel,
  discardLocalModel,
  listLocalModels,
  type LocalModelInstalled,
} from '../../../entities/local-model/api/local-models'

type Invoke = (command: string, args?: Record<string, unknown>) => Promise<unknown>

/// Owner-side manager for the Local Engine model journey:
/// stage (picker + license form) → admit → list → discard.
export class LocalModelManager {
  private readonly invoke: Invoke
  private installed: LocalModelInstalled[] = []

  constructor(invoke: Invoke) {
    this.invoke = invoke
  }

  async refresh(): Promise<LocalModelInstalled[]> {
    this.installed = await listLocalModels(this.invoke)
    return this.installed
  }

  installedModels(): readonly LocalModelInstalled[] {
    return this.installed
  }

  async admit(candidateId: string, licenseDigest: string): Promise<LocalModelInstalled> {
    const installed = await admitLocalModel(candidateId, licenseDigest, this.invoke)
    this.installed = [...this.installed, installed]
    return installed
  }

  async discard(candidateId: string): Promise<boolean> {
    return discardLocalModel(candidateId, this.invoke)
  }
}
