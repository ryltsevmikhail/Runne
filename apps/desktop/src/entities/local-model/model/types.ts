/// Metadata-only types for the Local Engine model journey. The
/// renderer never receives filesystem paths or credential material.

/** One installed local model known to the catalog authority. */
export interface LocalModelInstalled {
  readonly manifestDigest: string
  readonly modelId: string
  readonly modelRevision: string
  /** Qualification matrix revision; empty = unqualified. */
  readonly matrixRevision: string
  readonly activeRefs: number
}

/** One staged (built but not yet admitted) candidate. */
export interface LocalModelCandidate {
  readonly candidateId: string
  readonly manifestDigest: string
  readonly modelId: string
  readonly modelRevision: string
  readonly license: string
  readonly artifactDigest: string
  readonly byteLen: number
}

/** Owner form fields required to stage a picked GGUF file. */
export interface LocalModelStageForm {
  readonly modelId: string
  readonly modelRevision: string
  readonly license: string
  readonly provenanceSourceUri: string
  readonly provenancePublisher: string
  readonly provenanceAcquiredAt: string
  readonly minCompatibleRuntime?: string
}
