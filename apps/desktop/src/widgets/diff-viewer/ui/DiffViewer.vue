<script setup lang="ts">
import type { WorkspaceDiff, WorkspaceDiffLineKind } from '@/entities/diff'
import { translate } from '@/shared/i18n'

defineProps<{
  diff: WorkspaceDiff | null
  loading: boolean
  error: boolean
}>()

function lineClass(kind: WorkspaceDiffLineKind): string {
  return `diff-viewer__line--${kind}`
}
</script>

<template>
  <div
    class="diff-viewer"
    :aria-label="translate('diff.workspaceDiff')"
  >
    <p
      v-if="loading"
      class="diff-viewer__status"
      aria-live="polite"
    >
      {{ translate('diff.loading') }}
    </p>
    <p
      v-else-if="error"
      class="diff-viewer__status"
      role="alert"
    >
      {{ translate('diff.unavailable') }}
    </p>
    <p
      v-else-if="diff === null"
      class="diff-viewer__status"
    >
      {{ translate('diff.selectFile') }}
    </p>
    <div
      v-else
      class="diff-viewer__content"
    >
      <p
        v-if="diff.truncated"
        class="diff-viewer__notice"
        role="status"
      >
        {{ translate('diff.truncated') }}
      </p>
      <section
        v-for="(hunk, hunkIndex) in diff.hunks"
        :key="`${diff.path}-${hunkIndex}`"
        class="diff-viewer__hunk"
        :aria-label="translate('diff.hunk', { index: hunkIndex + 1 })"
      >
        <p class="diff-viewer__range">
          -{{ hunk.oldStart }},{{ hunk.oldLines }} +{{ hunk.newStart }},{{ hunk.newLines }}
        </p>
        <p
          v-for="(line, lineIndex) in hunk.lines"
          :key="`${hunkIndex}-${lineIndex}`"
          class="diff-viewer__line"
          :class="lineClass(line.kind)"
        >
          <span aria-hidden="true">{{ line.kind === 'added' ? '+' : line.kind === 'removed' ? '-' : ' ' }}</span>
          <code>{{ line.text }}</code>
        </p>
      </section>
    </div>
  </div>
</template>

<style scoped>
.diff-viewer { min-height: 12rem; overflow: auto; }
.diff-viewer__status, .diff-viewer__notice { padding: 1rem; color: var(--gc-text-muted); }
.diff-viewer__notice { color: var(--gc-warning-text, #9a6700); }
.diff-viewer__range { margin: 0; padding: 0.35rem 0.75rem; color: var(--gc-text-muted); background: var(--gc-surface-subtle); font-size: 0.75rem; }
.diff-viewer__line { display: flex; gap: 0.5rem; margin: 0; padding: 0.15rem 0.75rem; white-space: pre; }
.diff-viewer__line code { font: inherit; }
.diff-viewer__line--added { background: color-mix(in srgb, #2da44e 16%, transparent); }
.diff-viewer__line--removed { background: color-mix(in srgb, #cf222e 16%, transparent); }
</style>
