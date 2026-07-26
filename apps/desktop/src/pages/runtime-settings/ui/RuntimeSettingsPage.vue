<script setup lang="ts">
import { GcAlert, GcBadge } from '@gocode/product/shared/ui'
</script>

<template>
  <section aria-labelledby="runtime-settings-title">
    <header class="page-header">
      <div>
        <h1 id="runtime-settings-title">
          Runtime
        </h1>
        <p>Runtime integration is unavailable until the canonical profile is frozen.</p>
      </div>
    </header>

    <GcAlert
      level="info"
      title="Runtime offline"
    >
      <GcBadge status="offline">
        Contract pending
      </GcBadge>
    </GcAlert>
  </section>
</template>
