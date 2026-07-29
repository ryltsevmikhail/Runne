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
        <p>No runtime profile configured. Desktop will not guess an endpoint.</p>
      </div>
    </header>

    <GcAlert
      level="info"
      title="Runtime offline"
    >
      <GcBadge status="offline">
        Unconfigured
      </GcBadge>
    </GcAlert>
  </section>
</template>
