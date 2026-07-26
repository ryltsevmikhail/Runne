<script setup lang="ts">
import { FolderKanban, Settings } from 'lucide-vue-next'
</script>

<template>
  <div class="app-shell">
    <aside class="sidebar">
      <div
        class="brand"
        aria-label="GOCODE home"
      >
        <span class="brand-mark">G</span>
        <span>GOCODE</span>
      </div>

      <nav aria-label="Primary">
        <RouterLink
          class="nav-item"
          to="/"
        >
          <FolderKanban
            :size="17"
            aria-hidden="true"
          />
          <span>Projects</span>
        </RouterLink>
        <RouterLink
          class="nav-item"
          to="/settings/runtimes"
        >
          <Settings
            :size="17"
            aria-hidden="true"
          />
          <span>Settings</span>
        </RouterLink>
      </nav>
    </aside>

    <main class="workspace">
      <RouterView />
    </main>
  </div>
</template>
