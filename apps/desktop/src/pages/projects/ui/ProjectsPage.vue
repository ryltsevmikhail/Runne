<script setup lang="ts">
import { Clock3, FolderOpen, Plus } from 'lucide-vue-next'
</script>

<template>
  <section
    class="projects-page"
    aria-labelledby="projects-title"
  >
    <header class="page-header">
      <div>
        <h1 id="projects-title">
          Projects
        </h1>
        <p>Choose a workspace and continue where you left off.</p>
      </div>
      <button
        class="primary-button"
        type="button"
      >
        <Plus
          :size="16"
          aria-hidden="true"
        />
        New project
      </button>
    </header>

    <div class="content-section">
      <div class="section-heading">
        <h2>Recent</h2>
        <span>Local workspaces</span>
      </div>

      <div class="project-grid">
        <button
          class="project-card project-card--open"
          type="button"
        >
          <span class="project-icon">
            <FolderOpen
              :size="21"
              aria-hidden="true"
            />
          </span>
          <span class="project-copy">
            <strong>Open local project</strong>
            <small>Select a folder on this device</small>
          </span>
          <span class="project-arrow">→</span>
        </button>
      </div>
    </div>

    <div class="empty-state">
      <span class="empty-icon">
        <Clock3
          :size="24"
          aria-hidden="true"
        />
      </span>
      <h2>No recent projects</h2>
      <p>Your local projects will appear here after you open them.</p>
    </div>
  </section>
</template>
