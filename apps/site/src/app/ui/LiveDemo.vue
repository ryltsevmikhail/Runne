<script setup lang="ts">
import { demo } from "../content";
</script>

<template>
  <section id="status" class="live-demo">
    <div class="wrap demo-grid">
      <div class="demo-copy">
        <p class="eyebrow cobalt">{{ demo.eyebrow }}</p>
        <h2>{{ demo.headline }}</h2>
        <p class="lead">{{ demo.body }}</p>
        <p class="demo-chip"><i aria-hidden="true" />{{ demo.chip }}</p>
      </div>
      <div class="demo-interface">
        <div class="demo-head">
          <span class="mono">{{ demo.task }}</span>
          <span class="active-pill">{{ demo.active }}</span>
        </div>
        <ol class="demo-steps">
          <li v-for="step in demo.steps" :key="step.n" :class="{ done: step.done, active: step.active, queued: !step.done && !step.active }">
            <span class="mono step-n">{{ step.n }}</span>
            <span class="step-mark" aria-hidden="true">{{ step.done ? "✓" : step.active ? "◐" : "·" }}</span>
            <strong>{{ step.label }}</strong>
          </li>
        </ol>
        <div class="demo-side">
          <p class="col-label">{{ demo.runState.heading }}</p>
          <dl class="run-metrics">
            <template v-for="metric in demo.runState.metrics" :key="metric.label">
              <dt>{{ metric.label }}</dt>
              <dd class="mono">{{ metric.value }}</dd>
            </template>
          </dl>
        </div>
        <p class="demo-command"><span aria-hidden="true">$</span> {{ demo.command }}</p>
      </div>
    </div>
  </section>
</template>
