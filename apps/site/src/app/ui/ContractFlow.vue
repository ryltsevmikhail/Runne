<script setup lang="ts">
import { contract } from "../content";
</script>

<template>
  <section id="architecture" class="contract">
    <div class="wrap">
      <div class="contract-head">
        <div>
          <p class="eyebrow cobalt">{{ contract.eyebrow }}</p>
          <h2>{{ contract.headline }}</h2>
          <p class="lead">{{ contract.body }}</p>
        </div>
        <ul class="contract-notes">
          <li v-for="note in contract.notes" :key="note">{{ note }}</li>
        </ul>
      </div>
      <div class="flow">
        <template v-for="(node, i) in contract.nodes" :key="node.title">
          <article class="flow-node" :class="node.tone">
            <h3>{{ node.title }}</h3>
            <p class="mono">{{ node.caption }}</p>
          </article>
          <span v-if="i < contract.nodes.length - 1" class="flow-arrow" aria-hidden="true">→</span>
        </template>
      </div>
    </div>
  </section>
</template>
