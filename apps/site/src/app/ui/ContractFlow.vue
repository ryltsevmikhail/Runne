<script setup lang="ts">
import { useSite } from "../useSite";
const { c } = useSite();
</script>

<template>
  <section id="architecture" class="contract">
    <div class="wrap">
      <div class="contract-head">
        <div>
          <p class="eyebrow cobalt">{{ c.contract.eyebrow }}</p>
          <h2>{{ c.contract.headline }}</h2>
          <p class="lead">{{ c.contract.body }}</p>
        </div>
        <ul class="contract-notes">
          <li v-for="note in c.contract.notes" :key="note">{{ note }}</li>
        </ul>
      </div>
      <div class="flow">
        <template v-for="(node, i) in c.contract.nodes" :key="node.title">
          <article class="flow-node" :class="node.tone">
            <h3>{{ node.title }}</h3>
            <p class="mono">{{ node.caption }}</p>
          </article>
          <span v-if="i < c.contract.nodes.length - 1" class="flow-arrow" aria-hidden="true">→</span>
        </template>
      </div>
    </div>
  </section>
</template>
