<script setup lang="ts">
import { computed } from "vue";
import type { MockupCopy } from "../../lib/i18n/types";

const props = defineProps<{ copy: MockupCopy }>();
const trailingRailItems = computed(() => props.copy.railItems[1].split(" · "));
</script>

<template>
  <aside
    class="mockup"
    :aria-label="copy.ariaLabel"
  >
    <div class="mockup-top">
      <span>{{ copy.topLabel }}</span><span class="status-dot">{{ copy.status }}</span>
    </div>
    <div class="mockup-body">
      <div class="mockup-rail">
        {{ copy.railTitle }}<b>{{ copy.project }}</b>{{ copy.railItems[0] }}<br>
        <template
          v-for="(item, index) in trailingRailItems"
          :key="item"
        >
          <br v-if="index > 0">{{ item }}
        </template>
      </div>
      <div class="mockup-chat">
        <h3>{{ copy.chatTitle }}</h3>
        <div class="bubble">
          <b>{{ copy.state }}</b>{{ copy.message }}
        </div>
        <div class="input-line">
          {{ copy.input }}
        </div>
      </div>
    </div>
  </aside>
</template>
