<script setup lang="ts">
import { useRoute } from "vue-router";

const route = useRoute();
const paymentId = String(route.query.payment_id ?? "");
</script>

<template>
  <div class="page">
    <div class="card" style="max-width: 560px; margin: 60px auto; text-align: center">
      <h2>Платёж принят</h2>
      <p class="muted">
        Оплата прошла успешно. Баланс пополнится автоматически в течение нескольких
        секунд — как только платёжная система подтвердит платёж.
      </p>
      <p v-if="paymentId" class="muted mono" style="font-size: 12px">
        платёж: {{ paymentId }}
      </p>
      <RouterLink to="/" class="btn" style="margin-top: 8px">В кабинет</RouterLink>
    </div>
  </div>
</template>
