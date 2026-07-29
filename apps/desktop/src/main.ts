import { createApp } from 'vue'
import { createRouter, createWebHistory } from 'vue-router'

import App from './app/App.vue'
import { routes } from './app/router'
import './app/styles/index.css'

const router = createRouter({
  history: createWebHistory(),
  routes,
})

createApp(App).use(router).mount('#app')
