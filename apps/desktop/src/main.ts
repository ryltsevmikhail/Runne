import { createApp } from 'vue'
import { createRouter, createWebHistory } from 'vue-router'

import App from './app/App.vue'
import { routes } from './app/router'
import './app/styles/index.css'

const LAST_ROUTE_KEY = 'runne:last-route'
const SESSION_KEY = 'runne:session-active'

const router = createRouter({
  history: createWebHistory(),
  routes,
})

const isNewSession = typeof sessionStorage !== 'undefined' && sessionStorage.getItem(SESSION_KEY) !== 'true'
if (typeof sessionStorage !== 'undefined') sessionStorage.setItem(SESSION_KEY, 'true')

if (isNewSession && window.location.pathname === '/' && typeof localStorage !== 'undefined') {
  const savedRoute = localStorage.getItem(LAST_ROUTE_KEY)
  if (savedRoute && savedRoute !== '/' && router.resolve(savedRoute).matched.length > 0) {
    void router.replace(savedRoute)
  }
}

router.afterEach((to) => {
  if (typeof localStorage !== 'undefined') localStorage.setItem(LAST_ROUTE_KEY, to.fullPath)
})

createApp(App).use(router).mount('#app')
