import { createApp, createSSRApp } from "vue";
import App from "./app/App.vue";
import "./app/styles/global.css";

const container = document.querySelector("#app");
const path = window.location.pathname;
const app = container?.firstElementChild
  ? createSSRApp(App, { path })
  : createApp(App, { path });
app.mount("#app");
