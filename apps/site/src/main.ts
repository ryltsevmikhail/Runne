import { createApp, createSSRApp } from "vue";
import App from "./app/App.vue";
import "./app/styles/global.css";

const container = document.querySelector("#app");
const app = container?.firstElementChild ? createSSRApp(App) : createApp(App);
app.mount("#app");
