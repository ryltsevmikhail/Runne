import { createApp } from "vue";
import PassApp from "./PassApp.vue";
import { passRouter } from "./router";
import "./pass.css";

createApp(PassApp).use(passRouter).mount("#app");
