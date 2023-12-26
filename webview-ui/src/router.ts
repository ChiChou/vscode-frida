import { createRouter, createWebHashHistory } from "vue-router";

import Modules from "./views/Modules.vue";

const routes = [
  {
    path: "/",
    name: "Modules",
    component: Modules,
  },
];

const router = createRouter({
  history: createWebHashHistory(),
  routes,
});

export default router;
