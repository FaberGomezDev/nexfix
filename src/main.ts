import { mount } from "svelte";
import "./app.css";
import App from "./App.svelte";

// Desktop app: no browser context menu outside text fields.
window.addEventListener("contextmenu", (e) => {
  const t = e.target as HTMLElement | null;
  if (!t?.closest("input, textarea, .selectable")) e.preventDefault();
});

export default mount(App, { target: document.getElementById("app")! });
