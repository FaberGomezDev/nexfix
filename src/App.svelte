<script lang="ts">
  import { onMount } from "svelte";
  import { api } from "./lib/api";
  import Dialog from "./lib/components/Dialog.svelte";
  import Icon from "./lib/components/Icon.svelte";
  import Toasts from "./lib/components/Toasts.svelte";
  import { app, go, relaunchAsAdmin, type View } from "./lib/state.svelte";
  import Analyzer from "./lib/views/Analyzer.svelte";
  import Cleaner from "./lib/views/Cleaner.svelte";
  import Dashboard from "./lib/views/Dashboard.svelte";
  import Hardware from "./lib/views/Hardware.svelte";
  import Maintenance from "./lib/views/Maintenance.svelte";
  import Optimize from "./lib/views/Optimize.svelte";
  import Storage from "./lib/views/Storage.svelte";

  const nav: { id: View; label: string; icon: string; hint: string }[] = [
    { id: "dashboard", label: "Resumen", icon: "gauge", hint: "Salud y recomendaciones" },
    { id: "hardware", label: "Componentes", icon: "cpu", hint: "CPU, GPU, RAM, pantallas" },
    { id: "storage", label: "Discos y M.2", icon: "drive", hint: "Salud SMART y TRIM" },
    { id: "cleaner", label: "Limpieza", icon: "sparkles", hint: "Temporales y cachés" },
    { id: "analyzer", label: "Espacio", icon: "pie", hint: "Qué ocupa tu disco" },
    { id: "optimize", label: "Optimización", icon: "rocket", hint: "Ajustes gaming e inicio" },
    { id: "maintenance", label: "Mantenimiento", icon: "wrench", hint: "TRIM, SFC, DISM, chkdsk" },
  ];

  // Views stay mounted after the first visit so their state survives navigation.
  let visited = $state<Record<string, boolean>>({ dashboard: true });
  $effect(() => {
    visited[app.view] = true;
  });

  onMount(async () => {
    app.admin = await api.isAdmin().catch(() => false);
  });
</script>

<div class="shell">
  <aside class="side">
    <div class="brand">
      <div class="logo">
        <svg viewBox="0 0 1024 1024" width="34" height="34" aria-hidden="true">
          <defs>
            <linearGradient id="lg" x1="0" y1="0" x2="1" y2="1">
              <stop offset="0" stop-color="#16e0bd" />
              <stop offset=".55" stop-color="#2f8cff" />
              <stop offset="1" stop-color="#7b5cff" />
            </linearGradient>
          </defs>
          <rect x="64" y="64" width="896" height="896" rx="220" fill="url(#lg)" />
          <path d="M300 760V264h112l200 316V264h112v496H612L412 444v316Z" fill="#fff" />
        </svg>
      </div>
      <div>
        <strong>NexFix</strong>
        <span>PC Gamer Care</span>
      </div>
    </div>

    <nav>
      {#each nav as item}
        <button class="nav-item" class:active={app.view === item.id} onclick={() => go(item.id)} title={item.hint}>
          <Icon name={item.icon} size={18} />
          <span>{item.label}</span>
        </button>
      {/each}
    </nav>

    <div class="side-foot">
      {#if app.admin}
        <div class="admin on">
          <Icon name="shield" size={16} />
          <span>Administrador</span>
        </div>
      {:else}
        <div class="admin">
          <Icon name="lock" size={16} />
          <span>Modo estándar</span>
        </div>
        <button class="btn sm grad full" onclick={relaunchAsAdmin}>
          <Icon name="shield" size={14} /> Reiniciar como admin
        </button>
      {/if}
    </div>
  </aside>

  <main class="content">
    <div class="view" hidden={app.view !== "dashboard"}><Dashboard active={app.view === "dashboard"} /></div>
    {#if visited.hardware}<div class="view" hidden={app.view !== "hardware"}><Hardware active={app.view === "hardware"} /></div>{/if}
    {#if visited.storage}<div class="view" hidden={app.view !== "storage"}><Storage /></div>{/if}
    {#if visited.cleaner}<div class="view" hidden={app.view !== "cleaner"}><Cleaner /></div>{/if}
    {#if visited.analyzer}<div class="view" hidden={app.view !== "analyzer"}><Analyzer /></div>{/if}
    {#if visited.optimize}<div class="view" hidden={app.view !== "optimize"}><Optimize /></div>{/if}
    {#if visited.maintenance}<div class="view" hidden={app.view !== "maintenance"}><Maintenance /></div>{/if}
  </main>
</div>

<Dialog />
<Toasts />

<style>
  .shell {
    display: grid;
    grid-template-columns: 228px 1fr;
    height: 100vh;
  }
  .side {
    background: linear-gradient(180deg, #0d1118 0%, #0a0d13 100%);
    border-right: 1px solid var(--line);
    display: flex;
    flex-direction: column;
    padding: 18px 12px 14px;
    min-height: 0;
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 2px 8px 20px;
  }
  .brand strong {
    display: block;
    font-size: 17px;
    letter-spacing: -0.01em;
  }
  .brand span {
    display: block;
    font-size: 11.5px;
    color: var(--muted);
    margin-top: -2px;
  }
  .logo {
    display: grid;
    place-items: center;
    filter: drop-shadow(0 4px 12px rgba(47, 140, 255, 0.35));
  }
  nav {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .nav-item {
    display: flex;
    align-items: center;
    gap: 12px;
    height: 40px;
    padding: 0 12px;
    border: none;
    border-radius: 10px;
    background: transparent;
    color: var(--text-2);
    cursor: pointer;
    font-weight: 550;
    text-align: left;
    position: relative;
    transition: background 0.15s, color 0.15s;
  }
  .nav-item:hover {
    background: var(--panel-2);
    color: var(--text);
  }
  .nav-item.active {
    background: var(--accent-soft);
    color: #fff;
  }
  .nav-item.active::before {
    content: "";
    position: absolute;
    left: -12px;
    top: 9px;
    bottom: 9px;
    width: 3px;
    border-radius: 0 3px 3px 0;
    background: var(--grad);
  }
  .nav-item.active :global(.icon) {
    color: var(--accent);
  }
  .side-foot {
    margin-top: auto;
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding: 12px 6px 0;
    border-top: 1px solid var(--line);
  }
  .admin {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 12.5px;
    color: var(--muted);
    padding: 0 4px;
  }
  .admin.on {
    color: var(--ok);
  }
  .full {
    width: 100%;
    justify-content: center;
  }
  .content {
    overflow: auto;
    min-width: 0;
    position: relative;
  }
  .view[hidden] {
    display: none;
  }
</style>
