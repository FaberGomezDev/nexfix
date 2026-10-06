<script lang="ts">
  import { onDestroy, onMount } from "svelte";
  import { api, on, type CleanReport, type JunkCategory, type Risk } from "../api";
  import Icon from "../components/Icon.svelte";
  import { bytes, date, num } from "../format";
  import { app, ask, relaunchAsAdmin, toast, toastError } from "../state.svelte";

  let scanning = $state(false);
  let cleaning = $state(false);
  let progress = $state<{ done: number; total: number; freed: number } | null>(null);
  let report = $state<CleanReport | null>(null);

  let selected = $state<Record<string, boolean>>({});
  let expanded = $state<Record<string, boolean>>({});
  /** Unticked files in normal categories (lower-case path). */
  let excluded = $state<Record<string, boolean>>({});
  /** Ticked files in explicit categories (lower-case path). */
  let included = $state<Record<string, boolean>>({});

  const groups = ["Sistema", "Juegos y GPU", "Navegadores", "Desarrollo", "Personal"];
  const riskLabel: Record<Risk, [string, string]> = {
    safe: ["ok", "Seguro"],
    moderate: ["warn", "Moderado"],
    caution: ["bad", "Revisar"],
  };

  const cats = $derived((app.junk ?? []).filter((c) => c.found));
  const missing = $derived((app.junk ?? []).filter((c) => !c.found).length);

  function initSelection(list: JunkCategory[]) {
    const sel: Record<string, boolean> = {};
    for (const c of list) {
      sel[c.id] = c.default_on && c.size > 0 && !c.explicit && (!c.admin || app.admin);
    }
    selected = sel;
    excluded = {};
    included = {};
  }

  async function scan() {
    scanning = true;
    report = null;
    try {
      app.junk = await api.junkScan();
      initSelection(app.junk);
    } catch (e) {
      toastError(e);
    } finally {
      scanning = false;
    }
  }

  onMount(() => {
    if (app.junk) initSelection(app.junk);
    else scan();
  });

  let unlisten: (() => void) | undefined;
  on<{ category: string; done: number; total: number; freed: number }>("cleaner://progress", (p) => {
    progress = { done: p.done, total: p.total, freed: p.freed };
  }).then((u) => (unlisten = u));
  onDestroy(() => unlisten?.());

  function selectedSize(c: JunkCategory): number {
    if (c.explicit) {
      return c.top.filter((f) => included[f.path.toLowerCase()]).reduce((s, f) => s + f.size, 0);
    }
    if (!selected[c.id]) return 0;
    const ex = c.top.filter((f) => excluded[f.path.toLowerCase()]).reduce((s, f) => s + f.size, 0);
    return Math.max(0, c.size - ex);
  }

  function isActive(c: JunkCategory) {
    return c.explicit ? c.top.some((f) => included[f.path.toLowerCase()]) : !!selected[c.id];
  }

  const totalFound = $derived(cats.reduce((s, c) => s + c.size, 0));
  const totalSelected = $derived(cats.reduce((s, c) => s + selectedSize(c), 0));
  const activeCats = $derived(cats.filter(isActive));

  function toggleGroup(group: string, value: boolean) {
    for (const c of cats.filter((c) => c.group === group && !c.explicit && c.size > 0)) selected[c.id] = value;
  }

  async function clean() {
    if (!activeCats.length) return;
    const details = activeCats.map((c) => `${c.name}: ${bytes(selectedSize(c))}${c.recycle ? " (a la Papelera)" : ""}`);
    const hasBin = activeCats.some((c) => c.id === "recycle_bin");
    const ok = await ask({
      title: `Liberar ${bytes(totalSelected)}`,
      body:
        "Se eliminarán los archivos de estas categorías. Los que estén en uso se saltan automáticamente." +
        (hasBin ? "\n\nVaciar la Papelera es definitivo." : ""),
      details,
      confirm: "Limpiar ahora",
      danger: true,
    });
    if (!ok) return;

    cleaning = true;
    progress = { done: 0, total: activeCats.length, freed: 0 };
    try {
      const ids = activeCats.map((c) => c.id);
      const exc = Object.keys(excluded).filter((k) => excluded[k]);
      const inc = Object.keys(included).filter((k) => included[k]);
      report = await api.junkClean(ids, exc, inc);
      toast(`Liberados ${bytes(report.freed)} (${num(report.deleted)} archivos)`, "ok");
      app.junk = await api.junkScan();
      initSelection(app.junk);
    } catch (e) {
      toastError(e);
    } finally {
      cleaning = false;
      progress = null;
    }
  }
</script>

<div class="page">
  <div class="page-head">
    <div>
      <h1>Limpieza</h1>
      <p>Temporales, cachés y restos. Revisa cada categoría y decide tú qué se borra.</p>
    </div>
    <button class="btn" onclick={scan} disabled={scanning || cleaning}>
      {#if scanning}<span class="spinner"></span>{:else}<Icon name="search" size={16} />{/if} Analizar de nuevo
    </button>
  </div>

  {#if report}
    <section class="card report">
      <div class="row">
        <div class="ok-ic"><Icon name="check" size={20} /></div>
        <div style="flex:1">
          <h2>Limpieza terminada: {bytes(report.freed)} liberados</h2>
          <p class="muted">
            {num(report.deleted)} archivos eliminados{report.failed ? ` · ${num(report.failed)} omitidos (en uso o sin permisos)` : ""}.
          </p>
        </div>
        <button class="btn ghost icon-only" onclick={() => (report = null)} aria-label="Cerrar"><Icon name="x" size={16} /></button>
      </div>
      {#if report.categories.some((c) => c.failed > 0)}
        <ul class="fails">
          {#each report.categories.filter((c) => c.failed > 0) as c}
            <li>
              <b>{app.junk?.find((j) => j.id === c.id)?.name ?? c.id}</b>: {num(c.failed)} omitidos{c.sample_error ? ` — ${c.sample_error}` : ""}
            </li>
          {/each}
        </ul>
      {/if}
    </section>
  {/if}

  {#if !app.admin}
    <div class="callout info" style="margin-bottom:14px">
      <Icon name="shield" size={18} />
      <div style="flex:1">Algunas categorías del sistema (temporales de Windows, caché de Windows Update, volcados) necesitan permisos de administrador para limpiarse por completo.</div>
      <button class="btn sm" onclick={relaunchAsAdmin}>Reiniciar como admin</button>
    </div>
  {/if}

  {#if scanning && !app.junk}
    <div class="empty card"><span class="spinner lg"></span><h2>Buscando archivos innecesarios…</h2><p>Revisando temporales, cachés de juegos, GPU y navegadores.</p></div>
  {:else}
    <div class="stack">
      {#each groups as g}
        {@const list = cats.filter((c) => c.group === g)}
        {#if list.length}
          <section class="card flush">
            <div class="group-head">
              <h2>{g}</h2>
              <span class="muted small">{bytes(list.reduce((s, c) => s + c.size, 0))}</span>
              <span class="spacer"></span>
              {#if g !== "Personal"}
                <button class="btn ghost sm" onclick={() => toggleGroup(g, true)}>Marcar todo</button>
                <button class="btn ghost sm" onclick={() => toggleGroup(g, false)}>Ninguno</button>
              {/if}
            </div>
            {#each list as c (c.id)}
              {@const [rc, rl] = riskLabel[c.risk]}
              <div class="cat" class:open={expanded[c.id]} class:empty-cat={c.size === 0}>
                <div class="cat-row">
                  {#if c.explicit}
                    <span class="pick-ic"><Icon name="folder" size={16} /></span>
                  {:else}
                    <input type="checkbox" bind:checked={selected[c.id]} disabled={c.size === 0 || cleaning} aria-label={c.name} />
                  {/if}
                  <button class="cat-main" onclick={() => (expanded[c.id] = !expanded[c.id])}>
                    <span class="cat-name">{c.name}</span>
                    <span class="badge {rc}">{rl}</span>
                    {#if c.admin && !app.admin}<span class="badge"><Icon name="lock" size={11} /> admin</span>{/if}
                    {#if c.denied}<span class="badge warn" title="Hay carpetas sin acceso">acceso parcial</span>{/if}
                    <span class="spacer"></span>
                    <span class="cat-size">{c.size ? bytes(c.size) : "Vacío"}</span>
                    <span class="muted small cat-count">{c.count ? `${num(c.count)} archivos` : ""}</span>
                    <Icon name={expanded[c.id] ? "up" : "down"} size={16} />
                  </button>
                </div>
                {#if expanded[c.id]}
                  <div class="cat-detail">
                    <p class="muted">{c.description}</p>
                    {#if c.min_age_hours}<p class="muted small">Solo archivos con más de {c.min_age_hours} h.</p>{/if}
                    {#if c.top.length}
                      <div class="files">
                        {#if c.explicit}
                          <div class="row small muted" style="padding:4px 0 8px">
                            Marca los archivos que quieras enviar a la Papelera ({c.top.length < c.count ? `mostrando los ${c.top.length} más grandes` : "todos"}).
                          </div>
                        {/if}
                        {#each c.top as f (f.path)}
                          {@const key = f.path.toLowerCase()}
                          <label class="file">
                            {#if c.explicit}
                              <input type="checkbox" bind:checked={included[key]} disabled={cleaning} />
                            {:else}
                              <input
                                type="checkbox"
                                checked={!!selected[c.id] && !excluded[key]}
                                disabled={!selected[c.id] || cleaning}
                                onchange={(e) => (excluded[key] = !(e.currentTarget as HTMLInputElement).checked)}
                              />
                            {/if}
                            <span class="ellipsis path selectable" title={f.path}>{f.path}</span>
                            <span class="muted small">{date(f.mtime)}</span>
                            <span class="num">{bytes(f.size)}</span>
                            <button class="btn ghost icon-only" title="Mostrar en el Explorador" onclick={(e) => { e.preventDefault(); api.reveal(f.path); }}>
                              <Icon name="external" size={14} />
                            </button>
                          </label>
                        {/each}
                        {#if !c.explicit && c.count > c.top.length}
                          <p class="muted small" style="padding:6px 0">Y {num(c.count - c.top.length)} archivos más pequeños.</p>
                        {/if}
                      </div>
                    {/if}
                  </div>
                {/if}
              </div>
            {/each}
          </section>
        {/if}
      {/each}
      {#if missing}<p class="muted small">{missing} categorías no aplican a tu PC (programas no instalados).</p>{/if}
    </div>
  {/if}

  <div class="footer-space"></div>
</div>

<div class="action-bar">
  <div>
    <div class="muted small">Seleccionado</div>
    <strong class="sel">{bytes(totalSelected)}</strong>
    <span class="muted small">de {bytes(totalFound)} encontrados · {activeCats.length} categorías</span>
  </div>
  <span class="spacer"></span>
  {#if cleaning && progress}
    <div class="prog">
      <span class="spinner"></span>
      <span>Limpiando {progress.done}/{progress.total} · {bytes(progress.freed)}</span>
    </div>
  {/if}
  <button class="btn grad lg" disabled={!activeCats.length || totalSelected === 0 || cleaning || scanning} onclick={clean}>
    <Icon name="sparkles" size={17} /> Limpiar {totalSelected ? bytes(totalSelected) : ""}
  </button>
</div>

<style>
  .group-head {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 12px 18px;
    border-bottom: 1px solid var(--line);
    background: var(--panel-2);
  }
  .cat {
    border-bottom: 1px solid var(--line);
  }
  .cat:last-child {
    border-bottom: none;
  }
  .cat.empty-cat {
    opacity: 0.55;
  }
  .cat-row {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 0 12px 0 18px;
  }
  .pick-ic {
    width: 16px;
    color: var(--muted);
    display: grid;
    place-items: center;
  }
  .cat-main {
    flex: 1;
    display: flex;
    align-items: center;
    gap: 8px;
    min-width: 0;
    height: 50px;
    background: none;
    border: none;
    cursor: pointer;
    text-align: left;
    color: var(--text-2);
    padding: 0;
  }
  .cat-name {
    font-weight: 600;
    color: var(--text);
  }
  .cat-size {
    font-weight: 650;
    font-variant-numeric: tabular-nums;
    min-width: 80px;
    text-align: right;
  }
  .cat-count {
    min-width: 110px;
    text-align: right;
  }
  .cat-detail {
    padding: 0 18px 14px 46px;
  }
  .files {
    margin-top: 10px;
    max-height: 320px;
    overflow: auto;
    border: 1px solid var(--line);
    border-radius: var(--radius-sm);
    padding: 4px 10px;
    background: var(--panel-2);
  }
  .file {
    display: flex;
    align-items: center;
    gap: 10px;
    height: 32px;
    font-size: 12.5px;
    border-bottom: 1px solid var(--line);
  }
  .file:last-child {
    border-bottom: none;
  }
  .file .path {
    flex: 1;
    color: var(--text-2);
  }
  .file .num {
    min-width: 72px;
    text-align: right;
    font-variant-numeric: tabular-nums;
  }
  .report {
    margin-bottom: 14px;
    border-color: rgba(34, 197, 94, 0.35);
    background: linear-gradient(90deg, var(--ok-soft), transparent 60%), var(--panel);
  }
  .ok-ic {
    width: 40px;
    height: 40px;
    border-radius: 12px;
    display: grid;
    place-items: center;
    background: var(--ok-soft);
    color: var(--ok);
  }
  .fails {
    margin: 10px 0 0;
    padding-left: 52px;
    color: var(--muted);
    font-size: 12.5px;
  }
  .footer-space {
    height: 70px;
  }
  .action-bar {
    position: sticky;
    bottom: 0;
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 12px 30px;
    background: rgba(13, 17, 24, 0.92);
    backdrop-filter: blur(10px);
    border-top: 1px solid var(--line);
    z-index: 5;
  }
  .sel {
    font-size: 20px;
    margin-right: 8px;
  }
  .prog {
    display: flex;
    align-items: center;
    gap: 10px;
    color: var(--text-2);
  }
  .btn.lg {
    height: 42px;
    padding: 0 22px;
    font-size: 15px;
  }
</style>
