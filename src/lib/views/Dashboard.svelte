<script lang="ts">
  import { onMount } from "svelte";
  import { api, type LiveStats } from "../api";
  import Icon from "../components/Icon.svelte";
  import Ring from "../components/Ring.svelte";
  import { bytes, bytesDecimal, duration } from "../format";
  import { buildInsights, healthScore, type Level } from "../insights";
  import { app, go, loadSecurity, loadStartup, loadStorage, loadSystem, loadTweaks, toastError } from "../state.svelte";

  let { active }: { active: boolean } = $props();

  let live = $state<LiveStats | null>(null);
  let loading = $state(true);
  let refreshing = $state(false);
  let sortBy = $state<"memory" | "cpu" | "gpu">("memory");

  const insights = $derived(buildInsights(app.system, app.storage, app.tweaks, app.junk, app.startup, app.security));
  const score = $derived(healthScore(insights));
  const issues = $derived(insights.filter((i) => i.level === "bad" || i.level === "warn").length);
  const scoreColor = $derived(score >= 85 ? "var(--ok)" : score >= 65 ? "var(--warn)" : "var(--bad)");
  const scoreText = $derived(
    score >= 90 ? "Tu PC está en muy buena forma" : score >= 75 ? "Buen estado, con mejoras posibles" : score >= 55 ? "Hay cosas importantes que mejorar" : "Tu PC necesita atención",
  );

  const dgpu = $derived(app.system?.gpus.find((g) => !g.integrated) ?? app.system?.gpus[0]);
  const sysVol = $derived(app.storage?.volumes.find((v) => v.is_system));
  const sysDisk = $derived(app.storage?.disks.find((d) => d.number === sysVol?.disk_number));

  const icons: Record<Level, string> = { bad: "xcircle", warn: "alert", info: "info", good: "check" };

  async function loadAll(force = false) {
    refreshing = true;
    // The security scan samples processes for ~2 s: it fills in on its own.
    loadSecurity(force).catch(() => {});
    try {
      await Promise.all([
        loadSystem(force),
        loadStorage(force),
        loadTweaks(force),
        loadStartup(force),
        (!app.junk || force) && api.junkScan().then((j) => (app.junk = j)),
      ]);
    } catch (e) {
      toastError(e);
    } finally {
      loading = false;
      refreshing = false;
    }
  }

  onMount(() => {
    loadAll();
  });

  // Live usage polling only while the dashboard is visible.
  $effect(() => {
    if (!active) return;
    let stop = false;
    const tick = async () => {
      try {
        live = await api.liveStats();
      } catch {}
      if (!stop) timer = setTimeout(tick, 1500);
    };
    let timer = setTimeout(tick, 50);
    return () => {
      stop = true;
      clearTimeout(timer);
    };
  });

  const memPct = $derived(live ? (live.mem_used / live.mem_total) * 100 : 0);
</script>

<div class="page">
  <div class="page-head">
    <div>
      <h1>Resumen</h1>
      <p>
        {#if app.system}{app.system.cpu.name} · {dgpu?.name} · {bytes(app.system.memory.total, 0)} RAM{:else}Analizando tu PC…{/if}
      </p>
    </div>
    <button class="btn" onclick={() => loadAll(true)} disabled={refreshing}>
      {#if refreshing}<span class="spinner"></span>{:else}<Icon name="refresh" size={16} />{/if}
      Volver a analizar
    </button>
  </div>

  <div class="top">
    <section class="card hero">
      {#if loading}
        <div class="skeleton" style="width:150px;height:150px;border-radius:50%"></div>
        <div class="stack" style="flex:1">
          <div class="skeleton" style="height:22px;width:60%"></div>
          <div class="skeleton" style="height:14px;width:80%"></div>
        </div>
      {:else}
        <Ring value={score} size={150} thickness={12} color={scoreColor} label={String(score)} sub="de 100" />
        <div class="hero-text">
          <span class="eyebrow">Salud del sistema</span>
          <h2>{scoreText}</h2>
          <p class="muted">
            {issues === 0 ? "No hay problemas importantes." : `${issues} ${issues === 1 ? "aspecto a revisar" : "aspectos a revisar"}`}
            · {insights.filter((i) => i.level === "info").length} sugerencias
          </p>
          <div class="row wrap" style="margin-top:14px">
            <button class="btn grad" onclick={() => go("cleaner")}><Icon name="sparkles" size={16} /> Limpiar</button>
            <button class="btn" onclick={() => go("analyzer")}><Icon name="pie" size={16} /> Analizar espacio</button>
            <button class="btn" onclick={() => go("security")}><Icon name="bug" size={16} /> Seguridad</button>
            <button class="btn" onclick={() => go("maintenance")}><Icon name="wrench" size={16} /> Mantenimiento</button>
          </div>
        </div>
      {/if}
    </section>

    <section class="card live">
      <div class="card-head">
        <div class="icon-box"><Icon name="activity" size={17} /></div>
        <h3>Uso en tiempo real</h3>
        {#if live}<span class="muted small">{live.process_count} procesos</span>{/if}
      </div>
      <div class="rings">
        <div class="ring-col">
          <Ring value={live?.cpu_total ?? 0} size={92} thickness={9} label={live ? `${Math.round(live.cpu_total)}%` : "—"} sub="CPU" />
          <span class="muted small">{live ? `${(live.cpu_mhz / 1000).toLocaleString("es-ES", { maximumFractionDigits: 2 })} GHz` : ""}</span>
        </div>
        <div class="ring-col">
          <Ring value={memPct} size={92} thickness={9} color="var(--violet)" label={live ? `${Math.round(memPct)}%` : "—"} sub="RAM" />
          <span class="muted small">{live ? `${bytes(live.mem_used)} / ${bytes(live.mem_total, 0)}` : ""}</span>
        </div>
        {#if live?.gpu_total != null}
          <div class="ring-col">
            <Ring value={live.gpu_total} size={92} thickness={9} color="var(--teal)" label={`${Math.round(live.gpu_total)}%`} sub="GPU" />
            <span class="muted small ellipsis" style="max-width:110px">{live.top_gpu[0] ? live.top_gpu[0].name : "En reposo"}</span>
          </div>
        {/if}
      </div>
      {#if live}
        <div class="cores" title="Uso por hilo">
          {#each live.per_core as c}
            <span style="--v:{Math.max(4, c)}%"></span>
          {/each}
        </div>
        <div class="muted small" style="margin-top:8px">Encendido desde hace {duration(live.uptime_secs)}</div>
      {/if}
    </section>
  </div>

  <div class="grid c4 tiles">
    <button class="card tile" onclick={() => go("hardware")}>
      <div class="tile-ic"><Icon name="cpu" size={18} /></div>
      <span class="label">Procesador</span>
      <strong class="ellipsis">{app.system?.cpu.name.replace(/\s+\d+-Core Processor/i, "") ?? "—"}</strong>
      <span class="muted small">{app.system ? `${app.system.cpu.cores} núcleos · ${app.system.cpu.threads} hilos` : ""}</span>
    </button>
    <button class="card tile" onclick={() => go("hardware")}>
      <div class="tile-ic violet"><Icon name="gpu" size={18} /></div>
      <span class="label">Gráfica</span>
      <strong class="ellipsis">{dgpu?.name ?? "—"}</strong>
      <span class="muted small">{dgpu ? `${bytes(dgpu.vram, 0)} VRAM · driver ${dgpu.driver_version}` : ""}</span>
    </button>
    <button class="card tile" onclick={() => go("hardware")}>
      <div class="tile-ic teal"><Icon name="memory" size={18} /></div>
      <span class="label">Memoria</span>
      <strong>{app.system ? bytes(app.system.memory.total, 0) : "—"} {app.system?.memory.modules[0]?.mem_type ?? ""}</strong>
      <span class="muted small">
        {#if app.system?.memory.modules.length}
          {app.system.memory.modules.length} módulos · {app.system.memory.modules[0].configured_speed || app.system.memory.modules[0].speed} MT/s
        {/if}
      </span>
    </button>
    <button class="card tile" onclick={() => go("storage")}>
      <div class="tile-ic warn"><Icon name="drive" size={18} /></div>
      <span class="label">Disco del sistema</span>
      <strong class="ellipsis">{sysDisk?.model ?? "—"}</strong>
      {#if sysVol}
        <div class="bar thin" style="margin:6px 0 4px"><span style="width:{((sysVol.total - sysVol.free) / sysVol.total) * 100}%"></span></div>
        <span class="muted small">
          {bytes(sysVol.free)} libres de {bytes(sysVol.total, 0)}
          {#if sysDisk?.nvme} · {sysDisk.nvme.temperature_c} °C · {bytesDecimal(sysDisk.nvme.data_written_bytes)} escritos{/if}
        </span>
      {/if}
    </button>
  </div>

  <div class="bottom">
    <section class="card flush">
      <div class="card-head pad">
        <div class="icon-box"><Icon name="shield" size={17} /></div>
        <h2>Recomendaciones</h2>
        <span class="muted small">{insights.length} comprobaciones</span>
      </div>
      {#if loading}
        <div class="stack pad">
          {#each Array(4) as _}<div class="skeleton" style="height:54px"></div>{/each}
        </div>
      {:else}
        <ul class="insights">
          {#each insights as ins (ins.id)}
            <li class="ins {ins.level}">
              <div class="ins-ic"><Icon name={icons[ins.level]} size={18} /></div>
              <div class="ins-body">
                <strong>{ins.title}</strong>
                <p>{ins.detail}</p>
              </div>
              {#if ins.action}
                <button class="btn sm" onclick={() => go(ins.action!.view)}>{ins.action.label}<Icon name="right" size={14} /></button>
              {/if}
            </li>
          {/each}
        </ul>
      {/if}
    </section>

    <section class="card flush">
      <div class="card-head pad">
        <div class="icon-box"><Icon name="layers" size={17} /></div>
        <h2>Lo que más consume</h2>
        <div class="tabs mini">
          <button class:active={sortBy === "memory"} onclick={() => (sortBy = "memory")}>RAM</button>
          <button class:active={sortBy === "cpu"} onclick={() => (sortBy = "cpu")}>CPU</button>
          <button class:active={sortBy === "gpu"} onclick={() => (sortBy = "gpu")}>GPU</button>
        </div>
      </div>
      {#if live}
        {@const list = sortBy === "cpu" ? live.top_cpu : sortBy === "gpu" ? live.top_gpu : live.top_memory}
        <table class="table procs">
          <thead><tr><th>Proceso</th><th class="num">RAM</th><th class="num">CPU</th><th class="num">GPU</th></tr></thead>
          <tbody>
            {#each list as p}
              <tr>
                <td class="ellipsis" style="max-width:180px">
                  {p.name}{#if p.count > 1}<span class="muted small"> ×{p.count}</span>{/if}
                </td>
                <td class="num">{bytes(p.memory)}</td>
                <td class="num">{p.cpu.toLocaleString("es-ES", { maximumFractionDigits: 1 })} %</td>
                <td class="num">{p.gpu >= 0.5 ? `${p.gpu.toLocaleString("es-ES", { maximumFractionDigits: 0 })} %` : "—"}</td>
              </tr>
            {:else}
              <tr><td colspan="4" class="muted">{sortBy === "gpu" ? "Ningún proceso está usando la GPU ahora mismo." : "Sin datos."}</td></tr>
            {/each}
          </tbody>
        </table>
        <p class="muted small pad">
          Cierra lo que no uses antes de jugar. Si algo usa la GPU sin que tengas nada abierto, revísalo en
          <button class="link" onclick={() => go("security")}>Seguridad</button>.
        </p>
      {:else}
        <div class="stack pad">{#each Array(6) as _}<div class="skeleton" style="height:20px"></div>{/each}</div>
      {/if}
    </section>
  </div>
</div>

<style>
  .top {
    display: grid;
    grid-template-columns: minmax(0, 1.6fr) minmax(300px, 1fr);
    gap: 14px;
    margin-bottom: 14px;
  }
  .hero {
    display: flex;
    align-items: center;
    gap: 26px;
    padding: 22px 26px;
    background:
      radial-gradient(600px 220px at 0% 0%, rgba(47, 140, 255, 0.12), transparent 60%),
      radial-gradient(500px 200px at 100% 100%, rgba(139, 108, 255, 0.1), transparent 60%),
      var(--panel);
  }
  .hero-text h2 {
    font-size: 21px;
    margin: 4px 0 4px;
  }
  .eyebrow {
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--accent);
    font-weight: 650;
  }
  .rings {
    display: flex;
    justify-content: space-around;
    gap: 10px;
  }
  .ring-col {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 6px;
  }
  .cores {
    display: flex;
    gap: 3px;
    height: 34px;
    align-items: flex-end;
    margin-top: 14px;
  }
  .cores span {
    flex: 1;
    height: var(--v);
    background: linear-gradient(180deg, var(--teal), var(--accent));
    border-radius: 3px 3px 1px 1px;
    opacity: 0.85;
    transition: height 0.5s ease;
  }
  .tiles {
    margin-bottom: 14px;
  }
  .tile {
    text-align: left;
    display: flex;
    flex-direction: column;
    gap: 2px;
    cursor: pointer;
    transition: border-color 0.15s, transform 0.15s;
  }
  .tile:hover {
    border-color: var(--line-2);
    transform: translateY(-1px);
  }
  .tile .label {
    font-size: 12px;
    color: var(--muted);
    margin-top: 8px;
  }
  .tile strong {
    font-size: 15px;
  }
  .tile-ic {
    width: 32px;
    height: 32px;
    border-radius: 9px;
    display: grid;
    place-items: center;
    background: var(--accent-soft);
    color: var(--accent);
  }
  .tile-ic.violet {
    background: rgba(139, 108, 255, 0.15);
    color: var(--violet);
  }
  .tile-ic.teal {
    background: rgba(22, 224, 189, 0.12);
    color: var(--teal);
  }
  .tile-ic.warn {
    background: var(--warn-soft);
    color: var(--warn);
  }
  .bottom {
    display: grid;
    grid-template-columns: minmax(0, 1.6fr) minmax(300px, 1fr);
    gap: 14px;
    align-items: start;
  }
  .pad {
    padding: 16px 18px;
  }
  .card-head.pad {
    margin: 0;
    padding-bottom: 12px;
    border-bottom: 1px solid var(--line);
  }
  .insights {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  .ins {
    display: flex;
    gap: 14px;
    align-items: center;
    padding: 13px 18px;
    border-bottom: 1px solid var(--line);
  }
  .ins:last-child {
    border-bottom: none;
  }
  .ins-ic {
    width: 34px;
    height: 34px;
    border-radius: 10px;
    display: grid;
    place-items: center;
    flex: none;
  }
  .ins.bad .ins-ic {
    background: var(--bad-soft);
    color: var(--bad);
  }
  .ins.warn .ins-ic {
    background: var(--warn-soft);
    color: var(--warn);
  }
  .ins.info .ins-ic {
    background: var(--accent-soft);
    color: var(--accent);
  }
  .ins.good .ins-ic {
    background: var(--ok-soft);
    color: var(--ok);
  }
  .ins-body {
    flex: 1;
    min-width: 0;
  }
  .ins-body strong {
    font-weight: 600;
  }
  .ins-body p {
    color: var(--muted);
    font-size: 12.5px;
    margin-top: 2px;
  }
  .procs td,
  .procs th {
    padding-left: 18px;
    padding-right: 18px;
  }
  .tabs.mini button {
    height: 24px;
    padding: 0 10px;
    font-size: 12px;
  }
  .link {
    background: none;
    border: none;
    padding: 0;
    color: var(--accent);
    cursor: pointer;
    font: inherit;
  }
  @media (max-width: 1180px) {
    .top,
    .bottom {
      grid-template-columns: 1fr;
    }
  }
</style>
