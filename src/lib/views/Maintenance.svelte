<script lang="ts">
  import { onDestroy, onMount, tick } from "svelte";
  import { api, on, type TaskDef, type TaskDone, type TaskOutput } from "../api";
  import Icon from "../components/Icon.svelte";
  import { app, ask, loadStorage, relaunchAsAdmin, toast, toastError } from "../state.svelte";

  type Status = "running" | "ok" | "fail" | "cancelled";

  let tasks = $state<TaskDef[]>([]);
  let drive = $state("C:");
  let status = $state<Record<string, Status>>({});
  let logs = $state<Record<string, { lines: string[]; replace: boolean }>>({});
  let shown = $state<string | null>(null);
  let queue = $state<string[]>([]);
  let consoleEl = $state<HTMLDivElement | null>(null);

  const ROUTINE = ["dism_restore", "sfc", "retrim", "chkdsk"];
  /** Tasks with side effects beyond the PC staying as it is. */
  const CONFIRM: Record<string, string> = {
    defender_offline:
      "El PC se reiniciará en unos segundos sin más avisos y Microsoft Defender analizará el disco antes de que arranque Windows (unos 15 minutos). Guarda y cierra todo lo que tengas abierto.",
    sandbox_off:
      "Se desactivará la característica «Espacio aislado de Windows» (Windows Sandbox). Después de reiniciar, Windows deja de mantener sus capas en ProgramData\\Microsoft\\Windows\\Containers. Puedes volver a activarla en «Activar o desactivar las características de Windows».",
  };
  const running = $derived(Object.entries(status).some(([, s]) => s === "running"));

  const unlisteners: (() => void)[] = [];
  onMount(async () => {
    try {
      tasks = await api.maintenanceTasks();
      const st = await loadStorage();
      drive = st.volumes.find((v) => v.is_system)?.letter ?? st.volumes[0]?.letter ?? "C:";
    } catch (e) {
      toastError(e);
    }
    unlisteners.push(
      await on<TaskOutput>("task://output", async (o) => {
        const log = (logs[o.task] ??= { lines: [], replace: false });
        if (log.replace && log.lines.length) log.lines[log.lines.length - 1] = o.line;
        else log.lines.push(o.line);
        log.replace = o.replace;
        if (log.lines.length > 600) log.lines.splice(0, log.lines.length - 600);
        if (shown === o.task) {
          await tick();
          consoleEl?.scrollTo({ top: consoleEl.scrollHeight });
        }
      }),
      await on<TaskDone>("task://done", (d) => {
        status[d.task] = d.cancelled ? "cancelled" : d.success ? "ok" : "fail";
        const t = tasks.find((x) => x.id === d.task);
        if (!d.cancelled) toast(`${t?.name ?? d.task}: ${d.success ? "completado" : `terminó con código ${d.code}`}`, d.success ? "ok" : "warn");
        if (queue.length && queue[0] === d.task) {
          queue = queue.slice(1);
          if (d.cancelled) queue = [];
          else if (queue.length) run(queue[0]);
        }
      }),
    );
  });
  onDestroy(() => unlisteners.forEach((u) => u()));

  // Tasks requested from other views (e.g. "Ejecutar ReTrim" in Discos).
  $effect(() => {
    const req = app.taskRequest;
    if (req && tasks.length) {
      app.taskRequest = null;
      if (req.drive) drive = req.drive;
      run(req.id);
    }
  });

  async function run(id: string) {
    const t = tasks.find((x) => x.id === id);
    if (!t) return;
    if (t.admin && !app.admin) {
      relaunchAsAdmin();
      return;
    }
    const warn = CONFIRM[id];
    if (warn && !(await ask({ title: t.name, body: warn, confirm: "Continuar", danger: true }))) {
      queue = [];
      return;
    }
    logs[id] = { lines: [], replace: false };
    shown = id;
    status[id] = "running";
    try {
      await api.taskRun(id, t.needs_drive ? drive : null);
    } catch (e) {
      status[id] = "fail";
      queue = [];
      toastError(e);
    }
  }

  async function cancel(id: string) {
    try {
      await api.taskCancel(id);
    } catch (e) {
      toastError(e);
    }
  }

  async function runRoutine() {
    if (!app.admin) {
      relaunchAsAdmin();
      return;
    }
    const ok = await ask({
      title: "Rutina de mantenimiento completa",
      body: `Se ejecutarán en orden: reparar la imagen de Windows (DISM), comprobar archivos del sistema (SFC), ReTrim del SSD y comprobación del disco ${drive}. Puede tardar entre 20 y 45 minutos; puedes seguir usando el PC.`,
      confirm: "Empezar",
    });
    if (!ok) return;
    queue = [...ROUTINE];
    run(queue[0]);
  }

  const categories = $derived([...new Set(tasks.map((t) => t.category))]);
</script>

<div class="page">
  <div class="page-head">
    <div>
      <h1>Mantenimiento</h1>
      <p>Herramientas oficiales de Windows, sin ventanas de consola y con progreso en vivo.</p>
    </div>
    <div class="row">
      <span class="muted small">Unidad</span>
      <select bind:value={drive} disabled={running}>
        {#each app.storage?.volumes ?? [{ letter: "C:" }] as v}
          <option value={v.letter}>{v.letter}</option>
        {/each}
      </select>
    </div>
  </div>

  {#if !app.admin}
    <div class="callout info" style="margin-bottom:14px">
      <Icon name="shield" size={18} />
      <div style="flex:1">Casi todas estas tareas requieren permisos de administrador.</div>
      <button class="btn sm grad" onclick={relaunchAsAdmin}>Reiniciar como admin</button>
    </div>
  {/if}

  <section class="card routine">
    <div class="r-ic"><Icon name="shield" size={22} /></div>
    <div style="flex:1">
      <h2>Rutina mensual recomendada</h2>
      <p class="muted">DISM → SFC → ReTrim → chkdsk. Repara Windows, mantiene rápido tu M.2 y revisa el sistema de archivos. Hazla una vez al mes o si notas fallos raros.</p>
      {#if queue.length}
        <div class="steps">
          {#each ROUTINE as id, i}
            {@const s = status[id]}
            <span class="step" class:done={s === "ok"} class:now={queue[0] === id} class:fail={s === "fail"}>
              {i + 1}. {tasks.find((t) => t.id === id)?.name ?? id}
            </span>
          {/each}
        </div>
      {/if}
    </div>
    {#if queue.length}
      <button class="btn" onclick={() => { const cur = queue[0]; queue = []; cancel(cur); }}><Icon name="stop" size={14} /> Detener rutina</button>
    {:else}
      <button class="btn grad" disabled={running} onclick={runRoutine}><Icon name="play" size={14} /> Ejecutar rutina</button>
    {/if}
  </section>

  <div class="layout">
    <div class="stack">
      {#each categories as cat}
        <section class="card flush">
          <div class="cat-head"><h3>{cat}</h3></div>
          {#each tasks.filter((t) => t.category === cat) as t (t.id)}
            {@const s = status[t.id]}
            <div class="task" class:selected={shown === t.id}>
              <button class="task-main" onclick={() => (shown = t.id)}>
                <div class="row">
                  <strong>{t.name}</strong>
                  {#if t.needs_drive}<span class="badge">{drive}</span>{/if}
                  {#if t.admin && !app.admin}<span class="badge"><Icon name="lock" size={11} /> admin</span>{/if}
                  {#if s === "ok"}<span class="badge ok">Completado</span>{/if}
                  {#if s === "fail"}<span class="badge bad">Con errores</span>{/if}
                  {#if s === "cancelled"}<span class="badge">Cancelado</span>{/if}
                </div>
                <p class="muted small">{t.description}</p>
                <p class="muted small"><Icon name="clock" size={11} class="inline" /> {t.duration}</p>
              </button>
              {#if s === "running"}
                <button class="btn sm" onclick={() => cancel(t.id)}><span class="spinner"></span> Cancelar</button>
              {:else}
                <button class="btn sm primary" disabled={running && !queue.length ? false : running} onclick={() => run(t.id)}><Icon name="play" size={12} /> Ejecutar</button>
              {/if}
            </div>
          {/each}
        </section>
      {/each}
    </div>

    <section class="card flush console-card">
      <div class="cat-head">
        <Icon name="terminal" size={16} />
        <h3>{shown ? (tasks.find((t) => t.id === shown)?.name ?? shown) : "Salida"}</h3>
        <span class="spacer"></span>
        {#if shown && status[shown] === "running"}<span class="spinner"></span>{/if}
      </div>
      <div class="console mono selectable" bind:this={consoleEl}>
        {#if shown && logs[shown]?.lines.length}
          {#each logs[shown].lines as line}
            <div>{line}</div>
          {/each}
        {:else}
          <div class="muted">Elige una tarea y pulsa Ejecutar. La salida aparecerá aquí en tiempo real.</div>
        {/if}
      </div>
    </section>
  </div>
</div>

<style>
  .routine {
    display: flex;
    align-items: center;
    gap: 16px;
    margin-bottom: 14px;
    background: radial-gradient(500px 160px at 0% 0%, rgba(22, 224, 189, 0.1), transparent 60%), var(--panel);
  }
  .r-ic {
    width: 46px;
    height: 46px;
    border-radius: 13px;
    display: grid;
    place-items: center;
    background: var(--grad);
    color: #fff;
    flex: none;
  }
  .steps {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
    margin-top: 10px;
  }
  .step {
    font-size: 12px;
    padding: 3px 10px;
    border-radius: 99px;
    background: var(--panel-3);
    color: var(--muted);
  }
  .step.now {
    background: var(--accent-soft);
    color: #8cc0ff;
  }
  .step.done {
    background: var(--ok-soft);
    color: var(--ok);
  }
  .step.fail {
    background: var(--bad-soft);
    color: var(--bad);
  }
  .layout {
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
    gap: 14px;
    align-items: start;
  }
  .cat-head {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 11px 18px;
    border-bottom: 1px solid var(--line);
    background: var(--panel-2);
  }
  .task {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 18px;
    border-bottom: 1px solid var(--line);
  }
  .task:last-child {
    border-bottom: none;
  }
  .task.selected {
    background: rgba(47, 140, 255, 0.06);
  }
  .task-main {
    flex: 1;
    min-width: 0;
    background: none;
    border: none;
    text-align: left;
    padding: 0;
    cursor: pointer;
    display: flex;
    flex-direction: column;
    gap: 3px;
  }
  .task-main :global(.inline) {
    display: inline;
    vertical-align: -1px;
  }
  .console-card {
    position: sticky;
    top: 16px;
  }
  .console {
    height: 520px;
    overflow: auto;
    padding: 12px 16px;
    background: #070910;
    color: #c8d3e6;
    line-height: 1.55;
    white-space: pre-wrap;
    word-break: break-word;
  }
  @media (max-width: 1180px) {
    .layout {
      grid-template-columns: 1fr;
    }
    .console-card {
      position: static;
    }
  }
</style>
