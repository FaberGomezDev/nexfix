<script lang="ts">
  import { onMount } from "svelte";
  import { api, type DefenderScan, type Finding, type FixReport, type QEntry, type ThreatLevel } from "../api";
  import Icon from "../components/Icon.svelte";
  import { bytes, date, isoDate, ms, num } from "../format";
  import { app, ask, go, loadSecurity, relaunchAsAdmin, toast, toastError } from "../state.svelte";

  let scanning = $state(false);
  let fixing = $state(false);
  let report = $state<FixReport | null>(null);
  let selected = $state<Record<string, boolean>>({});
  let expanded = $state<Record<string, boolean>>({});
  let busy = $state<Record<string, boolean>>({});
  let defender = $state<Record<string, DefenderScan>>({});
  let quarantine = $state<QEntry[] | null>(null);
  let showInfo = $state(false);
  let showIgnored = $state(false);

  const sec = $derived(app.security);
  const visible = $derived((sec?.findings ?? []).filter((f) => !f.ignored));
  const threats = $derived(visible.filter((f) => f.level !== "info"));
  const notes = $derived(visible.filter((f) => f.level === "info"));
  const ignoredList = $derived((sec?.findings ?? []).filter((f) => f.ignored));
  const chosen = $derived(visible.filter((f) => selected[f.id] && f.plan.length));
  const worst = $derived<ThreatLevel | null>(threats[0]?.level ?? null);
  const activeAv = $derived(sec?.av.products.filter((p) => p.enabled) ?? []);

  const levelInfo: Record<ThreatLevel, [string, string]> = {
    critical: ["bad", "Crítico"],
    high: ["bad", "Alto"],
    medium: ["warn", "Revisar"],
    info: ["", "Info"],
  };
  const categoryLabel: Record<Finding["category"], [string, string]> = {
    mineria: ["flame", "Minería"],
    malware: ["bug", "Malware"],
    persistencia: ["clock", "Inicio automático"],
    proteccion: ["shield", "Protección"],
    disco: ["drive", "Disco"],
  };

  function initSelection() {
    const sel: Record<string, boolean> = {};
    // Only the near-certain ones start ticked; the user decides the rest.
    for (const f of visible) sel[f.id] = f.level === "critical" && f.plan.length > 0;
    selected = sel;
  }

  async function loadQuarantine() {
    try {
      quarantine = await api.quarantineList();
    } catch (e) {
      toastError(e);
    }
  }

  async function scan() {
    scanning = true;
    try {
      await loadSecurity(true);
      initSelection();
    } catch (e) {
      toastError(e);
    } finally {
      scanning = false;
    }
  }

  onMount(() => {
    loadQuarantine();
    if (app.security) initSelection();
    else scan();
  });

  async function fix() {
    if (!chosen.length) return;
    const admin = chosen.some((f) => f.needs_admin) && !app.admin;
    const details = chosen.flatMap((f) => [`■ ${f.title}`, ...f.plan.map((p) => `   · ${p}`)]);
    const ok = await ask({
      title: `Eliminar ${chosen.length} ${chosen.length === 1 ? "amenaza" : "amenazas"}`,
      body:
        "NexFix cerrará los procesos, moverá los archivos a la cuarentena (podrás restaurarlos) y quitará sus entradas de inicio, guardando una copia de cada cambio. Guarda tu trabajo antes de continuar." +
        (admin ? "\n\nAlgunos pasos necesitan permisos de administrador y fallarán: lo ideal es reiniciar NexFix como administrador primero." : ""),
      details,
      confirm: "Eliminar ahora",
      danger: true,
    });
    if (!ok) return;
    fixing = true;
    try {
      report = await api.securityFix(chosen.map((f) => f.id));
      toast(
        report.failed ? `${report.fixed} resueltas · ${report.failed} con errores` : `${report.fixed} amenazas eliminadas`,
        report.failed ? "warn" : "ok",
      );
      await Promise.all([scan(), loadQuarantine()]);
    } catch (e) {
      toastError(e);
    } finally {
      fixing = false;
    }
  }

  async function setIgnored(f: Finding, value: boolean) {
    try {
      await api.securityIgnore(f.key, value);
      for (const x of app.security?.findings ?? []) if (x.key === f.key) x.ignored = value;
      selected[f.id] = false;
      toast(value ? "No se volverá a marcar como amenaza" : "Se vuelve a vigilar", "ok");
    } catch (e) {
      toastError(e);
    }
  }

  async function scanWithDefender(f: Finding) {
    if (!f.path) return;
    busy[`def:${f.id}`] = true;
    try {
      const r = await api.defenderScanFile(f.path);
      defender[f.id] = r;
      toast(r.summary, r.threat ? "error" : "ok", 7000);
    } catch (e) {
      toastError(e);
    } finally {
      busy[`def:${f.id}`] = false;
    }
  }

  function runTask(id: string) {
    app.taskRequest = { id, drive: null };
    go("maintenance");
  }

  async function restore(q: QEntry) {
    if (q.admin && !app.admin) return relaunchAsAdmin();
    const ok = await ask({
      title: "Restaurar desde la cuarentena",
      body: "Volverá a su sitio tal como estaba. Si era malware, volverá a ejecutarse. Hazlo solo si estás seguro de que es legítimo.",
      details: [`${q.title}`, q.original],
      confirm: "Restaurar",
      danger: true,
    });
    if (!ok) return;
    busy[q.id] = true;
    try {
      toast(await api.quarantineRestore(q.id), "ok");
      await loadQuarantine();
    } catch (e) {
      toastError(e);
    } finally {
      busy[q.id] = false;
    }
  }

  async function purge(q: QEntry) {
    if (q.admin && !app.admin) return relaunchAsAdmin();
    const ok = await ask({
      title: "Eliminar de la cuarentena",
      body: q.kind === "file" ? "El archivo se borrará para siempre y ya no se podrá restaurar." : "Se borrará la copia de seguridad y ya no se podrá deshacer este cambio.",
      details: [q.original],
      confirm: "Eliminar",
      danger: true,
    });
    if (!ok) return;
    busy[q.id] = true;
    try {
      await api.quarantineDelete(q.id);
      await loadQuarantine();
    } catch (e) {
      toastError(e);
    } finally {
      busy[q.id] = false;
    }
  }

  async function deleteBigFile(path: string, size: number) {
    const ok = await ask({
      title: `Eliminar ${bytes(size)}`,
      body: "El archivo se borrará definitivamente. Si pertenece a un programa que usas (máquina virtual, juego, caché), ese programa podría perder datos.",
      details: [path],
      confirm: "Eliminar",
      danger: true,
    });
    if (!ok) return;
    busy[path] = true;
    try {
      const r = await api.deletePaths(null, [path], false);
      if (r.deleted) toast(`Liberados ${bytes(r.freed || size)}`, "ok");
      if (r.failed.length) toast(r.failed[0].error, "warn", 7000);
      if (app.security) app.security.disk.big_files = app.security.disk.big_files.filter((b) => b.path !== path || !r.deleted);
    } catch (e) {
      toastError(e);
    } finally {
      busy[path] = false;
    }
  }

  function analyze(path: string) {
    app.analyzeRequest = path;
    go("analyzer");
  }

  const qKind: Record<QEntry["kind"], [string, string]> = {
    file: ["file", "Archivo"],
    reg: ["list", "Registro"],
    task: ["clock", "Tarea programada"],
    service: ["layers", "Servicio"],
    exclusion: ["shield", "Exclusión del antivirus"],
    hosts: ["globe", "Archivo hosts"],
  };

  const daysText = (d: number) => (d === 0 ? "hoy" : d === 1 ? "hace 1 día" : `hace ${d} días`);
  const pctText = (v: number) => `${v.toLocaleString("es-ES", { maximumFractionDigits: v < 10 ? 1 : 0 })} %`;
  const rate = (b: number) => (b >= 1024 * 1024 ? `${(b / 1048576).toLocaleString("es-ES", { maximumFractionDigits: 1 })} MB/s` : b > 0 ? "< 1 MB/s" : "—");
  const growthMax = $derived(Math.max(1, ...(sec?.disk.growth.map((g) => g.bytes) ?? [1])));
</script>

{#snippet findingRow(f: Finding)}
  {@const [lc, ll] = levelInfo[f.level]}
  {@const [ci, cl] = categoryLabel[f.category]}
  <div class="finding {f.level}" class:open={expanded[f.id]}>
    <div class="f-row">
      <input type="checkbox" bind:checked={selected[f.id]} disabled={!f.plan.length || fixing || f.ignored} aria-label={f.title} />
      <button class="f-main" onclick={() => (expanded[f.id] = !expanded[f.id])}>
        <span class="f-ic"><Icon name={ci} size={17} /></span>
        <span class="f-text">
          <span class="row" style="gap:8px">
            <strong class="ellipsis">{f.title}</strong>
            <span class="badge {lc}">{ll}</span>
            <span class="badge">{cl}</span>
            {#if f.needs_admin && !app.admin}<span class="badge"><Icon name="lock" size={11} /> admin</span>{/if}
          </span>
          {#if f.path}<span class="muted small mono ellipsis">{f.path}</span>{/if}
        </span>
        <span class="chips">
          {#if f.gpu != null && f.gpu >= 1}<span class="chip violet">GPU {pctText(f.gpu)}</span>{/if}
          {#if f.cpu != null && f.cpu >= 1}<span class="chip">CPU {pctText(f.cpu)}</span>{/if}
          {#if f.vram != null && f.vram >= 256 * 1024 * 1024}<span class="chip">VRAM {bytes(f.vram)}</span>{/if}
          {#if f.size}<span class="chip">{bytes(f.size)}</span>{/if}
        </span>
        <Icon name={expanded[f.id] ? "up" : "down"} size={16} />
      </button>
    </div>
    {#if expanded[f.id]}
      <div class="f-detail">
        <p class="text-2">{f.summary}</p>
        {#if f.reasons.length}
          <ul class="reasons">
            {#each f.reasons as r}<li>{r}</li>{/each}
          </ul>
        {/if}
        <dl class="kv f-kv">
          {#if f.signer || f.sign_state}
            <dt>Firma digital</dt>
            <dd>
              {#if f.sign_state === "trusted"}<span class="ok-text">Válida</span> · {f.signer}
              {:else if f.sign_state === "invalid"}<span class="bad-text">No válida</span>{f.signer ? ` · ${f.signer}` : ""}
              {:else if f.sign_state === "unsigned"}<span class="warn-text">Sin firma</span>
              {:else}—{/if}
            </dd>
          {/if}
          {#if f.pids.length}<dt>Procesos</dt><dd>PID {f.pids.slice(0, 6).join(", ")}{f.pids.length > 6 ? "…" : ""}</dd>{/if}
          {#if f.write_rate}<dt>Escritura en disco</dt><dd>{rate(f.write_rate)}</dd>{/if}
          {#if f.mtime}<dt>Modificado</dt><dd>{date(f.mtime)}</dd>{/if}
        </dl>
        {#if f.command}
          <div class="cmd mono selectable" title={f.command}>{f.command}</div>
        {/if}
        {#if f.plan.length}
          <div class="plan">
            <span class="muted small">Al eliminar, NexFix hará:</span>
            <ol>{#each f.plan as p}<li>{p}</li>{/each}</ol>
          </div>
        {/if}
        {#if defender[f.id]}
          <div class="callout {defender[f.id].threat ? 'bad' : 'info'}" style="margin-top:10px">
            <Icon name={defender[f.id].threat ? "alert" : "shield"} size={16} />
            <div>{defender[f.id].summary}</div>
          </div>
        {/if}
        <div class="row wrap" style="margin-top:12px">
          {#if f.path && f.kind !== "defender"}
            <button class="btn sm" onclick={() => api.reveal(f.path!)}><Icon name="external" size={13} /> Mostrar en el Explorador</button>
          {/if}
          {#if f.path && ["process", "startup", "task", "service", "file"].includes(f.kind)}
            <button class="btn sm" disabled={busy[`def:${f.id}`]} onclick={() => scanWithDefender(f)}>
              {#if busy[`def:${f.id}`]}<span class="spinner"></span>{:else}<Icon name="shield" size={13} />{/if} Analizar con Defender
            </button>
          {/if}
          {#if f.kind === "defender"}
            <button class="btn sm" onclick={() => api.openWindowsSecurity().catch(toastError)}><Icon name="shield" size={13} /> Abrir Seguridad de Windows</button>
            {#if f.id.startsWith("det:")}
              <button class="btn sm" onclick={() => runTask("defender_offline")}><Icon name="power" size={13} /> Análisis sin conexión</button>
            {:else if f.id === "av:signatures"}
              <button class="btn sm" onclick={() => runTask("defender_update")}><Icon name="refresh" size={13} /> Actualizar firmas</button>
            {/if}
          {/if}
          <span class="spacer"></span>
          {#if f.ignored}
            <button class="btn ghost sm" onclick={() => setIgnored(f, false)}><Icon name="eye" size={13} /> Dejar de ignorar</button>
          {:else}
            <button class="btn ghost sm" title="Es legítimo: no volver a marcarlo" onclick={() => setIgnored(f, true)}>
              <Icon name="eyeoff" size={13} /> Es de confianza, ignorar
            </button>
          {/if}
        </div>
      </div>
    {/if}
  </div>
{/snippet}

<div class="page">
  <div class="page-head">
    <div>
      <h1>Seguridad</h1>
      <p>Mineros ocultos que usan tu gráfica o CPU, malware que llena el disco y cambios sospechosos. Tú decides qué se elimina.</p>
    </div>
    <button class="btn" onclick={scan} disabled={scanning || fixing}>
      {#if scanning}<span class="spinner"></span>{:else}<Icon name="scan" size={16} />{/if} Analizar de nuevo
    </button>
  </div>

  {#if !app.admin}
    <div class="callout info" style="margin-bottom:14px">
      <Icon name="shield" size={18} />
      <div style="flex:1">
        Sin permisos de administrador no se revisan las tareas programadas, las suscripciones WMI ni las exclusiones del antivirus, y no se pueden
        cerrar procesos protegidos. Para un análisis completo, reinicia como administrador.
      </div>
      <button class="btn sm grad" onclick={relaunchAsAdmin}>Reiniciar como admin</button>
    </div>
  {/if}

  {#if report}
    <section class="card result" class:bad-border={report.failed > 0}>
      <div class="row">
        <div class="res-ic" class:warn={report.failed > 0}><Icon name={report.failed ? "alert" : "check"} size={20} /></div>
        <div style="flex:1">
          <h2>{report.failed ? `${report.fixed} resueltas, ${report.failed} con errores` : `${report.fixed} amenazas eliminadas`}</h2>
          <p class="muted">
            {#if report.freed}Liberados {bytes(report.freed)}. {/if}Todo lo movido está en la cuarentena (abajo) por si necesitas restaurarlo.
            {#if report.reboot}<b class="warn-text">Reinicia el PC para terminar: hay archivos en uso que se eliminarán al arrancar.</b>{/if}
          </p>
        </div>
        <button class="btn ghost icon-only" onclick={() => (report = null)} aria-label="Cerrar"><Icon name="x" size={16} /></button>
      </div>
      <ul class="res-list">
        {#each report.items as it}
          <li>
            <b class={it.ok ? "ok-text" : "warn-text"}>{it.title}</b>
            {#each it.steps as s}
              <div class="small" class:muted={s.ok}>
                <Icon name={s.ok ? "check" : "xcircle"} size={12} class="inline {s.ok ? 'ok-text' : 'bad-text'}" />
                {s.text} — {s.message}
              </div>
            {/each}
          </li>
        {/each}
      </ul>
    </section>
  {/if}

  {#if !sec}
    <div class="empty card">
      <span class="spinner lg"></span>
      <h2>Analizando tu PC…</h2>
      <p>Midiendo el uso de CPU y GPU de cada proceso y revisando el inicio automático, los servicios, el antivirus y lo que crece en el disco.</p>
    </div>
  {:else}
    <section class="card hero" class:alarm={worst === "critical" || worst === "high"} class:caution={worst === "medium"}>
      <div class="hero-ic">
        <Icon name={worst ? "alert" : "shield"} size={30} />
      </div>
      <div style="flex:1;min-width:0">
        <h2>
          {#if !threats.length}No se encontraron amenazas
          {:else}{threats.length} {threats.length === 1 ? "elemento sospechoso" : "elementos sospechosos"}{/if}
        </h2>
        <p class="muted small">
          {num(sec.checked.processes)} procesos · {num(sec.checked.startup)} entradas de inicio · {sec.checked.tasks != null ? `${num(sec.checked.tasks)} tareas` : "tareas (admin)"}
          · {num(sec.checked.services)} servicios · {sec.checked.wmi != null ? "WMI" : "WMI (admin)"} · hosts · {num(sec.disk.scanned_files)} archivos · {ms(sec.elapsed_ms)}
        </p>
        {#if !threats.length}
          <p class="text-2" style="margin-top:6px">Ningún proceso mina criptomonedas ni se hace pasar por Windows, y no hay persistencia ni cambios sospechosos en el antivirus.</p>
        {/if}
      </div>
      <div class="hero-stats">
        <div class="stat"><span class="label">CPU</span><span class="value">{Math.round(sec.cpu_total)}<small>%</small></span></div>
        <div class="stat"><span class="label">GPU</span><span class="value">{sec.gpu_total != null ? Math.round(sec.gpu_total) : "—"}<small>{sec.gpu_total != null ? "%" : ""}</small></span></div>
        <div class="stat"><span class="label">Antivirus</span><span class="value av" class:bad-text={!activeAv.length}>{activeAv[0]?.name ?? "Ninguno"}</span></div>
      </div>
    </section>

    {#if threats.length}
      <section class="card flush" style="margin-bottom:14px">
        <div class="sec-head">
          <Icon name="bug" size={17} />
          <h2>Amenazas y elementos sospechosos</h2>
          <span class="spacer"></span>
          <button class="btn ghost sm" onclick={() => threats.forEach((f) => f.plan.length && (selected[f.id] = true))}>Marcar todo</button>
          <button class="btn ghost sm" onclick={() => (selected = {})}>Ninguno</button>
        </div>
        {#each threats as f (f.id)}{@render findingRow(f)}{/each}
      </section>
    {/if}

    {#if notes.length}
      <section class="card flush" style="margin-bottom:14px">
        <button class="sec-head toggle-head" onclick={() => (showInfo = !showInfo)}>
          <Icon name="info" size={17} />
          <h2>Otras observaciones</h2>
          <span class="muted small">{notes.length} · entradas de inicio rotas y avisos menores</span>
          <span class="spacer"></span>
          <Icon name={showInfo ? "up" : "down"} size={16} />
        </button>
        {#if showInfo}{#each notes as f (f.id)}{@render findingRow(f)}{/each}{/if}
      </section>
    {/if}

    <section class="card flush" style="margin-bottom:14px">
      <div class="sec-head">
        <Icon name="activity" size={17} />
        <h2>Qué está usando tu equipo ahora</h2>
        <span class="muted small">medido durante 1,6 s</span>
      </div>
      {#if sec.resources.length}
        <table class="table res">
          <thead>
            <tr><th>Proceso</th><th class="num">GPU</th><th class="num">VRAM</th><th class="num">CPU</th><th class="num">Disco</th><th>Firma</th><th></th></tr>
          </thead>
          <tbody>
            {#each sec.resources as r (r.path ?? r.pids.join(","))}
              <tr class:flag={r.flagged}>
                <td>
                  <div class="row" style="gap:6px">
                    <strong class="ellipsis" style="max-width:220px">{r.name}</strong>
                    {#if r.pids.length > 1}<span class="muted small">×{r.pids.length}</span>{/if}
                    {#if r.flagged}<span class="badge bad">sospechoso</span>{/if}
                    {#if !r.windowed}<span class="badge" title="No tiene ninguna ventana visible">2.º plano</span>{/if}
                  </div>
                  {#if r.path}<div class="muted small mono ellipsis" style="max-width:420px" title={r.path}>{r.path}</div>{/if}
                </td>
                <td class="num">
                  {#if r.gpu >= 0.5}
                    <div class="gpu-cell">
                      <div class="bar thin" style="width:60px"><span style="width:{Math.min(100, r.gpu)}%;background:var(--violet)"></span></div>
                      {pctText(r.gpu)}
                    </div>
                    {#if r.compute}<span class="muted small">cómputo</span>{/if}
                  {:else}—{/if}
                </td>
                <td class="num">{r.vram >= 64 * 1024 * 1024 ? bytes(r.vram) : "—"}</td>
                <td class="num">{r.cpu >= 0.5 ? pctText(r.cpu) : "—"}</td>
                <td class="num">{rate(r.write_rate)}</td>
                <td class="small">
                  {#if r.sign_state === "trusted"}<span class="ok-text ellipsis" title={r.signer ?? ""}>{r.signer ?? "Firmado"}</span>
                  {:else if r.sign_state === "unsigned"}<span class="warn-text">Sin firma</span>
                  {:else if r.sign_state === "invalid"}<span class="bad-text">Firma no válida</span>
                  {:else}<span class="muted">—</span>{/if}
                </td>
                <td>
                  {#if r.path}<button class="btn ghost icon-only" title="Mostrar en el Explorador" onclick={() => api.reveal(r.path!)}><Icon name="external" size={14} /></button>{/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
        <p class="muted small pad">
          Los juegos y programas con ventana pueden usar mucha GPU sin problema. Lo raro es un proceso en segundo plano, sin firma, usando la
          GPU en modo cómputo: así trabajan los mineros.
        </p>
      {:else}
        <p class="muted pad">Nada está consumiendo recursos de forma notable ahora mismo.</p>
      {/if}
    </section>

    <div class="grid c2 two">
      <section class="card flush">
        <div class="sec-head">
          <Icon name="drive" size={17} />
          <h2>¿Qué está llenando el disco?</h2>
          <span class="muted small">últimos {sec.disk.days} días</span>
        </div>
        <div class="pad">
          <p class="muted small">
            {bytes(sec.disk.recent_bytes)} escritos en carpetas temporales, de programas y del sistema. Para ver todo el disco usa
            <button class="link" onclick={() => go("analyzer")}>Espacio</button>.
          </p>
          {#if sec.disk.growth.length}
            <ul class="growth">
              {#each sec.disk.growth as g}
                <li>
                  <div class="row" style="gap:8px">
                    <span class="mono small ellipsis" style="flex:1" title={g.path}>{g.path}</span>
                    <strong class="small">{bytes(g.bytes)}</strong>
                    <button class="btn ghost icon-only" title="Analizar esta carpeta" onclick={() => analyze(g.path)}><Icon name="pie" size={14} /></button>
                  </div>
                  <div class="bar thin"><span style="width:{(g.bytes / growthMax) * 100}%"></span></div>
                  {#if g.note}<span class="muted small">{g.note}</span>{/if}
                </li>
              {/each}
            </ul>
          {:else}
            <p class="muted" style="margin-top:10px">Nada ha crecido de forma notable esta semana.</p>
          {/if}
        </div>
        {#if sec.disk.big_files.length}
          <div class="sub-head">Archivos grandes en carpetas ocultas o del sistema</div>
          <div class="bigfiles">
            {#each sec.disk.big_files as b (b.path)}
              <div class="bf">
                <div style="flex:1;min-width:0">
                  <div class="row" style="gap:6px">
                    <span class="mono small ellipsis" title={b.path}>{b.path}</span>
                    {#if b.suspicious}<span class="badge warn">sin explicación</span>{/if}
                  </div>
                  <span class="muted small">{b.note ?? "Origen desconocido"} · {date(b.mtime)}</span>
                </div>
                <strong class="small">{bytes(b.size)}</strong>
                <button class="btn ghost icon-only" title="Mostrar en el Explorador" onclick={() => api.reveal(b.path)}><Icon name="external" size={14} /></button>
                <button class="btn ghost icon-only" title="Eliminar" disabled={busy[b.path]} onclick={() => deleteBigFile(b.path, b.size)}><Icon name="trash" size={14} /></button>
              </div>
            {/each}
          </div>
        {/if}
      </section>

      <section class="card flush">
        <div class="sec-head">
          <Icon name="shield" size={17} />
          <h2>Protección antivirus</h2>
          <span class="spacer"></span>
          <button class="btn ghost sm" onclick={() => api.openWindowsSecurity().catch(toastError)}><Icon name="external" size={13} /> Seguridad de Windows</button>
        </div>
        <div class="pad stack" style="gap:12px">
          {#if sec.av.products.length}
            <div class="products">
              {#each sec.av.products as p}
                <div class="product">
                  <Icon name="shield" size={16} />
                  <strong style="flex:1">{p.name}</strong>
                  <span class="badge {p.enabled ? 'ok' : ''}">{p.enabled ? "Activo" : p.defender ? "Pasivo / desactivado" : "Desactivado"}</span>
                  {#if p.enabled && !p.up_to_date}<span class="badge warn">Desactualizado</span>{/if}
                </div>
              {/each}
            </div>
          {/if}
          {#if sec.av.defender}
            {@const d = sec.av.defender}
            <dl class="kv">
              <dt>Protección en tiempo real (Defender)</dt>
              <dd class:ok-text={d.realtime === true}>{d.realtime == null ? "—" : d.realtime ? "Activada" : d.mode && /passive|pasiv/i.test(d.mode) ? "Modo pasivo (usas otro antivirus)" : "Desactivada"}</dd>
              <dt>Firmas</dt>
              <dd class:warn-text={(d.signature_age ?? 0) > 7}>{isoDate(d.signature_date)}{d.signature_age != null ? ` · ${daysText(d.signature_age)}` : ""}</dd>
              <dt>Último análisis rápido</dt>
              <dd>{d.quick_scan_age == null ? "Nunca" : daysText(d.quick_scan_age).replace(/^./, (c) => c.toUpperCase())}</dd>
              <dt>Protección contra alteraciones</dt>
              <dd>{d.tamper == null ? "—" : d.tamper ? "Activada" : "Desactivada"}</dd>
            </dl>
          {/if}
          <div class="row wrap">
            <button class="btn sm primary" onclick={() => runTask("defender_quick")}><Icon name="play" size={12} /> Análisis rápido</button>
            <button class="btn sm" onclick={() => runTask("defender_full")}><Icon name="scan" size={13} /> Completo</button>
            <button class="btn sm" onclick={() => runTask("defender_update")}><Icon name="refresh" size={13} /> Actualizar firmas</button>
            <button class="btn sm" title="Reinicia y analiza antes de que arranque Windows" onclick={() => runTask("defender_offline")}>
              <Icon name="power" size={13} /> Sin conexión
            </button>
          </div>

          {#if sec.av.detections.length}
            <div>
              <div class="sub-title">Detecciones recientes de Defender</div>
              <ul class="dets">
                {#each sec.av.detections as d}
                  <li>
                    <div class="row" style="gap:6px">
                      <strong class="ellipsis" style="flex:1">{d.name}</strong>
                      <span class="badge {d.active ? 'bad' : 'ok'}">{d.status}</span>
                    </div>
                    <span class="muted small">{isoDate(d.date)} · gravedad {d.severity.toLowerCase()}{d.resources[0] ? ` · ${d.resources[0]}` : ""}</span>
                  </li>
                {/each}
              </ul>
            </div>
          {/if}

          <div>
            <div class="sub-title">Exclusiones del antivirus</div>
            {#if !sec.av.exclusions_readable}
              <p class="muted small">Windows solo muestra las exclusiones a los administradores. Los mineros suelen añadirse aquí para que Defender no los vea.</p>
            {:else if !sec.av.exclusions.length}
              <p class="muted small">No hay exclusiones: Defender lo analiza todo.</p>
            {:else}
              <ul class="excl">
                {#each sec.av.exclusions as ex}
                  <li class:risky={ex.risk}>
                    <span class="badge">{ex.kind === "path" ? "Ruta" : ex.kind === "process" ? "Proceso" : "Extensión"}</span>
                    <span class="mono small ellipsis" style="flex:1" title={ex.value}>{ex.value}</span>
                    {#if ex.risk}<span class="badge warn" title={ex.risk}>riesgo</span>{/if}
                    {#if ex.policy}<span class="badge" title="Configurada por directiva de grupo">directiva</span>{/if}
                  </li>
                {/each}
              </ul>
            {/if}
          </div>
        </div>
      </section>
    </div>

    <section class="card flush" style="margin-top:14px">
      <div class="sec-head">
        <Icon name="archive" size={17} />
        <h2>Cuarentena</h2>
        <span class="muted small">{quarantine?.length ?? 0} {quarantine?.length === 1 ? "elemento" : "elementos"}</span>
        <span class="spacer"></span>
        <button class="btn ghost icon-only" title="Actualizar" onclick={loadQuarantine}><Icon name="refresh" size={14} /></button>
      </div>
      {#if !quarantine?.length}
        <p class="muted pad">
          Vacía. Lo que NexFix aísla (archivos, entradas de inicio, tareas, servicios, exclusiones, hosts) se guarda aquí con una copia para que
          puedas deshacerlo.
        </p>
      {:else}
        <table class="table q">
          <tbody>
            {#each quarantine as q (q.id)}
              {@const [qi, ql] = qKind[q.kind] ?? ["file", q.kind]}
              <tr>
                <td style="width:30px"><Icon name={qi} size={16} /></td>
                <td>
                  <div class="row" style="gap:6px"><strong class="ellipsis">{q.title}</strong><span class="badge">{ql}</span>{#if q.admin && !app.admin}<span class="badge"><Icon name="lock" size={11} /> admin</span>{/if}</div>
                  <div class="muted small mono ellipsis" style="max-width:640px" title={q.original}>{q.original}</div>
                </td>
                <td class="num small muted">{q.size && q.kind === "file" ? bytes(q.size) : ""}</td>
                <td class="num small muted">{date(q.date)}</td>
                <td class="num">
                  <div class="row" style="justify-content:flex-end;gap:6px">
                    <button class="btn sm" disabled={busy[q.id]} onclick={() => restore(q)}><Icon name="undo" size={13} /> Restaurar</button>
                    <button class="btn ghost icon-only" title="Eliminar definitivamente" disabled={busy[q.id]} onclick={() => purge(q)}><Icon name="trash" size={14} /></button>
                  </div>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </section>

    {#if ignoredList.length}
      <section class="card flush" style="margin-top:14px">
        <button class="sec-head toggle-head" onclick={() => (showIgnored = !showIgnored)}>
          <Icon name="eyeoff" size={17} />
          <h2>Ignorados</h2>
          <span class="muted small">{ignoredList.length} marcados como de confianza</span>
          <span class="spacer"></span>
          <Icon name={showIgnored ? "up" : "down"} size={16} />
        </button>
        {#if showIgnored}{#each ignoredList as f (f.id)}{@render findingRow(f)}{/each}{/if}
      </section>
    {/if}
  {/if}

  <div class="footer-space"></div>
</div>

{#if threats.length || chosen.length}
  <div class="action-bar">
    <div>
      <div class="muted small">Seleccionadas</div>
      <strong class="sel">{chosen.length}</strong>
      <span class="muted small">de {threats.length} · lo eliminado va a la cuarentena y se puede restaurar</span>
    </div>
    <span class="spacer"></span>
    {#if fixing}<span class="row text-2"><span class="spinner"></span> Eliminando…</span>{/if}
    <button class="btn danger lg" disabled={!chosen.length || fixing || scanning} onclick={fix}>
      <Icon name="trash" size={17} /> Eliminar {chosen.length || ""} {chosen.length === 1 ? "amenaza" : "amenazas"}
    </button>
  </div>
{/if}

<style>
  .hero {
    display: flex;
    align-items: center;
    gap: 18px;
    margin-bottom: 14px;
    padding: 18px 22px;
    background: radial-gradient(500px 180px at 0% 0%, rgba(34, 197, 94, 0.1), transparent 60%), var(--panel);
  }
  .hero.alarm {
    background: radial-gradient(500px 180px at 0% 0%, rgba(240, 75, 75, 0.14), transparent 60%), var(--panel);
    border-color: rgba(240, 75, 75, 0.35);
  }
  .hero.caution {
    background: radial-gradient(500px 180px at 0% 0%, rgba(245, 165, 36, 0.12), transparent 60%), var(--panel);
  }
  .hero-ic {
    width: 56px;
    height: 56px;
    border-radius: 16px;
    display: grid;
    place-items: center;
    background: var(--ok-soft);
    color: var(--ok);
    flex: none;
  }
  .alarm .hero-ic {
    background: var(--bad-soft);
    color: var(--bad);
  }
  .caution .hero-ic {
    background: var(--warn-soft);
    color: var(--warn);
  }
  .hero h2 {
    font-size: 19px;
    margin-bottom: 2px;
  }
  .hero-stats {
    display: flex;
    gap: 22px;
    flex: none;
  }
  .hero-stats .value.av {
    font-size: 14px;
    max-width: 160px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    display: block;
    margin-top: 4px;
  }
  .sec-head {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 12px 18px;
    border-bottom: 1px solid var(--line);
    background: var(--panel-2);
    width: 100%;
    color: var(--text);
  }
  .toggle-head {
    border: none;
    cursor: pointer;
    text-align: left;
    font: inherit;
  }
  .sub-head {
    padding: 8px 18px;
    font-size: 12px;
    font-weight: 600;
    color: var(--muted);
    border-top: 1px solid var(--line);
    border-bottom: 1px solid var(--line);
    background: var(--panel-2);
  }
  .sub-title {
    font-size: 12px;
    font-weight: 600;
    color: var(--muted);
    margin-bottom: 6px;
  }
  .pad {
    padding: 14px 18px;
  }
  .finding {
    border-bottom: 1px solid var(--line);
    border-left: 3px solid transparent;
  }
  .finding:last-child {
    border-bottom: none;
  }
  .finding.critical,
  .finding.high {
    border-left-color: var(--bad);
  }
  .finding.medium {
    border-left-color: var(--warn);
  }
  .f-row {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 0 12px 0 15px;
  }
  .f-main {
    flex: 1;
    min-width: 0;
    display: flex;
    align-items: center;
    gap: 12px;
    min-height: 58px;
    padding: 8px 0;
    background: none;
    border: none;
    cursor: pointer;
    text-align: left;
    color: var(--text-2);
  }
  .f-ic {
    width: 32px;
    height: 32px;
    border-radius: 9px;
    display: grid;
    place-items: center;
    background: var(--panel-3);
    color: var(--text-2);
    flex: none;
  }
  .critical .f-ic,
  .high .f-ic {
    background: var(--bad-soft);
    color: var(--bad);
  }
  .medium .f-ic {
    background: var(--warn-soft);
    color: var(--warn);
  }
  .f-text {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .f-text strong {
    color: var(--text);
    font-weight: 600;
  }
  .chips {
    display: flex;
    gap: 6px;
    flex: none;
  }
  .chip {
    font-size: 11.5px;
    padding: 2px 8px;
    border-radius: 6px;
    background: var(--panel-3);
    color: var(--text-2);
    font-variant-numeric: tabular-nums;
    white-space: nowrap;
  }
  .chip.violet {
    background: rgba(139, 108, 255, 0.15);
    color: #a993ff;
  }
  .f-detail {
    padding: 0 18px 16px 60px;
  }
  .reasons {
    margin: 8px 0 0;
    padding-left: 18px;
    font-size: 13px;
    color: var(--text-2);
  }
  .reasons li {
    margin: 2px 0;
  }
  .f-kv {
    margin-top: 10px;
    max-width: 640px;
  }
  .f-kv dd {
    text-align: left;
  }
  .cmd {
    margin-top: 10px;
    padding: 8px 10px;
    border-radius: var(--radius-sm);
    background: #070910;
    color: #c8d3e6;
    max-height: 90px;
    overflow: auto;
    word-break: break-all;
  }
  .plan {
    margin-top: 10px;
    padding: 8px 12px;
    border-radius: var(--radius-sm);
    background: var(--panel-2);
    border: 1px solid var(--line);
  }
  .plan ol {
    margin: 4px 0 0;
    padding-left: 20px;
    font-size: 12.5px;
    color: var(--text-2);
  }
  .result {
    margin-bottom: 14px;
    border-color: rgba(34, 197, 94, 0.35);
    background: linear-gradient(90deg, var(--ok-soft), transparent 60%), var(--panel);
  }
  .result.bad-border {
    border-color: rgba(245, 165, 36, 0.35);
    background: linear-gradient(90deg, var(--warn-soft), transparent 60%), var(--panel);
  }
  .res-ic {
    width: 40px;
    height: 40px;
    border-radius: 12px;
    display: grid;
    place-items: center;
    background: var(--ok-soft);
    color: var(--ok);
  }
  .res-ic.warn {
    background: var(--warn-soft);
    color: var(--warn);
  }
  .res-list {
    list-style: none;
    margin: 12px 0 0;
    padding: 0 0 0 52px;
    display: flex;
    flex-direction: column;
    gap: 8px;
    font-size: 13px;
  }
  .res-list :global(.inline) {
    display: inline;
    vertical-align: -1px;
  }
  .res td,
  .res th,
  .q td {
    padding-left: 18px;
    padding-right: 18px;
  }
  tr.flag td {
    background: rgba(240, 75, 75, 0.06);
  }
  .gpu-cell {
    display: inline-flex;
    align-items: center;
    gap: 8px;
  }
  .two {
    align-items: start;
  }
  .growth {
    list-style: none;
    margin: 12px 0 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .growth li {
    display: flex;
    flex-direction: column;
    gap: 3px;
  }
  .bigfiles {
    max-height: 280px;
    overflow: auto;
  }
  .bf {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 8px 18px;
    border-bottom: 1px solid var(--line);
  }
  .bf:last-child {
    border-bottom: none;
  }
  .link {
    background: none;
    border: none;
    padding: 0;
    color: var(--accent);
    cursor: pointer;
    font: inherit;
  }
  .products {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .product {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 8px 12px;
    border-radius: var(--radius-sm);
    background: var(--panel-2);
    border: 1px solid var(--line);
  }
  .dets,
  .excl {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .dets li {
    display: flex;
    flex-direction: column;
    gap: 1px;
  }
  .excl li {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 5px 8px;
    border-radius: 6px;
  }
  .excl li.risky {
    background: var(--warn-soft);
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
  .btn.lg {
    height: 42px;
    padding: 0 22px;
    font-size: 15px;
  }
  @media (max-width: 1180px) {
    .two {
      grid-template-columns: 1fr;
    }
    .hero {
      flex-wrap: wrap;
    }
  }
</style>
