<script lang="ts" module>
  const EXT_KINDS: [string, string, string[]][] = [
    ["Juegos", "#8b6cff", ["pak", "paz", "rpf", "xpak", "ucas", "utoc", "vpk", "forge", "bundle", "assets", "ress", "wem", "bnk", "bk2", "psf", "pck", "bsa", "ba2", "wad", "big", "sb", "toc", "cas", "arc", "rpkg", "bdt", "dsar"]],
    ["Vídeo", "#e2558f", ["mp4", "mkv", "avi", "mov", "wmv", "webm", "flv", "m4v", "ts", "mts"]],
    ["Discos virtuales", "#f5a524", ["vhdx", "vhd", "vdi", "vmdk", "iso", "img", "qcow2", "wim", "esd"]],
    ["Comprimidos", "#ff8a4c", ["zip", "rar", "7z", "tar", "gz", "xz", "zst", "cab", "bz2"]],
    ["Programas", "#2f8cff", ["exe", "dll", "sys", "msi", "msp", "cat", "mui", "ocx", "node"]],
    ["Imágenes", "#16c7a8", ["jpg", "jpeg", "png", "gif", "bmp", "webp", "heic", "tif", "tiff", "psd", "raw", "cr2", "nef", "dng", "svg", "ico"]],
    ["Audio", "#3fb8f0", ["mp3", "flac", "wav", "aac", "ogg", "m4a", "opus", "wma"]],
    ["Documentos", "#7ccf4a", ["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "md", "csv", "odt"]],
    ["Desarrollo", "#c77dff", ["js", "ts", "map", "json", "py", "rs", "jar", "class", "pdb", "lib", "obj", "o", "rlib", "pack", "idx"]],
  ];
  export function extKind(ext: string): [string, string] {
    for (const [name, color, list] of EXT_KINDS) if (list.includes(ext)) return [name, color];
    return ["Otros", "#7f8aa0"];
  }
</script>

<script lang="ts">
  import { open } from "@tauri-apps/plugin-dialog";
  import { onDestroy, onMount } from "svelte";
  import { api, on, type ExtStat, type FileDto, type Listing, type ScanDone, type ScanProgress, type ScanSummary } from "../api";
  import Icon from "../components/Icon.svelte";
  import Toggle from "../components/Toggle.svelte";
  import Treemap, { type TreemapItem } from "../components/Treemap.svelte";
  import { bytes, date, ms, num, pct } from "../format";
  import { app, ask, loadStorage, toast, toastError } from "../state.svelte";

  let scanId = $state<number | null>(null);
  let scanning = $state(false);
  let progress = $state<ScanProgress | null>(null);
  let summary = $state<ScanSummary | null>(null);
  let listing = $state<Listing | null>(null);
  let tab = $state<"folders" | "files" | "types">("folders");
  let topFiles = $state<FileDto[]>([]);
  let exts = $state<ExtStat[]>([]);
  let selection = $state<Record<string, boolean>>({});
  let toRecycle = $state(true);
  let deleting = $state(false);
  let loadingList = $state(false);

  const selected = $derived(Object.keys(selection).filter((k) => selection[k]));

  const unlisteners: (() => void)[] = [];
  onMount(async () => {
    loadStorage().catch(() => {});
    unlisteners.push(
      await on<ScanProgress>("analyzer://progress", (p) => {
        if (p.id === scanId) progress = p;
      }),
      await on<ScanDone>("analyzer://done", (d) => {
        // Small folders can finish before analyzer_start has even returned its id.
        if (d.id !== scanId) earlyDone.set(d.id, d);
        else handleDone(d);
      }),
    );
  });

  const earlyDone = new Map<number, ScanDone>();

  async function handleDone(d: ScanDone) {
    scanning = false;
    if (!d.ok || !d.summary) {
      if (d.error) toast(d.error, /cancelad/i.test(d.error) ? "info" : "error");
      return;
    }
    summary = d.summary;
    await openNode(0);
    [topFiles, exts] = await Promise.all([api.analyzerTopFiles(d.id), api.analyzerExtensions(d.id)]);
  }
  onDestroy(() => unlisteners.forEach((u) => u()));

  // Requests coming from other views ("Analizar C:").
  $effect(() => {
    const req = app.analyzeRequest;
    if (req) {
      app.analyzeRequest = null;
      start(req);
    }
  });

  async function start(path: string) {
    if (scanning && scanId != null) await api.analyzerCancel(scanId);
    summary = null;
    listing = null;
    topFiles = [];
    exts = [];
    selection = {};
    progress = null;
    tab = "folders";
    scanning = true;
    try {
      const id = await api.analyzerStart(path);
      scanId = id;
      const early = earlyDone.get(id);
      if (early) {
        earlyDone.delete(id);
        handleDone(early);
      }
    } catch (e) {
      scanning = false;
      toastError(e);
    }
  }

  async function pickFolder() {
    const dir = await open({ directory: true, multiple: false, title: "Elige una carpeta para analizar" });
    if (typeof dir === "string") start(dir);
  }

  async function cancel() {
    if (scanId != null) await api.analyzerCancel(scanId);
  }

  async function openNode(node: number) {
    if (scanId == null) return;
    loadingList = true;
    try {
      listing = await api.analyzerList(scanId, node);
      selection = {};
    } catch (e) {
      toastError(e);
    } finally {
      loadingList = false;
    }
  }

  const ownFiles = $derived(listing ? listing.files.reduce((s, f) => s + f.size, 0) + listing.files_more_size : 0);
  const mapItems = $derived.by((): TreemapItem[] => {
    if (!listing) return [];
    const items: TreemapItem[] = listing.dirs.map((d) => ({ key: `d${d.id}`, label: d.name, value: d.size, kind: "dir", id: d.id }));
    if (ownFiles > 0) items.push({ key: "files", label: `Archivos sueltos (${num(listing.files.length + listing.files_more)})`, value: ownFiles, kind: "files" });
    return items;
  });

  function join(base: string, name: string) {
    return base.endsWith("\\") ? base + name : `${base}\\${name}`;
  }

  async function deleteSelected(paths = selected) {
    if (!paths.length || scanId == null) return;
    const sizeOf = (p: string) => {
      const d = listing?.dirs.find((x) => join(listing!.path, x.name) === p);
      if (d) return d.size;
      return listing?.files.find((f) => f.path === p)?.size ?? topFiles.find((f) => f.path === p)?.size ?? 0;
    };
    const total = paths.reduce((s, p) => s + sizeOf(p), 0);
    const ok = await ask({
      title: toRecycle ? `Enviar a la Papelera (${bytes(total)})` : `Eliminar definitivamente (${bytes(total)})`,
      body: toRecycle
        ? "Podrás recuperarlos desde la Papelera de reciclaje. El espacio no se libera hasta que la vacíes."
        : "Se borrarán para siempre. Asegúrate de que no contienen nada importante (partidas guardadas, fotos, proyectos).",
      details: paths.slice(0, 30).concat(paths.length > 30 ? [`… y ${paths.length - 30} más`] : []),
      confirm: toRecycle ? "Enviar a la Papelera" : "Eliminar",
      danger: true,
    });
    if (!ok) return;
    deleting = true;
    try {
      const r = await api.deletePaths(scanId, paths, toRecycle);
      if (r.deleted) toast(`${num(r.deleted)} elementos ${toRecycle ? "enviados a la Papelera" : "eliminados"} · ${bytes(r.freed)}`, "ok");
      if (r.failed.length) toast(`${r.failed.length} no se pudieron borrar: ${r.failed[0].error}`, "warn", 7000);
      summary = await api.analyzerSummary(scanId);
      if (listing) await openNode(listing.node.id);
      [topFiles, exts] = await Promise.all([api.analyzerTopFiles(scanId), api.analyzerExtensions(scanId)]);
    } catch (e) {
      toastError(e);
    } finally {
      deleting = false;
    }
  }

  const extTotal = $derived(exts.reduce((s, e) => s + e.size, 0));
  const kinds = $derived.by(() => {
    const m = new Map<string, { name: string; color: string; size: number; count: number }>();
    for (const e of exts) {
      const [name, color] = extKind(e.ext);
      const k = m.get(name) ?? { name, color, size: 0, count: 0 };
      k.size += e.size;
      k.count += e.count;
      m.set(name, k);
    }
    return [...m.values()].sort((a, b) => b.size - a.size);
  });
</script>

<div class="page">
  <div class="page-head">
    <div>
      <h1>Espacio en disco</h1>
      <p>Descubre qué carpetas y archivos ocupan más y decide qué hacer con ellos.</p>
    </div>
  </div>

  <section class="card pick">
    <div class="row wrap">
      {#each app.storage?.volumes ?? [] as v}
        {@const ratio = v.total ? (v.total - v.free) / v.total : 0}
        <button class="vol" disabled={scanning} onclick={() => start(`${v.letter}\\`)}>
          <Icon name="drive" size={20} />
          <div style="flex:1;min-width:0">
            <div class="row"><strong>{v.letter}</strong><span class="muted small ellipsis">{v.label || (v.is_system ? "Sistema" : "Local")}</span></div>
            <div class="bar thin" class:warn={ratio > 0.82} class:bad={ratio > 0.9} style="margin:5px 0 3px"><span style="width:{ratio * 100}%"></span></div>
            <span class="muted small">{bytes(v.free)} libres de {bytes(v.total, 0)}</span>
          </div>
        </button>
      {/each}
      <button class="vol folder" disabled={scanning} onclick={pickFolder}>
        <Icon name="folder" size={20} />
        <div><strong>Elegir carpeta…</strong><div class="muted small">Analiza solo una carpeta</div></div>
      </button>
    </div>
    {#if !app.admin}
      <p class="muted small" style="margin-top:10px">
        Consejo: como administrador NexFix puede leer la MFT de NTFS directamente (si tu sistema lo permite) y ver carpetas protegidas.
      </p>
    {/if}
  </section>

  {#if scanning}
    <section class="card scanning">
      <span class="spinner lg"></span>
      <div style="flex:1;min-width:0">
        <h2>Analizando…</h2>
        <p class="text-2">
          {num(progress?.files ?? 0)} archivos · {num(progress?.dirs ?? 0)} carpetas · {bytes(progress?.bytes ?? 0)}
        </p>
        <p class="muted small ellipsis mono">{progress?.current ?? ""}</p>
      </div>
      <button class="btn" onclick={cancel}><Icon name="stop" size={14} /> Cancelar</button>
    </section>
  {:else if summary && listing}
    <section class="card summary">
      <div class="stat"><span class="label">Analizado</span><span class="value">{summary.path}</span></div>
      <div class="stat"><span class="label">Tamaño</span><span class="value">{bytes(summary.root.size)}</span></div>
      <div class="stat"><span class="label">Archivos</span><span class="value">{num(summary.root.files)}</span></div>
      <div class="stat"><span class="label">Carpetas</span><span class="value">{num(summary.root.dirs)}</span></div>
      <div class="stat">
        <span class="label">Tiempo</span>
        <span class="value">{ms(summary.elapsed_ms)}<small>{summary.method === "mft" ? "MFT" : "paralelo"}</small></span>
      </div>
      {#if summary.errors}
        <div class="stat"><span class="label">Sin acceso</span><span class="value warn-text">{num(summary.errors)}</span></div>
      {/if}
    </section>

    <div class="row toolbar">
      <div class="tabs">
        <button class:active={tab === "folders"} onclick={() => (tab = "folders")}><Icon name="grid" size={15} /> Carpetas</button>
        <button class:active={tab === "files"} onclick={() => (tab = "files")}><Icon name="file" size={15} /> Más grandes</button>
        <button class:active={tab === "types"} onclick={() => (tab = "types")}><Icon name="pie" size={15} /> Tipos</button>
      </div>
      <span class="spacer"></span>
      <label class="row small text-2" title="Recomendado: podrás recuperar lo borrado">
        <Toggle checked={toRecycle} label="Enviar a la Papelera" onchange={(v) => (toRecycle = v)} />
        Enviar a la Papelera
      </label>
      <button class="btn danger" disabled={!selected.length || deleting} onclick={() => deleteSelected()}>
        {#if deleting}<span class="spinner"></span>{:else}<Icon name="trash" size={15} />{/if}
        {selected.length ? `Borrar ${selected.length}` : "Borrar"}
      </button>
    </div>

    {#if tab === "folders"}
      <div class="crumbs">
        {#each listing.crumbs as c, i}
          {#if i > 0}<Icon name="right" size={14} />{/if}
          <button class:current={i === listing.crumbs.length - 1} onclick={() => openNode(c.id)}>{c.name}</button>
        {/each}
        <span class="spacer"></span>
        <button class="btn ghost sm" onclick={() => api.reveal(listing!.path)}><Icon name="external" size={14} /> Abrir en el Explorador</button>
      </div>

      <div class="folder-view">
        <section class="card map-card" class:dim={loadingList}>
          <Treemap items={mapItems} total={listing.node.size} onopen={(it) => it.id != null && openNode(it.id)} />
        </section>

        <section class="card flush list-card" class:dim={loadingList}>
          <table class="table entries">
            <thead>
              <tr><th style="width:28px"></th><th>Nombre</th><th class="num">Tamaño</th><th style="width:22%"></th><th class="num">Archivos</th><th class="num">Modificado</th><th></th></tr>
            </thead>
            <tbody>
              {#if listing.node.id !== 0}
                <tr class="up" onclick={() => openNode(listing!.crumbs[listing!.crumbs.length - 2].id)}>
                  <td></td><td colspan="6"><Icon name="back" size={14} /> Subir un nivel</td>
                </tr>
              {/if}
              {#each listing.dirs as d (d.id)}
                {@const p = join(listing.path, d.name)}
                <tr ondblclick={() => openNode(d.id)}>
                  <td><input type="checkbox" bind:checked={selection[p]} disabled={d.skipped} /></td>
                  <td>
                    <button class="name-btn" onclick={() => openNode(d.id)}>
                      <Icon name="folder" size={16} class="dir-ic" />
                      <span class="ellipsis">{d.name}</span>
                      {#if d.skipped}<span class="badge" title="Capas virtuales de contenedores: no se recorren por rendimiento">omitida</span>{/if}
                      {#if d.denied}<span class="badge warn">sin acceso</span>{/if}
                    </button>
                  </td>
                  <td class="num"><strong>{bytes(d.size)}</strong></td>
                  <td>
                    <div class="bar thin grad"><span style="width:{listing.node.size ? (d.size / listing.node.size) * 100 : 0}%"></span></div>
                    <span class="muted small">{pct(d.size, listing.node.size, 1)}</span>
                  </td>
                  <td class="num muted">{num(d.files)}</td>
                  <td class="num muted">{date(d.mtime)}</td>
                  <td class="acts">
                    <button class="btn ghost icon-only" title="Abrir en el Explorador" onclick={() => api.reveal(p)}><Icon name="external" size={14} /></button>
                  </td>
                </tr>
              {/each}
              {#each listing.files as f (f.path)}
                <tr>
                  <td><input type="checkbox" bind:checked={selection[f.path]} /></td>
                  <td><span class="name-btn static"><Icon name="file" size={16} class="file-ic" /><span class="ellipsis">{f.name}</span></span></td>
                  <td class="num">{bytes(f.size)}</td>
                  <td>
                    <div class="bar thin"><span style="width:{listing.node.size ? (f.size / listing.node.size) * 100 : 0}%"></span></div>
                    <span class="muted small">{pct(f.size, listing.node.size, 1)}</span>
                  </td>
                  <td class="num muted">—</td>
                  <td class="num muted">{date(f.mtime)}</td>
                  <td class="acts">
                    <button class="btn ghost icon-only" title="Mostrar en el Explorador" onclick={() => api.reveal(f.path)}><Icon name="external" size={14} /></button>
                  </td>
                </tr>
              {/each}
              {#if listing.files_more}
                <tr><td></td><td colspan="6" class="muted small">Y {num(listing.files_more)} archivos más pequeños ({bytes(listing.files_more_size)})</td></tr>
              {/if}
              {#if !listing.dirs.length && !listing.files.length}
                <tr><td></td><td colspan="6" class="muted">Carpeta vacía.</td></tr>
              {/if}
            </tbody>
          </table>
        </section>
      </div>
    {:else if tab === "files"}
      <section class="card flush">
        <table class="table entries">
          <thead><tr><th style="width:28px"></th><th>Archivo</th><th class="num">Tamaño</th><th class="num">Modificado</th><th></th></tr></thead>
          <tbody>
            {#each topFiles as f (f.path)}
              <tr>
                <td><input type="checkbox" bind:checked={selection[f.path]} /></td>
                <td>
                  <div class="ellipsis"><strong>{f.name}</strong></div>
                  <div class="muted small ellipsis selectable" title={f.path}>{f.path}</div>
                </td>
                <td class="num"><strong>{bytes(f.size)}</strong></td>
                <td class="num muted">{date(f.mtime)}</td>
                <td class="acts"><button class="btn ghost icon-only" title="Mostrar en el Explorador" onclick={() => api.reveal(f.path)}><Icon name="external" size={14} /></button></td>
              </tr>
            {/each}
          </tbody>
        </table>
      </section>
    {:else}
      <div class="types">
        <section class="card">
          <div class="card-head"><h2>Por categoría</h2></div>
          <div class="stack">
            {#each kinds as k}
              <div>
                <div class="row small"><span class="dot" style="background:{k.color}"></span><strong>{k.name}</strong><span class="spacer"></span><span>{bytes(k.size)}</span></div>
                <div class="bar thin" style="margin-top:5px"><span style="width:{extTotal ? (k.size / extTotal) * 100 : 0}%;background:{k.color}"></span></div>
              </div>
            {/each}
          </div>
        </section>
        <section class="card flush">
          <table class="table entries">
            <thead><tr><th>Extensión</th><th>Tipo</th><th class="num">Tamaño</th><th style="width:30%"></th><th class="num">Archivos</th></tr></thead>
            <tbody>
              {#each exts as e (e.ext)}
                {@const [kn, kc] = extKind(e.ext)}
                <tr>
                  <td class="mono">{e.ext ? `.${e.ext}` : "(sin extensión)"}</td>
                  <td><span class="dot" style="background:{kc}"></span> {kn}</td>
                  <td class="num"><strong>{bytes(e.size)}</strong></td>
                  <td><div class="bar thin"><span style="width:{extTotal ? (e.size / exts[0].size) * 100 : 0}%;background:{kc}"></span></div></td>
                  <td class="num muted">{num(e.count)}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </section>
      </div>
    {/if}
  {:else}
    <div class="empty card">
      <Icon name="pie" size={40} stroke={1.5} />
      <h2>Elige una unidad o carpeta</h2>
      <p>NexFix recorre el disco en paralelo y te muestra qué ocupa más, en segundos.</p>
    </div>
  {/if}
</div>

<style>
  .pick {
    margin-bottom: 14px;
  }
  .vol {
    display: flex;
    align-items: center;
    gap: 12px;
    width: 250px;
    padding: 12px 14px;
    text-align: left;
    background: var(--panel-2);
    border: 1px solid var(--line);
    border-radius: var(--radius);
    cursor: pointer;
    color: var(--text);
    transition: border-color 0.15s, background 0.15s;
  }
  .vol:hover:not(:disabled) {
    border-color: var(--accent);
    background: var(--panel-3);
  }
  .vol:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
  .vol :global(.icon) {
    color: var(--accent);
  }
  .vol.folder {
    width: auto;
    border-style: dashed;
  }
  .scanning {
    display: flex;
    align-items: center;
    gap: 18px;
  }
  .summary {
    display: flex;
    gap: 34px;
    flex-wrap: wrap;
    margin-bottom: 14px;
  }
  .summary .value {
    font-size: 17px;
  }
  .toolbar {
    margin-bottom: 12px;
    gap: 14px;
  }
  .crumbs {
    display: flex;
    align-items: center;
    gap: 4px;
    margin-bottom: 10px;
    flex-wrap: wrap;
    color: var(--muted);
  }
  .crumbs button:not(.btn) {
    background: none;
    border: none;
    color: var(--text-2);
    cursor: pointer;
    padding: 3px 6px;
    border-radius: 6px;
    font-weight: 550;
  }
  .crumbs button:not(.btn):hover {
    background: var(--panel-3);
  }
  .crumbs button.current {
    color: var(--text);
  }
  .folder-view {
    display: grid;
    grid-template-rows: 300px auto;
    gap: 14px;
  }
  .map-card {
    padding: 8px;
  }
  .dim {
    opacity: 0.55;
    pointer-events: none;
    transition: opacity 0.15s;
  }
  .entries td {
    padding-top: 6px;
    padding-bottom: 6px;
  }
  .entries tbody tr:hover {
    background: var(--panel-2);
  }
  .entries tr.up {
    cursor: pointer;
    color: var(--text-2);
  }
  .name-btn {
    display: flex;
    align-items: center;
    gap: 8px;
    background: none;
    border: none;
    padding: 0;
    color: var(--text);
    cursor: pointer;
    max-width: 420px;
    min-width: 0;
    font-weight: 550;
    text-align: left;
  }
  .name-btn.static {
    cursor: default;
    font-weight: 400;
    color: var(--text-2);
  }
  .name-btn :global(.dir-ic) {
    color: var(--warn);
  }
  .name-btn :global(.file-ic) {
    color: var(--muted);
  }
  .acts {
    width: 40px;
    text-align: right;
  }
  .types {
    display: grid;
    grid-template-columns: 320px 1fr;
    gap: 14px;
    align-items: start;
  }
  .dot {
    display: inline-block;
    width: 9px;
    height: 9px;
    border-radius: 3px;
    margin-right: 4px;
  }
</style>
