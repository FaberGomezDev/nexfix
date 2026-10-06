<script lang="ts">
  import { onMount } from "svelte";
  import type { PhysicalDisk } from "../api";
  import Icon from "../components/Icon.svelte";
  import Ring from "../components/Ring.svelte";
  import { bytes, bytesDecimal, num, pct } from "../format";
  import { app, go, loadStorage, relaunchAsAdmin, toastError } from "../state.svelte";

  let loading = $state(false);

  async function refresh(force = false) {
    loading = true;
    try {
      await loadStorage(force);
    } catch (e) {
      toastError(e);
    } finally {
      loading = false;
    }
  }
  onMount(() => refresh());

  const st = $derived(app.storage);

  function tempColor(t: number) {
    return t >= 70 ? "var(--bad)" : t >= 55 ? "var(--warn)" : "var(--ok)";
  }
  function healthBadge(h: string) {
    return h === "healthy" ? ["ok", "Saludable"] : h === "warning" ? ["warn", "Advertencia"] : h === "unhealthy" ? ["bad", "Con fallos"] : ["", "Desconocido"];
  }

  function freeRatio(d: PhysicalDisk) {
    const vols = st?.volumes.filter((v) => v.disk_number === d.number) ?? [];
    const total = vols.reduce((s, v) => s + v.total, 0);
    const free = vols.reduce((s, v) => s + v.free, 0);
    return total ? free / total : null;
  }

  interface Check {
    ok: boolean | null;
    title: string;
    detail: string;
  }

  function checklist(d: PhysicalDisk): Check[] {
    const n = d.nvme;
    const free = freeRatio(d);
    const list: Check[] = [
      {
        ok: st?.trim_ntfs ?? null,
        title: st?.trim_ntfs === false ? "TRIM desactivado" : "TRIM activado",
        detail: "Windows avisa al SSD de los bloques borrados para que siga escribiendo rápido. Debe estar activo siempre.",
      },
      {
        ok: free == null ? null : free >= 0.15,
        title: free == null ? "Espacio libre" : `${Math.round(free * 100)} % de espacio libre`,
        detail: "Deja al menos un 15-20 % libre: el SSD usa ese espacio para repartir el desgaste y mantener la velocidad.",
      },
    ];
    if (n) {
      list.push(
        {
          ok: n.temperature_c < 70,
          title: `Temperatura ${n.temperature_c} °C`,
          detail:
            n.temperature_c < 55
              ? "Temperatura excelente."
              : n.temperature_c < 70
                ? "Correcta. En partidas largas vigila que no pase de 70 °C."
                : "Alta: el M.2 puede bajar su velocidad. Usa el disipador de la placa base y mejora el flujo de aire.",
        },
        {
          ok: n.percentage_used < 80 && n.available_spare > n.spare_threshold,
          title: `Vida útil restante ${Math.max(0, 100 - n.percentage_used)} %`,
          detail: `Reserva de bloques ${n.available_spare} % (mínimo ${n.spare_threshold} %). ${bytesDecimal(n.data_written_bytes)} escritos en total.`,
        },
        {
          ok: n.media_errors === 0 && n.critical_warning === 0,
          title: n.media_errors === 0 ? "Sin errores de datos" : `${n.media_errors} errores de datos`,
          detail: "Errores de integridad detectados por el propio controlador del SSD.",
        },
      );
      if (n.unsafe_shutdowns > 0) {
        list.push({
          ok: null,
          title: `${num(n.unsafe_shutdowns)} apagados inesperados`,
          detail: "Cortes de luz o apagados con el botón. Apaga siempre desde Windows; un SAI protege también al SSD.",
        });
      }
    }
    list.push(
      {
        ok: null,
        title: `Firmware ${d.firmware || "—"}`,
        detail: d.vendor_tool
          ? `Busca actualizaciones de firmware con ${d.vendor_tool}: corrigen fallos y mejoran la durabilidad.`
          : "Busca actualizaciones de firmware en la web del fabricante.",
      },
      {
        ok: null,
        title: "No lo desfragmentes",
        detail: "En SSD/M.2 la desfragmentación no aporta nada y gasta escrituras. NexFix usa ReTrim, que es lo correcto.",
      },
    );
    return list;
  }

  function runRetrim(d: PhysicalDisk) {
    const letter = d.volumes[0];
    if (!letter) return;
    app.taskRequest = { id: "retrim", drive: letter };
    go("maintenance");
  }

  function analyze(letter: string) {
    app.analyzeRequest = `${letter}\\`;
    go("analyzer");
  }
</script>

<div class="page">
  <div class="page-head">
    <div>
      <h1>Discos y M.2</h1>
      <p>Salud, temperatura, desgaste y mantenimiento de tus unidades.</p>
    </div>
    <button class="btn" onclick={() => refresh(true)} disabled={loading}>
      {#if loading}<span class="spinner"></span>{:else}<Icon name="refresh" size={16} />{/if} Actualizar
    </button>
  </div>

  {#if !st}
    <div class="skeleton" style="height:320px"></div>
  {:else}
    {#if !st.is_admin && st.disks.some((d) => d.is_nvme)}
      <div class="callout info" style="margin-bottom:14px">
        <Icon name="shield" size={18} />
        <div style="flex:1">
          <strong>Lee el SMART completo de tu M.2</strong>
          <p class="muted">Temperatura, desgaste, TB escritos y errores requieren permisos de administrador.</p>
        </div>
        <button class="btn sm grad" onclick={relaunchAsAdmin}>Reiniciar como admin</button>
      </div>
    {/if}

    <div class="stack">
      {#each st.disks as d (d.number)}
        {@const [hb, ht] = healthBadge(d.health)}
        {@const n = d.nvme}
        <section class="card disk">
          <div class="card-head">
            <div class="icon-box"><Icon name="drive" size={17} /></div>
            <div style="flex:1;min-width:0">
              <h2 class="ellipsis">{d.model}</h2>
              <span class="muted small">Disco {d.number} · {bytes(d.size, 0)} · {d.volumes.join(", ") || "sin letra"}</span>
            </div>
            {#if d.is_nvme}<span class="badge violet">M.2 NVMe</span>{:else}<span class="badge">{d.bus}</span>{/if}
            <span class="badge">{d.media}</span>
            <span class="badge {hb}">{ht}</span>
          </div>

          {#if n}
            <div class="smart">
              <div class="rings">
                <Ring value={100 - n.percentage_used} size={110} thickness={10} color={n.percentage_used >= 80 ? "var(--bad)" : "var(--ok)"} label={`${Math.max(0, 100 - n.percentage_used)}%`} sub="vida útil" />
                <Ring value={Math.min(100, (n.temperature_c / 85) * 100)} size={110} thickness={10} color={tempColor(n.temperature_c)} label={`${n.temperature_c}°`} sub="temperatura" />
              </div>
              <div class="grid c4 smart-stats">
                <div class="stat"><span class="label">Escrito</span><span class="value">{bytesDecimal(n.data_written_bytes)}</span></div>
                <div class="stat"><span class="label">Leído</span><span class="value">{bytesDecimal(n.data_read_bytes)}</span></div>
                <div class="stat"><span class="label">Horas encendido</span><span class="value">{num(n.power_on_hours)}<small>h</small></span></div>
                <div class="stat"><span class="label">Encendidos</span><span class="value">{num(n.power_cycles)}</span></div>
                <div class="stat"><span class="label">Reserva</span><span class="value">{n.available_spare}<small>%</small></span></div>
                <div class="stat"><span class="label">Errores de datos</span><span class="value" class:bad-text={n.media_errors > 0}>{num(n.media_errors)}</span></div>
                <div class="stat"><span class="label">Apagados inesperados</span><span class="value">{num(n.unsafe_shutdowns)}</span></div>
                <div class="stat"><span class="label">Min. sobre temp. aviso</span><span class="value">{num(n.warning_temp_minutes)}</span></div>
              </div>
            </div>
          {:else if d.reliability}
            <dl class="kv" style="margin-bottom:12px">
              {#if d.reliability.temperature}<dt>Temperatura</dt><dd>{d.reliability.temperature} °C</dd>{/if}
              {#if d.reliability.wear != null}<dt>Desgaste</dt><dd>{d.reliability.wear} %</dd>{/if}
              {#if d.reliability.power_on_hours != null}<dt>Horas encendido</dt><dd>{num(d.reliability.power_on_hours)} h</dd>{/if}
              {#if d.reliability.read_errors != null}<dt>Errores de lectura</dt><dd>{num(d.reliability.read_errors)}</dd>{/if}
            </dl>
          {:else if d.nvme_error}
            <p class="muted small" style="margin-bottom:12px">{d.nvme_error}</p>
          {/if}

          {#if d.is_ssd}
            <h3 class="sub">Mantenimiento del {d.is_nvme ? "M.2" : "SSD"}</h3>
            <ul class="checks">
              {#each checklist(d) as c}
                <li>
                  <span class="ck" class:ok={c.ok === true} class:bad={c.ok === false}>
                    <Icon name={c.ok === true ? "check" : c.ok === false ? "alert" : "info"} size={16} />
                  </span>
                  <div>
                    <strong>{c.title}</strong>
                    <p>{c.detail}</p>
                  </div>
                </li>
              {/each}
            </ul>
            <div class="row wrap" style="margin-top:12px">
              <button class="btn primary" disabled={!d.volumes.length} onclick={() => runRetrim(d)}>
                <Icon name="zap" size={16} /> Ejecutar ReTrim ahora
              </button>
              {#each d.volumes as v}
                <button class="btn" onclick={() => analyze(v)}><Icon name="pie" size={16} /> Analizar {v}</button>
              {/each}
              {#if !app.admin}<span class="muted small">ReTrim requiere administrador.</span>{/if}
            </div>
          {/if}
        </section>
      {/each}

      <div class="grid c2">
        <section class="card">
          <div class="card-head">
            <div class="icon-box"><Icon name="layers" size={17} /></div>
            <h2>Volúmenes</h2>
          </div>
          <div class="stack">
            {#each st.volumes as v}
              {@const used = v.total - v.free}
              {@const ratio = v.total ? used / v.total : 0}
              <div>
                <div class="row">
                  <strong>{v.letter}</strong>
                  <span class="muted small">{v.label || (v.is_system ? "Sistema" : "Local")} · {v.fs}</span>
                  <span class="spacer"></span>
                  <span class="small">{bytes(v.free)} libres de {bytes(v.total, 0)}</span>
                </div>
                <div class="bar" class:warn={ratio > 0.82} class:bad={ratio > 0.9} style="margin-top:6px">
                  <span style="width:{ratio * 100}%"></span>
                </div>
                <div class="muted small" style="margin-top:4px">{pct(used, v.total)} usado</div>
              </div>
            {/each}
          </div>
        </section>

        <section class="card">
          <div class="card-head">
            <div class="icon-box"><Icon name="file" size={17} /></div>
            <h2>Archivos del sistema</h2>
          </div>
          <dl class="kv">
            <dt>Archivo de paginación (pagefile.sys)</dt><dd>{bytes(st.system_files.pagefile)}</dd>
            <dt>Hibernación (hiberfil.sys)</dt><dd>{bytes(st.system_files.hiberfil)}</dd>
            <dt>Swap de apps (swapfile.sys)</dt><dd>{bytes(st.system_files.swapfile)}</dd>
          </dl>
          <p class="muted small" style="margin-top:12px">
            No los borres a mano. El de paginación lo gestiona Windows (déjalo en automático); la hibernación se puede desactivar en
            <button class="link" onclick={() => go("optimize")}>Optimización</button> si nunca hibernas.
          </p>
          {#if st.windows_old}
            <div class="callout warn" style="margin-top:12px">
              <Icon name="alert" size={16} />
              <span>Hay una carpeta Windows.old. Bórrala desde Configuración › Almacenamiento › Archivos temporales.</span>
            </div>
          {/if}
        </section>
      </div>
    </div>
  {/if}
</div>

<style>
  .smart {
    display: flex;
    gap: 28px;
    align-items: center;
    padding: 6px 0 16px;
    border-bottom: 1px solid var(--line);
    margin-bottom: 14px;
  }
  .rings {
    display: flex;
    gap: 16px;
  }
  .smart-stats {
    flex: 1;
    gap: 14px 18px;
  }
  .smart-stats .value {
    font-size: 17px;
  }
  .sub {
    margin-bottom: 8px;
  }
  .checks {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 8px 18px;
  }
  .checks li {
    display: flex;
    gap: 10px;
    align-items: flex-start;
    padding: 8px 0;
  }
  .checks p {
    color: var(--muted);
    font-size: 12.5px;
  }
  .ck {
    width: 26px;
    height: 26px;
    border-radius: 8px;
    display: grid;
    place-items: center;
    background: var(--accent-soft);
    color: var(--accent);
    flex: none;
  }
  .ck.ok {
    background: var(--ok-soft);
    color: var(--ok);
  }
  .ck.bad {
    background: var(--bad-soft);
    color: var(--bad);
  }
  .link {
    background: none;
    border: none;
    color: var(--accent);
    padding: 0;
    cursor: pointer;
    font-size: inherit;
  }
  .kv dt {
    max-width: 260px;
  }
  @media (max-width: 1180px) {
    .smart {
      flex-direction: column;
      align-items: stretch;
    }
    .checks {
      grid-template-columns: 1fr;
    }
  }
</style>
