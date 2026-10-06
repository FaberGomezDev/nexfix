<script lang="ts">
  import { onMount } from "svelte";
  import Icon from "../components/Icon.svelte";
  import { ago, bytes, daysSince, duration, isoDate } from "../format";
  import { ratedSpeed } from "../insights";
  import { app, loadSystem, toastError } from "../state.svelte";

  let { active }: { active: boolean } = $props();
  let loading = $state(false);

  async function refresh(force = false) {
    loading = true;
    try {
      await loadSystem(force);
    } catch (e) {
      toastError(e);
    } finally {
      loading = false;
    }
  }
  onMount(() => refresh());

  const s = $derived(app.system);
  const totalSlots = $derived(Math.max(s?.memory.slots ?? 0, s?.memory.modules.length ?? 0));
</script>

<div class="page">
  <div class="page-head">
    <div>
      <h1>Componentes</h1>
      <p>Inventario de tu hardware y cómo está configurado.</p>
    </div>
    <button class="btn" onclick={() => refresh(true)} disabled={loading || !active}>
      {#if loading}<span class="spinner"></span>{:else}<Icon name="refresh" size={16} />{/if} Actualizar
    </button>
  </div>

  {#if !s}
    <div class="grid c2">{#each Array(4) as _}<div class="skeleton" style="height:200px"></div>{/each}</div>
  {:else}
    <div class="grid c2">
      <section class="card">
        <div class="card-head">
          <div class="icon-box"><Icon name="cpu" size={17} /></div>
          <h2>Procesador</h2>
          <span class="badge info">{s.cpu.socket || s.cpu.vendor}</span>
        </div>
        <h3 class="big">{s.cpu.name}</h3>
        <div class="stats">
          <div class="stat"><span class="label">Núcleos</span><span class="value">{s.cpu.cores}</span></div>
          <div class="stat"><span class="label">Hilos</span><span class="value">{s.cpu.threads}</span></div>
          <div class="stat"><span class="label">Frecuencia base</span><span class="value">{(s.cpu.max_mhz / 1000).toLocaleString("es-ES", { maximumFractionDigits: 1 })}<small>GHz</small></span></div>
          <div class="stat"><span class="label">Caché L3</span><span class="value">{Math.round(s.cpu.l3_kb / 1024)}<small>MB</small></span></div>
        </div>
        <p class="muted small" style="margin-top:12px">
          La temperatura de la CPU requiere un driver de sensores (como el de HWiNFO o Ryzen Master); NexFix no instala drivers de kernel por seguridad.
        </p>
      </section>

      <section class="card">
        <div class="card-head">
          <div class="icon-box"><Icon name="memory" size={17} /></div>
          <h2>Memoria RAM</h2>
          <span class="badge info">{bytes(s.memory.total, 0)}</span>
        </div>
        <table class="table">
          <thead>
            <tr><th>Ranura</th><th>Módulo</th><th class="num">Tamaño</th><th class="num">Velocidad</th></tr>
          </thead>
          <tbody>
            {#each s.memory.modules as m}
              {@const rated = ratedSpeed(m)}
              <tr>
                <td>{m.locator || "—"}</td>
                <td>
                  <div>{m.manufacturer} <span class="muted">{m.mem_type}</span></div>
                  <div class="mono muted selectable">{m.part_number}</div>
                </td>
                <td class="num">{bytes(m.capacity, 0)}</td>
                <td class="num">
                  <strong>{m.configured_speed || m.speed} MT/s</strong>
                  {#if rated}<div class="muted small">kit: {rated} MT/s</div>{/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
        <p class="muted small" style="margin-top:10px">
          {s.memory.modules.length} de {totalSlots || "?"} ranuras ocupadas{s.memory.modules.length >= 2 ? " · dual channel" : ""}.
          La velocidad configurada es la real; la del kit sale del número de pieza.
        </p>
      </section>

      <section class="card">
        <div class="card-head">
          <div class="icon-box"><Icon name="gpu" size={17} /></div>
          <h2>Gráficos</h2>
        </div>
        <div class="stack">
          {#each s.gpus as g}
            {@const days = daysSince(g.driver_date)}
            <div class="gpu">
              <div class="row">
                <strong class="ellipsis" style="flex:1">{g.name}</strong>
                <span class="badge {g.integrated ? '' : 'violet'}">{g.integrated ? "Integrada" : "Dedicada"}</span>
              </div>
              <dl class="kv">
                <dt>VRAM</dt><dd>{bytes(g.vram, 0)}</dd>
                <dt>Driver</dt><dd class="selectable">{g.driver_version}</dd>
                <dt>Fecha del driver</dt>
                <dd class:warn-text={days != null && days > 365}>{isoDate(g.driver_date)}{days != null ? ` (hace ${ago(days)})` : ""}</dd>
                {#if g.width}<dt>Salida</dt><dd>{g.width}×{g.height} @ {g.refresh_rate} Hz</dd>{/if}
              </dl>
            </div>
          {/each}
        </div>
      </section>

      <section class="card">
        <div class="card-head">
          <div class="icon-box"><Icon name="monitor" size={17} /></div>
          <h2>Pantallas</h2>
        </div>
        <div class="stack">
          {#each s.displays as d}
            <div class="gpu">
              <div class="row">
                <strong class="ellipsis" style="flex:1">{d.name}</strong>
                {#if d.primary}<span class="badge info">Principal</span>{/if}
              </div>
              <dl class="kv">
                <dt>Resolución</dt><dd>{d.width}×{d.height}</dd>
                <dt>Frecuencia</dt>
                <dd class:warn-text={d.max_hz > d.current_hz + 5} class:ok-text={d.max_hz <= d.current_hz + 5}>
                  {d.current_hz} Hz {d.max_hz > d.current_hz + 5 ? `(admite ${d.max_hz} Hz)` : "(la máxima)"}
                </dd>
                <dt>Conectada a</dt><dd>{d.adapter}</dd>
              </dl>
              {#if d.max_hz > d.current_hz + 5}
                <div class="callout warn" style="margin-top:10px">
                  <Icon name="alert" size={16} />
                  <span>Estás perdiendo fluidez: cámbiala en <b>Configuración › Pantalla › Pantalla avanzada</b> a {d.max_hz} Hz.</span>
                </div>
              {/if}
            </div>
          {/each}
        </div>
      </section>

      <section class="card">
        <div class="card-head">
          <div class="icon-box"><Icon name="board" size={17} /></div>
          <h2>Placa base y BIOS</h2>
        </div>
        <dl class="kv">
          <dt>Placa</dt><dd>{s.board.manufacturer} {s.board.product}</dd>
          <dt>BIOS</dt><dd>{s.board.bios_vendor} · {s.board.bios_version}</dd>
          <dt>Fecha BIOS</dt>
          <dd>{isoDate(s.board.bios_date)}{daysSince(s.board.bios_date) != null ? ` (hace ${ago(daysSince(s.board.bios_date)!)})` : ""}</dd>
          <dt>Sistema</dt><dd>{s.board.system_model}</dd>
        </dl>
      </section>

      <section class="card">
        <div class="card-head">
          <div class="icon-box"><Icon name="windows" size={17} /></div>
          <h2>Sistema operativo</h2>
        </div>
        <dl class="kv">
          <dt>Windows</dt><dd>{s.os.name}</dd>
          <dt>Compilación</dt><dd>{s.os.build} · {s.os.arch}</dd>
          <dt>Equipo</dt><dd>{s.os.hostname}</dd>
          <dt>Instalado</dt><dd>{isoDate(s.os.install_date)}</dd>
          <dt>Encendido</dt><dd>{duration(s.os.uptime_secs)}</dd>
          <dt>Permisos</dt><dd>{s.is_admin ? "Administrador" : "Estándar"}</dd>
        </dl>
      </section>
    </div>
  {/if}
</div>

<style>
  .big {
    font-size: 18px;
    margin-bottom: 14px;
  }
  .stats {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 12px;
  }
  .gpu {
    padding: 12px 14px;
    background: var(--panel-2);
    border-radius: var(--radius-sm);
    border: 1px solid var(--line);
  }
  .gpu .kv {
    margin-top: 8px;
  }
</style>
