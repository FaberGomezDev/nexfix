<script lang="ts">
  import { onMount } from "svelte";
  import { api } from "../api";
  import Icon from "../components/Icon.svelte";
  import Toggle from "../components/Toggle.svelte";
  import { bytes } from "../format";
  import { app, ask, loadStartup, loadTweaks, relaunchAsAdmin, toast, toastError } from "../state.svelte";

  let busy = $state<Record<string, boolean>>({});
  let filter = $state("");

  onMount(() => {
    loadTweaks().catch(toastError);
    loadStartup().catch(toastError);
  });

  const tw = $derived(app.tweaks);
  const isRyzen = $derived(/ryzen/i.test(app.system?.cpu.name ?? ""));

  interface TweakDef {
    key: "game_mode" | "game_dvr" | "hags" | "mouse_accel" | "hibernation" | "storage_sense";
    icon: string;
    title: string;
    detail: string;
    recommended: boolean;
    admin?: boolean;
    reboot?: boolean;
  }

  const defs: TweakDef[] = [
    {
      key: "game_mode",
      icon: "gamepad",
      title: "Modo juego",
      detail: "Windows da prioridad al juego y no instala actualizaciones ni muestra notificaciones mientras juegas.",
      recommended: true,
    },
    {
      key: "game_dvr",
      icon: "video",
      title: "Grabación de Xbox Game Bar",
      detail: "Captura en segundo plano. Desactívala si grabas con NVIDIA App, Adrenalin u OBS: ahorra GPU y disco.",
      recommended: false,
    },
    {
      key: "hags",
      icon: "gpu",
      title: "Programación de GPU acelerada por hardware (HAGS)",
      detail: "Reduce latencia en GPUs modernas y es necesaria para DLSS Frame Generation. Requiere reiniciar.",
      recommended: true,
      admin: true,
      reboot: true,
    },
    {
      key: "mouse_accel",
      icon: "mouse",
      title: "Aceleración del ratón (\"Mejorar precisión del puntero\")",
      detail: "Con ella el cursor recorre más o menos según la velocidad del gesto. En juegos de puntería se suele desactivar.",
      recommended: false,
    },
    {
      key: "hibernation",
      icon: "moon",
      title: "Hibernación e Inicio rápido",
      detail: "Desactivarla libera el archivo hiberfil.sys y hace arranques \"limpios\". Activada, el PC arranca algo más rápido.",
      recommended: true,
      admin: true,
    },
    {
      key: "storage_sense",
      icon: "sparkles",
      title: "Sensor de almacenamiento",
      detail: "Windows borra automáticamente temporales y vacía la Papelera periódicamente.",
      recommended: true,
    },
  ];

  function value(key: TweakDef["key"]): boolean {
    if (!tw) return false;
    return key === "hags" ? tw.hags ?? true : (tw[key] as boolean);
  }

  async function setTweak(d: TweakDef, v: boolean) {
    if (d.admin && !app.admin) {
      relaunchAsAdmin();
      return;
    }
    if (d.key === "hibernation" && !v) {
      const ok = await ask({
        title: "Desactivar hibernación",
        body: `Se liberarán ${bytes(tw?.hiberfil_size ?? 0)} y se desactivará el Inicio rápido de Windows. Puedes volver a activarla cuando quieras.`,
        confirm: "Desactivar",
      });
      if (!ok) return;
    }
    busy[d.key] = true;
    try {
      await api.tweakSet(d.key, v);
      await loadTweaks(true);
      toast(d.reboot ? "Cambio guardado. Reinicia el PC para aplicarlo." : "Ajuste aplicado", "ok");
    } catch (e) {
      toastError(e);
    } finally {
      busy[d.key] = false;
    }
  }

  async function setPlan(guid: string) {
    busy.plan = true;
    try {
      await api.powerPlanSet(guid);
      await loadTweaks(true);
      toast("Plan de energía cambiado", "ok");
    } catch (e) {
      toastError(e);
    } finally {
      busy.plan = false;
    }
  }

  async function addUltimate() {
    busy.plan = true;
    try {
      await api.powerPlanAddUltimate();
      await loadTweaks(true);
      toast("Plan \"Máximo rendimiento\" añadido", "ok");
    } catch (e) {
      toastError(e);
    } finally {
      busy.plan = false;
    }
  }

  const planHint = (name: string) => {
    const n = name.toLowerCase();
    if (n.includes("equilibrado") || n.includes("balanced"))
      return isRyzen ? "Recomendado en Ryzen: sube a máxima frecuencia al instante y ahorra en reposo." : "Buen equilibrio para el día a día.";
    if (n.includes("alto") || n.includes("high")) return "La CPU se mantiene en frecuencias altas. Algo más de consumo y temperatura.";
    if (n.includes("máximo") || n.includes("ultimate") || n.includes("maximo")) return "Elimina casi todo el ahorro de energía. Útil solo en casos concretos.";
    if (n.includes("econom") || n.includes("ahorro") || n.includes("saver")) return "Limita la CPU: evítalo para jugar.";
    return "";
  };

  async function setStartup(id: string, enabled: boolean, machine: boolean) {
    if (machine && !app.admin) {
      relaunchAsAdmin();
      return;
    }
    busy[id] = true;
    try {
      await api.startupSet(id, enabled);
      const item = app.startup?.find((s) => s.id === id);
      if (item) item.enabled = enabled;
    } catch (e) {
      toastError(e);
    } finally {
      busy[id] = false;
    }
  }

  const startup = $derived(
    (app.startup ?? []).filter((s) => !filter || s.name.toLowerCase().includes(filter.toLowerCase()) || s.command.toLowerCase().includes(filter.toLowerCase())),
  );
  const enabledCount = $derived((app.startup ?? []).filter((s) => s.enabled).length);
</script>

<div class="page">
  <div class="page-head">
    <div>
      <h1>Optimización</h1>
      <p>Ajustes de Windows que afectan a tus juegos. Todos se pueden revertir.</p>
    </div>
  </div>

  {#if !tw}
    <div class="skeleton" style="height:300px"></div>
  {:else}
    <div class="grid c2 top">
      <section class="card">
        <div class="card-head">
          <div class="icon-box"><Icon name="power" size={17} /></div>
          <h2>Plan de energía</h2>
          {#if busy.plan}<span class="spinner"></span>{/if}
        </div>
        <div class="plans">
          {#each tw.power_plans as p (p.guid)}
            <label class="plan" class:active={p.active}>
              <input type="radio" name="plan" checked={p.active} disabled={busy.plan} onchange={() => setPlan(p.guid)} />
              <div>
                <strong>{p.name}</strong>
                {#if planHint(p.name)}<p class="muted small">{planHint(p.name)}</p>{/if}
              </div>
              {#if p.active}<span class="badge ok">Activo</span>{/if}
            </label>
          {/each}
        </div>
        {#if !tw.power_plans.some((p) => /máximo|maximo|ultimate/i.test(p.name))}
          <button class="btn sm ghost" style="margin-top:8px" onclick={addUltimate} disabled={busy.plan}>
            <Icon name="plus" size={14} /> Añadir "Máximo rendimiento"
          </button>
        {/if}
      </section>

      <section class="card">
        <div class="card-head">
          <div class="icon-box"><Icon name="rocket" size={17} /></div>
          <h2>Ajustes para jugar</h2>
        </div>
        <div class="tweaks">
          {#each defs as d (d.key)}
            {@const v = value(d.key)}
            <div class="tweak">
              <div class="t-ic"><Icon name={d.icon} size={17} /></div>
              <div class="t-body">
                <div class="row">
                  <strong>{d.title}</strong>
                  {#if v === d.recommended}<span class="badge ok">Recomendado</span>{/if}
                  {#if d.key === "hags" && tw.hags == null}<span class="badge">Predeterminado</span>{/if}
                  {#if d.admin && !app.admin}<span class="badge"><Icon name="lock" size={11} /> admin</span>{/if}
                </div>
                <p class="muted small">
                  {d.detail}{#if d.key === "hibernation" && tw.hiberfil_size} Ocupa {bytes(tw.hiberfil_size)}.{/if}
                </p>
              </div>
              <Toggle checked={v} busy={busy[d.key]} label={d.title} onchange={(nv) => setTweak(d, nv)} />
            </div>
          {/each}
        </div>
      </section>
    </div>
  {/if}

  <section class="card flush">
    <div class="startup-head">
      <div class="icon-box"><Icon name="clock" size={17} /></div>
      <div style="flex:1">
        <h2>Programas al iniciar Windows</h2>
        <p class="muted small">{enabledCount} activos de {app.startup?.length ?? 0}. Desactivar no desinstala nada: solo evita que se abran solos.</p>
      </div>
      <input type="text" placeholder="Buscar…" bind:value={filter} style="width:200px" />
      <button class="btn icon-only" title="Actualizar" onclick={() => loadStartup(true)}><Icon name="refresh" size={15} /></button>
    </div>
    {#if !app.startup}
      <div class="stack" style="padding:16px">{#each Array(5) as _}<div class="skeleton" style="height:28px"></div>{/each}</div>
    {:else}
      <table class="table">
        <thead><tr><th>Programa</th><th>Origen</th><th class="num">Estado</th></tr></thead>
        <tbody>
          {#each startup as s (s.id)}
            <tr class:off={!s.enabled}>
              <td>
                <div class="ellipsis" style="max-width:520px"><strong>{s.name}</strong></div>
                <div class="muted small ellipsis mono selectable" style="max-width:620px" title={s.command}>{s.command}</div>
              </td>
              <td class="muted small">{s.source}{#if s.machine && !app.admin} <Icon name="lock" size={11} />{/if}</td>
              <td class="num">
                <div class="row" style="justify-content:flex-end">
                  <span class="small {s.enabled ? 'ok-text' : 'muted'}">{s.enabled ? "Activo" : "Desactivado"}</span>
                  <Toggle checked={s.enabled} busy={busy[s.id]} label={s.name} onchange={(v) => setStartup(s.id, v, s.machine)} />
                </div>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </section>
</div>

<style>
  .top {
    margin-bottom: 14px;
    align-items: start;
  }
  .plans {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .plan {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 11px 14px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--line);
    background: var(--panel-2);
    cursor: pointer;
  }
  .plan > div {
    flex: 1;
  }
  .plan.active {
    border-color: rgba(47, 140, 255, 0.5);
    background: var(--accent-soft);
  }
  .tweaks {
    display: flex;
    flex-direction: column;
  }
  .tweak {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px 0;
    border-bottom: 1px solid var(--line);
  }
  .tweak:last-child {
    border-bottom: none;
  }
  .t-ic {
    width: 32px;
    height: 32px;
    border-radius: 9px;
    display: grid;
    place-items: center;
    background: var(--panel-3);
    color: var(--text-2);
    flex: none;
  }
  .t-body {
    flex: 1;
    min-width: 0;
  }
  .startup-head {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 14px 18px;
    border-bottom: 1px solid var(--line);
  }
  .startup-head .icon-box {
    width: 32px;
    height: 32px;
    border-radius: 9px;
    display: grid;
    place-items: center;
    background: var(--accent-soft);
    color: var(--accent);
  }
  .table td,
  .table th {
    padding-left: 18px;
    padding-right: 18px;
  }
  tr.off strong {
    color: var(--muted);
  }
</style>
