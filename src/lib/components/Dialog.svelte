<script lang="ts">
  import { closeDialog, dialog } from "../state.svelte";
  import Icon from "./Icon.svelte";

  function onkey(e: KeyboardEvent) {
    if (!dialog.current) return;
    if (e.key === "Escape") closeDialog(false);
  }
</script>

<svelte:window onkeydown={onkey} />

{#if dialog.current}
  {@const d = dialog.current}
  <div class="backdrop" role="presentation" onclick={() => closeDialog(false)}>
    <div
      class="dialog"
      role="dialog"
      aria-modal="true"
      aria-labelledby="dlg-title"
      tabindex="-1"
      onclick={(e) => e.stopPropagation()}
      onkeydown={() => {}}
    >
      <div class="head">
        <div class="ic" class:danger={d.danger}>
          <Icon name={d.danger ? "alert" : "info"} size={20} />
        </div>
        <h2 id="dlg-title">{d.title}</h2>
      </div>
      <p class="body">{d.body}</p>
      {#if d.details?.length}
        <ul class="details">
          {#each d.details as line}
            <li>{line}</li>
          {/each}
        </ul>
      {/if}
      <div class="actions">
        <button class="btn" onclick={() => closeDialog(false)}>{d.cancel ?? "Cancelar"}</button>
        <!-- svelte-ignore a11y_autofocus -->
        <button class="btn {d.danger ? 'danger' : 'primary'}" autofocus onclick={() => closeDialog(true)}>
          {d.confirm ?? "Aceptar"}
        </button>
      </div>
    </div>
  </div>
{/if}

<style>
  .backdrop {
    position: fixed;
    inset: 0;
    background: rgba(3, 5, 9, 0.65);
    backdrop-filter: blur(3px);
    display: grid;
    place-items: center;
    z-index: 100;
    animation: fade 0.12s ease;
  }
  .dialog {
    width: min(520px, calc(100vw - 40px));
    background: var(--panel);
    border: 1px solid var(--line-2);
    border-radius: 14px;
    padding: 20px 22px;
    box-shadow: var(--shadow);
    animation: pop 0.15s ease;
    outline: none;
  }
  .head {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 10px;
  }
  .ic {
    width: 36px;
    height: 36px;
    border-radius: 10px;
    display: grid;
    place-items: center;
    background: var(--accent-soft);
    color: var(--accent);
  }
  .ic.danger {
    background: var(--bad-soft);
    color: var(--bad);
  }
  .body {
    color: var(--text-2);
    font-size: 13.5px;
    white-space: pre-line;
  }
  .details {
    margin: 12px 0 0;
    padding: 10px 14px 10px 28px;
    background: var(--panel-2);
    border-radius: var(--radius-sm);
    max-height: 200px;
    overflow: auto;
    font-size: 12.5px;
    color: var(--text-2);
    user-select: text;
  }
  .details li {
    margin: 2px 0;
    word-break: break-all;
  }
  .actions {
    display: flex;
    justify-content: flex-end;
    gap: 10px;
    margin-top: 18px;
  }
  @keyframes fade {
    from {
      opacity: 0;
    }
  }
  @keyframes pop {
    from {
      transform: scale(0.97);
      opacity: 0;
    }
  }
</style>
