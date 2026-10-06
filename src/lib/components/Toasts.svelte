<script lang="ts">
  import { toasts } from "../state.svelte";
  import Icon from "./Icon.svelte";

  const icons = { ok: "check", info: "info", warn: "alert", error: "xcircle" } as const;
</script>

<div class="toasts" aria-live="polite">
  {#each toasts as t (t.id)}
    <div class="toast {t.kind}">
      <Icon name={icons[t.kind]} size={18} />
      <span>{t.text}</span>
    </div>
  {/each}
</div>

<style>
  .toasts {
    position: fixed;
    right: 20px;
    bottom: 20px;
    display: flex;
    flex-direction: column;
    gap: 8px;
    z-index: 200;
    pointer-events: none;
  }
  .toast {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    max-width: 420px;
    padding: 11px 14px;
    border-radius: 10px;
    background: var(--panel-3);
    border: 1px solid var(--line-2);
    box-shadow: var(--shadow);
    font-size: 13px;
    animation: slide 0.18s ease;
    pointer-events: auto;
    user-select: text;
  }
  .toast.ok :global(.icon) {
    color: var(--ok);
  }
  .toast.info :global(.icon) {
    color: var(--accent);
  }
  .toast.warn :global(.icon) {
    color: var(--warn);
  }
  .toast.error {
    border-color: rgba(240, 75, 75, 0.45);
  }
  .toast.error :global(.icon) {
    color: var(--bad);
  }
  @keyframes slide {
    from {
      transform: translateY(8px);
      opacity: 0;
    }
  }
</style>
