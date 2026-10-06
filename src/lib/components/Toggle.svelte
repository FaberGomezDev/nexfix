<script lang="ts">
  let {
    checked,
    disabled = false,
    busy = false,
    label = "",
    onchange,
  }: { checked: boolean; disabled?: boolean; busy?: boolean; label?: string; onchange: (v: boolean) => void } = $props();
</script>

<button
  type="button"
  role="switch"
  aria-checked={checked}
  aria-label={label}
  class="toggle"
  class:on={checked}
  class:busy
  disabled={disabled || busy}
  onclick={() => onchange(!checked)}
>
  <span class="knob"></span>
</button>

<style>
  .toggle {
    width: 40px;
    height: 22px;
    border-radius: 999px;
    border: 1px solid var(--line-2);
    background: var(--panel-3);
    position: relative;
    padding: 0;
    flex: none;
    cursor: pointer;
    transition: background 0.2s, border-color 0.2s;
  }
  .toggle.on {
    background: var(--accent);
    border-color: var(--accent);
  }
  .toggle:disabled {
    opacity: 0.45;
    cursor: not-allowed;
  }
  .toggle.busy {
    opacity: 0.7;
    cursor: progress;
  }
  .knob {
    position: absolute;
    top: 2px;
    left: 2px;
    width: 16px;
    height: 16px;
    border-radius: 50%;
    background: #fff;
    transition: transform 0.2s;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.4);
  }
  .on .knob {
    transform: translateX(18px);
  }
</style>
