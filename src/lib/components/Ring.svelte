<script lang="ts">
  let {
    value,
    size = 120,
    thickness = 10,
    color = "var(--accent)",
    label = "",
    sub = "",
  }: { value: number; size?: number; thickness?: number; color?: string; label?: string; sub?: string } = $props();

  const r = $derived((size - thickness) / 2);
  const c = $derived(2 * Math.PI * r);
  const v = $derived(Math.max(0, Math.min(100, value)));
</script>

<div class="ring" style="width:{size}px;height:{size}px">
  <svg width={size} height={size} viewBox="0 0 {size} {size}">
    <circle cx={size / 2} cy={size / 2} {r} fill="none" stroke="var(--track)" stroke-width={thickness} />
    <circle
      cx={size / 2}
      cy={size / 2}
      {r}
      fill="none"
      stroke={color}
      stroke-width={thickness}
      stroke-linecap="round"
      stroke-dasharray={c}
      stroke-dashoffset={c * (1 - v / 100)}
      transform="rotate(-90 {size / 2} {size / 2})"
      style="transition: stroke-dashoffset .6s ease, stroke .3s"
    />
  </svg>
  <div class="ring-text">
    <strong style="font-size:{Math.round(size / 4.2)}px">{label}</strong>
    {#if sub}<span>{sub}</span>{/if}
  </div>
</div>

<style>
  .ring {
    position: relative;
    flex: none;
  }
  .ring-text {
    position: absolute;
    inset: 0;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    line-height: 1.1;
  }
  .ring-text strong {
    font-weight: 700;
    letter-spacing: -0.02em;
  }
  .ring-text span {
    font-size: 11px;
    color: var(--muted);
    margin-top: 2px;
  }
</style>
