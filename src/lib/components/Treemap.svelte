<script lang="ts" module>
  export interface TreemapItem {
    key: string;
    label: string;
    value: number;
    kind: "dir" | "files";
    id?: number;
  }

  interface Rect {
    x: number;
    y: number;
    w: number;
    h: number;
    item: TreemapItem;
  }

  /** Squarified treemap (Bruls, Huizing, van Wijk). */
  function squarify(items: TreemapItem[], x: number, y: number, w: number, h: number): Rect[] {
    const total = items.reduce((s, i) => s + i.value, 0);
    if (total <= 0 || w <= 0 || h <= 0) return [];
    const scale = (w * h) / total;
    const areas = items.map((i) => ({ item: i, a: i.value * scale }));
    const out: Rect[] = [];
    let row: typeof areas = [];
    let rx = x,
      ry = y,
      rw = w,
      rh = h;

    const worst = (r: typeof areas, side: number) => {
      const s = r.reduce((t, i) => t + i.a, 0);
      if (s === 0) return Infinity;
      let max = -Infinity,
        min = Infinity;
      for (const i of r) {
        max = Math.max(max, i.a);
        min = Math.min(min, i.a);
      }
      const s2 = s * s,
        side2 = side * side;
      return Math.max((side2 * max) / s2, s2 / (side2 * min));
    };

    const layout = (r: typeof areas) => {
      const s = r.reduce((t, i) => t + i.a, 0);
      if (rw >= rh) {
        const colW = s / rh;
        let cy = ry;
        for (const i of r) {
          const ih = i.a / colW;
          out.push({ x: rx, y: cy, w: colW, h: ih, item: i.item });
          cy += ih;
        }
        rx += colW;
        rw -= colW;
      } else {
        const rowH = s / rw;
        let cx = rx;
        for (const i of r) {
          const iw = i.a / rowH;
          out.push({ x: cx, y: ry, w: iw, h: rowH, item: i.item });
          cx += iw;
        }
        ry += rowH;
        rh -= rowH;
      }
    };

    for (const a of areas) {
      const side = Math.min(rw, rh);
      if (row.length === 0 || worst([...row, a], side) <= worst(row, side)) {
        row.push(a);
      } else {
        layout(row);
        row = [a];
      }
    }
    if (row.length) layout(row);
    return out;
  }

  const PALETTE = ["#2f8cff", "#16c7a8", "#8b6cff", "#f5a524", "#e2558f", "#3fb8f0", "#7ccf4a", "#c77dff", "#ff8a4c", "#4f7cff"];
</script>

<script lang="ts">
  import { bytes, pct } from "../format";

  let {
    items,
    total,
    onopen,
  }: { items: TreemapItem[]; total: number; onopen: (item: TreemapItem) => void } = $props();

  let w = $state(0);
  let h = $state(0);

  const rects = $derived.by(() => {
    const visible = items.filter((i) => i.value > 0).sort((a, b) => b.value - a.value);
    // Group the long tail so the map stays readable and fast.
    const max = 60;
    let list = visible.slice(0, max);
    if (visible.length > max) {
      const rest = visible.slice(max).reduce((s, i) => s + i.value, 0);
      list.push({ key: "__rest", label: `${visible.length - max} elementos más`, value: rest, kind: "files" });
    }
    return squarify(list, 0, 0, w, h);
  });
</script>

<div class="map" bind:clientWidth={w} bind:clientHeight={h}>
  {#each rects as r, i (r.item.key)}
    {@const big = r.w > 90 && r.h > 38}
    <button
      class="cell"
      class:files={r.item.kind === "files"}
      style="left:{r.x}px;top:{r.y}px;width:{Math.max(0, r.w - 2)}px;height:{Math.max(0, r.h - 2)}px;--c:{PALETTE[i % PALETTE.length]}"
      title="{r.item.label} — {bytes(r.item.value)} ({pct(r.item.value, total, 1)})"
      disabled={r.item.kind !== "dir"}
      onclick={() => onopen(r.item)}
    >
      {#if big}
        <span class="name">{r.item.label}</span>
        <span class="size">{bytes(r.item.value)}</span>
      {/if}
    </button>
  {/each}
</div>

<style>
  .map {
    position: relative;
    width: 100%;
    height: 100%;
    min-height: 220px;
    overflow: hidden;
  }
  .cell {
    position: absolute;
    border: none;
    border-radius: 6px;
    padding: 6px 8px;
    text-align: left;
    background: color-mix(in srgb, var(--c) 30%, #0d1118);
    border: 1px solid color-mix(in srgb, var(--c) 55%, transparent);
    color: #fff;
    overflow: hidden;
    display: flex;
    flex-direction: column;
    gap: 1px;
    cursor: pointer;
    transition: background 0.15s, transform 0.12s;
    margin: 1px;
  }
  .cell:hover:not(:disabled) {
    background: color-mix(in srgb, var(--c) 48%, #0d1118);
  }
  .cell:disabled {
    cursor: default;
  }
  .cell.files {
    background: repeating-linear-gradient(45deg, #151a24, #151a24 6px, #181e2a 6px, #181e2a 12px);
    border-color: var(--line-2);
  }
  .name {
    font-weight: 600;
    font-size: 12.5px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .size {
    font-size: 11.5px;
    opacity: 0.8;
  }
</style>
