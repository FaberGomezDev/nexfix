import type { JunkCategory, MemModule, SecurityReport, StartupItem, StorageInfo, SystemInfo, Tweaks } from "./api";
import { ago, bytes, bytesDecimal, daysSince } from "./format";
import type { View } from "./state.svelte";

export type Level = "good" | "info" | "warn" | "bad";

export interface Insight {
  id: string;
  level: Level;
  title: string;
  detail: string;
  /** Points removed from the 100-point health score. */
  penalty: number;
  action?: { label: string; view: View };
  area: "rendimiento" | "almacenamiento" | "sistema" | "limpieza" | "seguridad";
}

/** Rated speed (MT/s) of a memory kit from its part number, when recognizable. */
export function ratedSpeed(m: MemModule): number | null {
  const p = m.part_number.toUpperCase().replace(/\s+/g, "");
  const tries: RegExp[] = [
    /M\dB(\d{4})C/, // Corsair CMK32GX5M2B6000C36
    /F[45]-(\d{4})/, // G.Skill F5-6000J3038F16G
    /KF[45](\d{2})C/, // Kingston Fury KF560C36 → 60 → 6000
    /CT\d+G(\d{2})C/, // Crucial CT16G56C46U5 → 56
    /(?:UD5|TF[0-9A-Z]*D5)-?(\d{4})/, // TeamGroup
  ];
  for (const re of tries) {
    const mm = p.match(re);
    if (mm) {
      const v = parseInt(mm[1], 10);
      return v < 100 ? v * 100 : v;
    }
  }
  const any = p.match(/(?<!\d)(2133|2400|2666|2933|3000|3200|3466|3600|3733|3866|4000|4400|4800|5200|5600|6000|6200|6400|6600|6800|7200|7600|8000|8400)(?!\d)/);
  return any ? parseInt(any[1], 10) : null;
}

function isAm5(cpu: string) {
  return /ryzen\s+\d\s+(7|8|9)\d{3}/i.test(cpu);
}

function memoryInsights(sys: SystemInfo): Insight[] {
  const out: Insight[] = [];
  const mods = sys.memory.modules;
  if (!mods.length) return out;
  const m = mods[0];
  const type = m.mem_type || "RAM";
  const cur = Math.min(...mods.map((x) => x.configured_speed || x.speed));
  const rated = ratedSpeed(m);
  const am5 = isAm5(sys.cpu.name) && type === "DDR5";

  if (mods.length === 1) {
    out.push({
      id: "ram-single",
      level: "warn",
      penalty: 8,
      area: "rendimiento",
      title: "Memoria en canal simple",
      detail: `Solo hay un módulo de ${type}. Con dos módulos (dual channel) los juegos suelen ganar entre un 10 y un 30 % de FPS en escenas exigentes con la CPU.`,
      action: { label: "Ver memoria", view: "hardware" },
    });
  }

  const jedecLike = (type === "DDR5" && cur <= 4800) || (type === "DDR4" && cur <= 2666);
  if (rated && cur && cur < rated * 0.97) {
    if (am5 && cur >= 6000) {
      out.push({
        id: "ram-am5-sweet",
        level: "good",
        penalty: 0,
        area: "rendimiento",
        title: `RAM a ${cur} MT/s: punto óptimo para tu Ryzen`,
        detail: `Tu kit es de ${rated} MT/s y funciona a ${cur} MT/s. En Ryzen 7000/9000, 6000 MT/s con FCLK 2000 MHz suele ser lo más estable y rápido; no hace falta subirla.`,
      });
    } else if (jedecLike) {
      out.push({
        id: "ram-expo",
        level: "bad",
        penalty: 15,
        area: "rendimiento",
        title: `La RAM va a ${cur} MT/s en vez de ${rated} MT/s`,
        detail: `El perfil ${sys.cpu.vendor.includes("AMD") ? "EXPO" : "XMP"} no está activado. Actívalo en la BIOS (sección de memoria/AI Tweaker) para obtener la velocidad por la que pagaste: más FPS mínimos y menos tirones.`,
        action: { label: "Ver memoria", view: "hardware" },
      });
    } else {
      out.push({
        id: "ram-below",
        level: "info",
        penalty: 2,
        area: "rendimiento",
        title: `RAM a ${cur} MT/s (kit de ${rated} MT/s)`,
        detail: "Funciona algo por debajo de su velocidad nominal. Si fue intencionado por estabilidad está bien; si no, revisa el perfil EXPO/XMP en la BIOS.",
      });
    }
  } else if (jedecLike) {
    out.push({
      id: "ram-jedec",
      level: "warn",
      penalty: 8,
      area: "rendimiento",
      title: `RAM a velocidad base (${cur} MT/s)`,
      detail: "Parece que el perfil EXPO/XMP no está activo. Compruébalo en la BIOS: la mayoría de kits gaming están pensados para ir más rápido.",
      action: { label: "Ver memoria", view: "hardware" },
    });
  } else if (cur) {
    out.push({
      id: "ram-ok",
      level: "good",
      penalty: 0,
      area: "rendimiento",
      title: `RAM a ${cur} MT/s${rated ? ` (kit de ${rated})` : ""}`,
      detail: `${mods.length} módulos de ${type}${mods.length >= 2 ? " en dual channel" : ""}.`,
    });
  }
  return out;
}

export function buildInsights(
  sys: SystemInfo | null,
  st: StorageInfo | null,
  tw: Tweaks | null,
  junk: JunkCategory[] | null,
  startup: StartupItem[] | null,
  security: SecurityReport | null = null,
): Insight[] {
  const out: Insight[] = [];

  if (security) out.push(...securityInsights(security));

  if (sys) {
    out.push(...memoryInsights(sys));

    for (const d of sys.displays) {
      if (d.max_hz > d.current_hz + 5) {
        out.push({
          id: `hz-${d.name}`,
          level: "warn",
          penalty: 10,
          area: "rendimiento",
          title: `Tu monitor va a ${d.current_hz} Hz pero admite ${d.max_hz} Hz`,
          detail: `Configuración > Sistema > Pantalla > Pantalla avanzada > Frecuencia de actualización: elige ${d.max_hz} Hz. Si no aparece, usa un cable DisplayPort o HDMI 2.1 y conéctalo a la tarjeta gráfica, no a la placa.`,
          action: { label: "Ver pantallas", view: "hardware" },
        });
      }
    }

    const dgpu = sys.gpus.find((g) => !g.integrated) ?? sys.gpus[0];
    if (dgpu) {
      const days = daysSince(dgpu.driver_date);
      if (days != null && days > 150) {
        out.push({
          id: "gpu-driver",
          level: days > 365 ? "warn" : "info",
          penalty: days > 365 ? 6 : 2,
          area: "rendimiento",
          title: `Driver de ${dgpu.vendor || "GPU"} de hace ${ago(days)}`,
          detail: `Los drivers nuevos traen optimizaciones para juegos recientes. Actualiza desde ${dgpu.vendor === "NVIDIA" ? "NVIDIA App" : dgpu.vendor === "AMD" ? "AMD Software: Adrenalin" : "la web del fabricante"}.`,
        });
      }
      const conn = sys.displays.find((d) => d.primary) ?? sys.displays[0];
      const igpu = sys.gpus.find((g) => g.integrated);
      if (conn && !dgpu.integrated && igpu && conn.adapter === igpu.name) {
        out.push({
          id: "monitor-igpu",
          level: "bad",
          penalty: 20,
          area: "rendimiento",
          title: "El monitor está conectado a la gráfica integrada",
          detail: `La pantalla principal sale por ${conn.adapter}. Conecta el cable a la ${dgpu.name} (salidas de la tarjeta, abajo en la torre).`,
        });
      }
    }

    const biosDays = daysSince(sys.board.bios_date);
    if (biosDays != null && biosDays > 400) {
      out.push({
        id: "bios-old",
        level: "info",
        penalty: 3,
        area: "sistema",
        title: `BIOS de hace ${ago(biosDays)} (versión ${sys.board.bios_version})`,
        detail: `Las actualizaciones de BIOS mejoran compatibilidad de memoria, estabilidad y seguridad. Busca "${sys.board.product}" en la web de ${sys.board.manufacturer.replace(/ COMPUTER INC\.?/i, "")} y sigue sus instrucciones (no apagues el PC durante el proceso).`,
      });
    }

    if (sys.os.uptime_secs > 7 * 86400) {
      out.push({
        id: "uptime",
        level: "info",
        penalty: 2,
        area: "sistema",
        title: `El PC lleva ${Math.floor(sys.os.uptime_secs / 86400)} días sin reiniciar`,
        detail: "Reiniciar de vez en cuando libera memoria, aplica actualizaciones y elimina procesos colgados.",
      });
    }
  }

  if (st) {
    for (const v of st.volumes) {
      if (!v.total) continue;
      const free = v.free / v.total;
      const disk = st.disks.find((d) => d.number === v.disk_number);
      const ssd = disk?.is_ssd;
      if (free < 0.1) {
        out.push({
          id: `free-${v.letter}`,
          level: "bad",
          penalty: 15,
          area: "almacenamiento",
          title: `${v.letter} casi lleno: ${bytes(v.free)} libres`,
          detail: ssd
            ? "Un SSD con menos del 10 % libre escribe más lento y se desgasta antes. Libera espacio con Limpieza y Espacio."
            : "Con poco espacio libre Windows no puede actualizar ni usar bien el archivo de paginación.",
          action: { label: "Liberar espacio", view: "analyzer" },
        });
      } else if (free < 0.18) {
        out.push({
          id: `free-${v.letter}`,
          level: "warn",
          penalty: 6,
          area: "almacenamiento",
          title: `${v.letter} con ${Math.round(free * 100)} % libre`,
          detail: ssd
            ? "Para que un SSD/M.2 mantenga su velocidad conviene dejar libre al menos un 15-20 %."
            : "Conviene mantener al menos un 15 % libre.",
          action: { label: "Analizar espacio", view: "analyzer" },
        });
      }
    }

    if (st.trim_ntfs === false) {
      out.push({
        id: "trim-off",
        level: "bad",
        penalty: 15,
        area: "almacenamiento",
        title: "TRIM está desactivado",
        detail: "Sin TRIM el SSD pierde rendimiento con el tiempo. Actívalo como administrador con: fsutil behavior set DisableDeleteNotify 0",
        action: { label: "Ver discos", view: "storage" },
      });
    }

    for (const d of st.disks) {
      const label = `${d.model}${d.is_nvme ? " (M.2 NVMe)" : ""}`;
      if (d.health === "unhealthy" || d.health === "warning") {
        out.push({
          id: `health-${d.number}`,
          level: "bad",
          penalty: 25,
          area: "almacenamiento",
          title: `Windows reporta problemas en ${label}`,
          detail: "Haz una copia de seguridad de tus datos importantes cuanto antes y revisa el SMART en Discos.",
          action: { label: "Ver disco", view: "storage" },
        });
      }
      const n = d.nvme;
      if (n) {
        if (n.critical_warning) {
          out.push({
            id: `nvme-crit-${d.number}`,
            level: "bad",
            penalty: 25,
            area: "almacenamiento",
            title: `${label}: aviso crítico del controlador`,
            detail: "El SSD informa de un estado crítico (temperatura, reserva agotada o modo solo lectura). Haz copia de seguridad.",
            action: { label: "Ver disco", view: "storage" },
          });
        }
        if (n.percentage_used >= 80) {
          out.push({
            id: `nvme-wear-${d.number}`,
            level: n.percentage_used >= 95 ? "bad" : "warn",
            penalty: n.percentage_used >= 95 ? 20 : 10,
            area: "almacenamiento",
            title: `${label}: ${n.percentage_used} % de vida útil consumida`,
            detail: `Lleva ${bytesDecimal(n.data_written_bytes)} escritos. Ve pensando en reemplazarlo y mantén copias de seguridad.`,
          });
        }
        if (n.media_errors > 0) {
          out.push({
            id: `nvme-media-${d.number}`,
            level: "warn",
            penalty: 10,
            area: "almacenamiento",
            title: `${label}: ${n.media_errors} errores de integridad de datos`,
            detail: "El SSD ha detectado errores de medio. Vigila que no aumenten y haz copia de seguridad.",
          });
        }
        if (n.temperature_c >= 70) {
          out.push({
            id: `nvme-temp-${d.number}`,
            level: "warn",
            penalty: 6,
            area: "almacenamiento",
            title: `${label} a ${n.temperature_c} °C`,
            detail: "Por encima de ~70 °C los M.2 reducen velocidad (thermal throttling). Usa el disipador de la placa o uno aftermarket y mejora el flujo de aire.",
          });
        } else if (n.warning_temp_minutes > 60) {
          out.push({
            id: `nvme-temphist-${d.number}`,
            level: "info",
            penalty: 2,
            area: "almacenamiento",
            title: `${label} ha estado ${n.warning_temp_minutes} min sobre su temperatura de aviso`,
            detail: "Ahora está bien, pero en algún momento se calentó. Considera un disipador para el M.2.",
          });
        }
        if (n.percentage_used < 80 && !n.critical_warning && n.media_errors === 0 && n.temperature_c < 70) {
          out.push({
            id: `nvme-ok-${d.number}`,
            level: "good",
            penalty: 0,
            area: "almacenamiento",
            title: `${label}: salud ${100 - n.percentage_used} %, ${n.temperature_c} °C`,
            detail: `${bytesDecimal(n.data_written_bytes)} escritos en ${n.power_on_hours.toLocaleString("es-ES")} h de uso, sin errores.`,
          });
        }
      } else if (d.is_nvme && !st.is_admin) {
        out.push({
          id: `nvme-admin-${d.number}`,
          level: "info",
          penalty: 0,
          area: "almacenamiento",
          title: `Salud completa del ${d.model} disponible como administrador`,
          detail: "Reinicia NexFix como administrador para leer temperatura, desgaste y TB escritos de tu M.2.",
          action: { label: "Ver discos", view: "storage" },
        });
      }
    }

    if (st.windows_old) {
      out.push({
        id: "winold",
        level: "info",
        penalty: 2,
        area: "limpieza",
        title: "Hay una instalación anterior de Windows (Windows.old)",
        detail: "Si todo funciona bien, elimínala desde Configuración > Sistema > Almacenamiento > Archivos temporales > Instalación anterior de Windows.",
      });
    }
  }

  if (tw) {
    const active = tw.power_plans.find((p) => p.active);
    if (active && /econom|ahorro|saver/i.test(active.name)) {
      out.push({
        id: "power-saver",
        level: "warn",
        penalty: 8,
        area: "rendimiento",
        title: `Plan de energía "${active.name}"`,
        detail: "El plan de ahorro limita la frecuencia de la CPU. Para jugar usa Equilibrado o Alto rendimiento.",
        action: { label: "Optimizar", view: "optimize" },
      });
    }
    if (!tw.game_mode) {
      out.push({
        id: "gamemode",
        level: "warn",
        penalty: 5,
        area: "rendimiento",
        title: "Modo juego desactivado",
        detail: "El Modo juego prioriza el juego y evita que Windows Update instale drivers o muestre notificaciones mientras juegas.",
        action: { label: "Activar", view: "optimize" },
      });
    }
    if (tw.game_dvr) {
      out.push({
        id: "dvr",
        level: "info",
        penalty: 3,
        area: "rendimiento",
        title: "Grabación de Xbox Game Bar activa",
        detail: "La captura en segundo plano consume algo de GPU y disco. Si grabas con NVIDIA App, AMD ReLive u OBS, puedes desactivarla.",
        action: { label: "Optimizar", view: "optimize" },
      });
    }
    if (tw.mouse_accel) {
      out.push({
        id: "mouseaccel",
        level: "info",
        penalty: 2,
        area: "rendimiento",
        title: "Aceleración del ratón activada",
        detail: "\"Mejorar precisión del puntero\" hace que la puntería dependa de la velocidad del gesto. En shooters la mayoría la desactiva.",
        action: { label: "Optimizar", view: "optimize" },
      });
    }
    if (tw.hibernation && tw.hiberfil_size > 4 * 1024 ** 3) {
      out.push({
        id: "hiber",
        level: "info",
        penalty: 1,
        area: "almacenamiento",
        title: `La hibernación ocupa ${bytes(tw.hiberfil_size)}`,
        detail: "Si nunca hibernas el PC puedes desactivarla para recuperar ese espacio (también desactiva el Inicio rápido).",
        action: { label: "Optimizar", view: "optimize" },
      });
    }
  }

  if (startup) {
    const enabled = startup.filter((s) => s.enabled).length;
    if (enabled > 10) {
      out.push({
        id: "startup",
        level: "info",
        penalty: 4,
        area: "sistema",
        title: `${enabled} programas se abren al iniciar Windows`,
        detail: "Cada uno resta memoria y alarga el arranque. Desactiva los que no necesites al encender.",
        action: { label: "Revisar inicio", view: "optimize" },
      });
    }
  }

  if (junk) {
    const safe = junk.filter((c) => c.default_on && c.found).reduce((s, c) => s + c.size, 0);
    const shaders = junk.filter((c) => c.id.endsWith("_shader")).reduce((s, c) => s + c.size, 0);
    if (safe > 1024 ** 3) {
      out.push({
        id: "junk",
        level: safe > 10 * 1024 ** 3 ? "warn" : "info",
        penalty: safe > 10 * 1024 ** 3 ? 5 : 2,
        area: "limpieza",
        title: `${bytes(safe)} de temporales y cachés que puedes borrar`,
        detail: "Archivos temporales, cachés de navegadores y launchers, informes de errores e instaladores de drivers ya usados.",
        action: { label: "Limpiar", view: "cleaner" },
      });
    }
    if (shaders > 5 * 1024 ** 3) {
      out.push({
        id: "shaders",
        level: "info",
        penalty: 1,
        area: "limpieza",
        title: `Las cachés de sombreadores ocupan ${bytes(shaders)}`,
        detail: "Es normal que crezcan, pero si ocupan mucho o tienes tirones/artefactos tras actualizar drivers, bórralas: se regeneran al jugar.",
        action: { label: "Ver en Limpieza", view: "cleaner" },
      });
    }
  }

  const order: Record<Level, number> = { bad: 0, warn: 1, info: 2, good: 3 };
  return out.sort((a, b) => order[a.level] - order[b.level] || b.penalty - a.penalty);
}

function securityInsights(sec: SecurityReport): Insight[] {
  const out: Insight[] = [];
  const open = sec.findings.filter((f) => !f.ignored);
  const serious = open.filter((f) => f.level === "critical" || f.level === "high");
  const medium = open.filter((f) => f.level === "medium");
  // Each serious finding counts, but security alone never takes more than 45 points.
  let budget = 45;
  for (const f of serious.slice(0, 4)) {
    const penalty = Math.min(budget, f.level === "critical" ? 25 : 15);
    budget -= penalty;
    out.push({
      id: `sec-${f.id}`,
      level: "bad",
      penalty,
      area: "seguridad",
      title: f.title,
      detail: f.summary,
      action: { label: "Revisar", view: "security" },
    });
  }
  if (serious.length > 4) {
    out.push({
      id: "sec-more",
      level: "bad",
      penalty: Math.min(budget, 5),
      area: "seguridad",
      title: `Y ${serious.length - 4} amenazas más`,
      detail: "Revísalas todas en Seguridad.",
      action: { label: "Revisar", view: "security" },
    });
  }
  if (medium.length) {
    out.push({
      id: "sec-medium",
      level: "warn",
      penalty: Math.min(Math.max(0, budget), 4),
      area: "seguridad",
      title: `${medium.length} ${medium.length === 1 ? "elemento sospechoso" : "elementos sospechosos"} para revisar`,
      detail: medium.slice(0, 3).map((f) => f.title).join(" · "),
      action: { label: "Revisar", view: "security" },
    });
  }
  if (!serious.length && !medium.length) {
    out.push({
      id: "sec-ok",
      level: "good",
      penalty: 0,
      area: "seguridad",
      title: "Sin mineros ni malware detectados",
      detail: `Revisados ${sec.checked.processes} procesos (CPU y GPU), ${sec.checked.startup} entradas de inicio y ${sec.checked.services} servicios.`,
    });
  }
  return out;
}

export function healthScore(list: Insight[]): number {
  const total = list.reduce((s, i) => s + i.penalty, 0);
  return Math.max(0, Math.min(100, 100 - total));
}
