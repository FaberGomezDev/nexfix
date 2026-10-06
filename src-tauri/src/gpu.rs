//! Per-process GPU usage from the "GPU Engine" and "GPU Process Memory"
//! performance counters — the same source Task Manager uses. No admin needed.
//! Instance names look like `pid_1234_luid_0x0_0xD1B2_phys_0_eng_0_engtype_3D`.

use std::collections::HashMap;

use windows_sys::Win32::System::Performance::{
    PdhAddEnglishCounterW, PdhCloseQuery, PdhCollectQueryData, PdhGetFormattedCounterArrayW, PdhOpenQueryW,
    PDH_FMT_COUNTERVALUE_ITEM_W, PDH_FMT_DOUBLE, PDH_FMT_LARGE, PDH_HCOUNTER, PDH_HQUERY, PDH_MORE_DATA,
};

use crate::util::wide;

#[derive(Default, Clone, Copy)]
pub struct ProcGpu {
    /// Busiest engine of the process, 0-100 (Task Manager's "GPU" column).
    pub usage: f32,
    /// The usage comes from Compute/CUDA engines (typical of miners) rather than 3D.
    pub compute: bool,
    /// Dedicated video memory in bytes.
    pub vram: u64,
}

#[derive(Default)]
pub struct GpuSample {
    pub procs: HashMap<u32, ProcGpu>,
    /// Busiest engine across the whole GPU, 0-100.
    pub total: f32,
    pub available: bool,
}

pub struct GpuQuery {
    query: PDH_HQUERY,
    engine: PDH_HCOUNTER,
    memory: Option<PDH_HCOUNTER>,
}

// PDH handles are plain opaque pointers usable from any thread.
unsafe impl Send for GpuQuery {}

impl Drop for GpuQuery {
    fn drop(&mut self) {
        unsafe { PdhCloseQuery(self.query) };
    }
}

fn pid_of(instance: &str) -> Option<u32> {
    let rest = instance.strip_prefix("pid_")?;
    let end = rest.find('_').unwrap_or(rest.len());
    rest[..end].parse().ok()
}

impl GpuQuery {
    /// Opens the query and takes the first sample (utilization is a rate:
    /// call [`GpuQuery::sample`] about a second later).
    pub fn open() -> Option<Self> {
        unsafe {
            let mut query: PDH_HQUERY = std::ptr::null_mut();
            if PdhOpenQueryW(std::ptr::null(), 0, &mut query) != 0 {
                return None;
            }
            let mut engine: PDH_HCOUNTER = std::ptr::null_mut();
            let path = wide(r"\GPU Engine(*)\Utilization Percentage");
            if PdhAddEnglishCounterW(query, path.as_ptr(), 0, &mut engine) != 0 {
                PdhCloseQuery(query);
                return None;
            }
            let mut memory: PDH_HCOUNTER = std::ptr::null_mut();
            let path = wide(r"\GPU Process Memory(*)\Dedicated Usage");
            let memory = (PdhAddEnglishCounterW(query, path.as_ptr(), 0, &mut memory) == 0).then_some(memory);
            PdhCollectQueryData(query);
            Some(Self { query, engine, memory })
        }
    }

    pub fn sample(&self) -> GpuSample {
        let mut out = GpuSample { available: true, ..Default::default() };
        if unsafe { PdhCollectQueryData(self.query) } != 0 {
            out.available = false;
            return out;
        }
        // Engine utilization per (pid, engine) → per process busiest engine,
        // and per engine summed over processes → GPU total.
        let mut per_engine: HashMap<String, f64> = HashMap::new();
        let mut compute_use: HashMap<u32, f64> = HashMap::new();
        for (name, value) in unsafe { counter_array(self.engine, PDH_FMT_DOUBLE) } {
            let v = unsafe { value.doubleValue }.clamp(0.0, 100.0);
            let Some(pid) = pid_of(&name) else { continue };
            let engine_key = name.split_once("_luid_").map(|(_, e)| e.to_string()).unwrap_or_default();
            *per_engine.entry(engine_key).or_default() += v;
            let lower = name.to_ascii_lowercase();
            if lower.contains("engtype_compute") || lower.contains("engtype_cuda") {
                let c = compute_use.entry(pid).or_default();
                *c = c.max(v);
            }
            let p = out.procs.entry(pid).or_default();
            p.usage = p.usage.max(v as f32);
        }
        for (pid, c) in compute_use {
            if let Some(p) = out.procs.get_mut(&pid) {
                p.compute = c >= 5.0 && c as f32 >= p.usage * 0.6;
            }
        }
        out.total = per_engine.values().fold(0.0f64, |a, &b| a.max(b)).min(100.0) as f32;

        if let Some(mem) = self.memory {
            for (name, value) in unsafe { counter_array(mem, PDH_FMT_LARGE) } {
                if let Some(pid) = pid_of(&name) {
                    out.procs.entry(pid).or_default().vram += unsafe { value.largeValue }.max(0) as u64;
                }
            }
        }
        out
    }
}

/// Formatted values of a wildcard counter as `(instance, value)` pairs.
unsafe fn counter_array(
    counter: PDH_HCOUNTER,
    format: u32,
) -> Vec<(String, windows_sys::Win32::System::Performance::PDH_FMT_COUNTERVALUE_0)> {
    for _ in 0..3 {
        let mut size = 0u32;
        let mut count = 0u32;
        let r = PdhGetFormattedCounterArrayW(counter, format, &mut size, &mut count, std::ptr::null_mut());
        if r != PDH_MORE_DATA || size == 0 {
            return Vec::new();
        }
        // u64 storage keeps the item array 8-byte aligned.
        let mut buf = vec![0u64; (size as usize).div_ceil(8)];
        let items = buf.as_mut_ptr() as *mut PDH_FMT_COUNTERVALUE_ITEM_W;
        let r = PdhGetFormattedCounterArrayW(counter, format, &mut size, &mut count, items);
        if r == PDH_MORE_DATA {
            continue; // Instances appeared between both calls.
        }
        if r != 0 {
            return Vec::new();
        }
        let slice = std::slice::from_raw_parts(items, count as usize);
        return slice
            .iter()
            // CStatus 0 = valid, 1 = new data; anything else has no usable value.
            .filter(|it| it.FmtValue.CStatus <= 1 && !it.szName.is_null())
            .map(|it| {
                let mut len = 0;
                while *it.szName.add(len) != 0 {
                    len += 1;
                }
                let name = String::from_utf16_lossy(std::slice::from_raw_parts(it.szName, len));
                (name, it.FmtValue.Anonymous)
            })
            .collect();
    }
    Vec::new()
}
