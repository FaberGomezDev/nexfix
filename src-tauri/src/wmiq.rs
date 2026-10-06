//! Untyped WMI helpers: rows as `HashMap<String, Variant>` plus tolerant getters
//! (WMI happily returns numbers as strings or different integer widths).

use std::collections::HashMap;

use wmi::{Variant, WMIConnection};

pub type Row = HashMap<String, Variant>;

pub fn connect(namespace: &str) -> Option<WMIConnection> {
    WMIConnection::with_namespace_path(namespace).ok()
}

pub fn query(con: &WMIConnection, q: &str) -> Vec<Row> {
    con.raw_query::<Row>(q).unwrap_or_default()
}

pub fn s(row: &Row, key: &str) -> String {
    match row.get(key) {
        Some(Variant::String(v)) => v.trim().to_string(),
        Some(Variant::UI1(v)) => v.to_string(),
        Some(Variant::UI2(v)) => v.to_string(),
        Some(Variant::UI4(v)) => v.to_string(),
        Some(Variant::UI8(v)) => v.to_string(),
        Some(Variant::I1(v)) => v.to_string(),
        Some(Variant::I2(v)) => v.to_string(),
        Some(Variant::I4(v)) => v.to_string(),
        Some(Variant::I8(v)) => v.to_string(),
        Some(Variant::Bool(v)) => v.to_string(),
        _ => String::new(),
    }
}

pub fn opt_u(row: &Row, key: &str) -> Option<u64> {
    match row.get(key)? {
        Variant::UI1(v) => Some(*v as u64),
        Variant::UI2(v) => Some(*v as u64),
        Variant::UI4(v) => Some(*v as u64),
        Variant::UI8(v) => Some(*v),
        Variant::I1(v) if *v >= 0 => Some(*v as u64),
        Variant::I2(v) if *v >= 0 => Some(*v as u64),
        Variant::I4(v) if *v >= 0 => Some(*v as u64),
        Variant::I8(v) if *v >= 0 => Some(*v as u64),
        Variant::R4(v) if *v >= 0.0 => Some(*v as u64),
        Variant::R8(v) if *v >= 0.0 => Some(*v as u64),
        Variant::String(v) => v.trim().parse().ok(),
        _ => None,
    }
}

pub fn u(row: &Row, key: &str) -> u64 {
    opt_u(row, key).unwrap_or(0)
}
