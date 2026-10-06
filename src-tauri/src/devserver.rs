//! Only in development builds (`cfg(dev)`, e.g. a plain `cargo run`): the
//! window loads the UI from the Vite dev server (`build.devUrl`). `pnpm tauri
//! dev` starts it through `beforeDevCommand`, but `cargo run` does not, and
//! WebView2 then shows "localhost rechazó la conexión". Here the server is
//! started automatically, or a clear message explains what to run.

use std::net::{Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONWARNING, MB_OK};

use crate::util::{hidden_command, wide};

pub struct DevServer(Option<Child>);

impl DevServer {
    /// Stops the server we started (cmd.exe → pnpm → node, hence `/T`).
    pub fn stop(&mut self) {
        if let Some(child) = self.0.take() {
            let _ = hidden_command("taskkill.exe")
                .args(["/PID", &child.id().to_string(), "/T", "/F"])
                .output();
        }
    }
}

fn listening(host: &str, port: u16) -> bool {
    // Node 17+ may bind "localhost" only on ::1; try both loopbacks.
    let mut addrs: Vec<SocketAddr> = (host, port).to_socket_addrs().map(|a| a.collect()).unwrap_or_default();
    addrs.push(SocketAddr::from(([127, 0, 0, 1], port)));
    addrs.push(SocketAddr::from((Ipv6Addr::LOCALHOST, port)));
    addrs.iter().any(|a| TcpStream::connect_timeout(a, Duration::from_millis(250)).is_ok())
}

fn fail(url: &str, reason: &str) -> ! {
    let text = format!(
        "NexFix se ha compilado en modo desarrollo y carga la interfaz desde {url}, \
         pero ese servidor (Vite) no está en marcha: {reason}.\n\n\
         Desde la carpeta del proyecto ejecuta:\n\
         \u{2003}pnpm install\n\
         \u{2003}pnpm tauri dev\n\n\
         Para generar el programa final, que no necesita servidor:\n\
         \u{2003}pnpm tauri build"
    );
    eprintln!("[NexFix] {text}");
    let (t, c) = (wide(&text), wide("NexFix · modo desarrollo"));
    unsafe { MessageBoxW(std::ptr::null_mut(), t.as_ptr(), c.as_ptr(), MB_OK | MB_ICONWARNING) };
    std::process::exit(1);
}

pub fn ensure(dev_url: Option<&tauri::Url>) -> DevServer {
    let Some(url) = dev_url else { return DevServer(None) };
    let host = url.host_str().unwrap_or("localhost").to_string();
    let port = url.port_or_known_default().unwrap_or(80);
    let local = matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1" | "[::1]");
    if !local || listening(&host, port) {
        return DevServer(None);
    }

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    if !root.join("package.json").exists() {
        fail(url.as_str(), "no se encontró package.json junto a src-tauri");
    }
    let script = if root.join("node_modules").exists() { "pnpm dev" } else { "pnpm install && pnpm dev" };
    eprintln!("[NexFix] Iniciando la interfaz con «{script}» (usa `pnpm tauri dev` para hacerlo en un paso)…");

    // `pnpm` is a .cmd shim on Windows: it has to go through cmd.exe.
    let mut child = match Command::new("cmd.exe").args(["/C", script]).current_dir(&root).spawn() {
        Ok(c) => c,
        Err(e) => fail(url.as_str(), &format!("no se pudo ejecutar cmd.exe ({e})")),
    };
    let start = Instant::now();
    while !listening(&host, port) {
        if let Ok(Some(status)) = child.try_wait() {
            fail(
                url.as_str(),
                &format!("«{script}» terminó con código {:?}; ¿están instalados Node.js y pnpm?", status.code()),
            );
        }
        if start.elapsed() > Duration::from_secs(120) {
            let _ = child.kill();
            fail(url.as_str(), "el servidor no respondió en 2 minutos");
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    DevServer(Some(child))
}
