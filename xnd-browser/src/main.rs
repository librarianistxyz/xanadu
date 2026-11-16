use std::env;
use std::fs;
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

const HUB_ADDR: &str = "127.0.0.1:8765";
const HUB_URL: &str = "http://127.0.0.1:8765";
const HUB_SCRIPT: &str = "/home/librarianist/pcGDM/XANADU/xnd-hub/hub.py";

fn is_hub_up() -> bool {
    TcpStream::connect(HUB_ADDR).is_ok()
}

fn start_hub() -> Option<Child> {
    if is_hub_up() {
        return None;
    }
    let child = Command::new("python3")
        .arg(HUB_SCRIPT)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start xnd-hub");

    for _ in 0..40 {
        if is_hub_up() {
            return Some(child);
        }
        thread::sleep(Duration::from_millis(150));
    }
    eprintln!("xnd-hub did not become ready in time.");
    Some(child)
}

fn find_browser_bin() -> &'static str {
    for candidate in ["/usr/bin/google-chrome", "/snap/bin/chromium", "/usr/bin/chromium"] {
        if Path::new(candidate).exists() {
            return candidate;
        }
    }
    panic!("No Chromium/Chrome binary found for standalone app window.");
}

fn main() {
    let mut hub_child = start_hub();

    let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let profile_dir = format!("{home}/.local/share/xanadu-browser");
    let _ = fs::create_dir_all(&profile_dir);

    let browser = find_browser_bin();
    let status = Command::new(browser)
        .arg(format!("--app={HUB_URL}"))
        .arg(format!("--user-data-dir={profile_dir}"))
        .arg("--class=XanaduBrowser")
        .arg("--no-first-run")
        .status()
        .expect("Failed to launch Xanadu Browser window");

    if let Some(ref mut child) = hub_child {
        let _ = child.kill();
    }
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
}
