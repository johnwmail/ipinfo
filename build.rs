fn main() {
    // Pass IPINFO_VERSION env var to the compiler so it's available via env!()/option_env!()
    // This works reliably even when invoked through worker-build -> wasm-pack -> cargo
    if let Ok(version) = std::env::var("IPINFO_VERSION") {
        println!("cargo:rustc-env=IPINFO_VERSION={}", version);
    }
}
