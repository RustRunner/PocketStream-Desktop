fn main() {
    // Add src-tauri/lib to native library search path (wpcap.lib, Packet.lib)
    let lib_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("lib");
    println!("cargo:rustc-link-search=native={}", lib_dir.display());

    tauri_build::build()
}
