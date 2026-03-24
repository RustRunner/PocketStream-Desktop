fn main() {
    // Add src-tauri/lib to native library search path (wpcap.lib, Packet.lib)
    let lib_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("lib");
    println!("cargo:rustc-link-search=native={}", lib_dir.display());

    // Embed Windows manifest requesting administrator elevation (UAC)
    #[cfg(target_os = "windows")]
    {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("pocketstream.exe.manifest");
        println!("cargo:rerun-if-changed={}", manifest.display());

        let mut res = tauri_build::WindowsAttributes::new();
        res = res.app_manifest(std::fs::read_to_string(&manifest).expect("failed to read manifest"));
        tauri_build::try_build(tauri_build::Attributes::new().windows_attributes(res))
            .expect("failed to run tauri-build");
        return;
    }

    #[allow(unreachable_code)]
    tauri_build::build()
}
