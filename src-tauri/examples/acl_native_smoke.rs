//! A-S1 native bridge smoke, with the real ACL and dialog initializer. This
//! fixture opens only its own window, cancels only dialogs in its own process,
//! and never constructs NetworkManager or loads user settings/media/capture.
//! Run with POCKETSTREAM_RELEASE unset: cargo run --example acl_native_smoke.

#[cfg(windows)]
mod windows {
    use std::{
        borrow::Cow,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc,
        },
        time::{Duration, Instant},
    };

    use tauri::{
        utils::assets::{AssetKey, AssetsIter, CspHash},
        Manager,
    };
    use windows_sys::Win32::{
        Foundation::{BOOL, HWND, LPARAM},
        UI::WindowsAndMessaging::{
            EnumWindows, GetClassNameW, GetWindowThreadProcessId, PostMessageW, WM_COMMAND,
        },
    };

    #[derive(Default)]
    struct SmokeState {
        dialog_step: AtomicUsize,
        cancelled_step: AtomicUsize,
        passed: AtomicBool,
        finished: AtomicBool,
    }

    struct SmokeAssets;
    impl<R: tauri::Runtime> tauri::Assets<R> for SmokeAssets {
        fn get(&self, _: &AssetKey) -> Option<Cow<'_, [u8]>> {
            Some(Cow::Borrowed(
                b"<!doctype html><title>ACL native smoke</title><p>Isolated ACL smoke</p>",
            ))
        }
        fn iter(&self) -> Box<AssetsIter<'_>> {
            Box::new(std::iter::empty())
        }
        fn csp_hashes(&self, _: &AssetKey) -> Box<dyn Iterator<Item = CspHash<'_>> + '_> {
            Box::new(std::iter::empty())
        }
    }

    #[tauri::command]
    fn log_frontend(
        app: tauri::AppHandle,
        state: tauri::State<'_, Arc<SmokeState>>,
        level: String,
        message: String,
    ) {
        println!(
            "smoke {level}: {}",
            message.chars().take(2000).collect::<String>()
        );
        match level.as_str() {
            "address" => state.dialog_step.store(1, Ordering::SeqCst),
            "dhcp" => state.dialog_step.store(2, Ordering::SeqCst),
            "restore" => {
                let window = app.get_webview_window("main").unwrap();
                window.unminimize().unwrap();
                window.set_size(tauri::LogicalSize::new(960, 600)).unwrap();
            }
            "complete" => state.passed.store(true, Ordering::SeqCst),
            "failed" => app.exit(1),
            _ => {}
        }
    }

    unsafe extern "system" fn cancel_own_dialog(window: HWND, parameter: LPARAM) -> BOOL {
        let state = &*(parameter as *const SmokeState);
        let mut pid = 0;
        GetWindowThreadProcessId(window, &mut pid);
        if pid == std::process::id() {
            let mut class = [0u16; 32];
            let len = GetClassNameW(window, class.as_mut_ptr(), class.len() as i32);
            if String::from_utf16_lossy(&class[..len as usize]) == "#32770" {
                let step = state.dialog_step.load(Ordering::SeqCst);
                if step > 0
                    && PostMessageW(window, WM_COMMAND, 2, 0) != 0
                    && state.cancelled_step.fetch_max(step, Ordering::SeqCst) < step
                {
                    println!("native dialog observed and Cancel posted: step={step}");
                }
            }
        }
        1
    }

    pub fn run() -> i32 {
        let state = Arc::new(SmokeState::default());
        let mut context = tauri::generate_context!();
        context.config_mut().app.windows.clear();
        // Keep the generated runtime authority intact; replace only the assets
        // so the real production main.ts cannot initialize application work.
        context.set_assets(Box::new(SmokeAssets));
        let app = tauri::Builder::default()
            .manage(state.clone())
            .plugin(tauri_plugin_dialog::init())
            .plugin(tauri_plugin_notification::init())
            .plugin(tauri_plugin_updater::Builder::new().build())
            .invoke_handler(tauri::generate_handler![log_frontend])
            .setup(|app| {
                tauri::WebviewWindowBuilder::new(app, "main", Default::default())
                    .title("PocketStream isolated ACL smoke")
                    .data_directory(
                        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                            .join("target/acl-smoke-webview"),
                    )
                    .build()?;
                Ok(())
            })
            .on_page_load(|webview, event| {
                if event.event() == tauri::webview::PageLoadEvent::Finished {
                    webview
                        .eval(include_str!("../tests/fixtures/acl-native-smoke.js"))
                        .unwrap();
                }
            })
            .build(context)
            .expect("native ACL fixture must build");
        let handle = app.handle().clone();
        let observer_state = state.clone();
        let observer = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(30);
            while !observer_state.finished.load(Ordering::SeqCst) {
                unsafe {
                    EnumWindows(
                        Some(cancel_own_dialog),
                        Arc::as_ptr(&observer_state) as LPARAM,
                    );
                }
                if Instant::now() >= deadline {
                    eprintln!("native smoke timed out; gate remains pending");
                    handle.exit(2);
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        });
        let code = app.run_return(|_, _| {});
        state.finished.store(true, Ordering::SeqCst);
        observer.join().unwrap();
        if code == 0
            && state.passed.load(Ordering::SeqCst)
            && state.cancelled_step.load(Ordering::SeqCst) == 2
        {
            println!("native ACL/confirm bridge smoke passed");
            0
        } else {
            eprintln!(
                "native smoke incomplete: exit={code}, passed={}, native_dialog_steps={}",
                state.passed.load(Ordering::SeqCst),
                state.cancelled_step.load(Ordering::SeqCst)
            );
            1
        }
    }
}

fn main() {
    #[cfg(windows)]
    std::process::exit(windows::run());
    #[cfg(not(windows))]
    {
        eprintln!("Native ACL smoke requires Windows/WebView2; gate remains pending.");
        std::process::exit(2);
    }
}
