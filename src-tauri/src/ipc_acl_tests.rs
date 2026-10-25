//! A-S1: the real generated application ACL with a minimal MockRuntime handler
//! set. Never construct NetworkManager or initialize capture/native mutation.

use std::sync::atomic::{AtomicUsize, Ordering};

use tauri::{ipc::InvokeBody, webview::InvokeRequest, Manager};

use crate::config::{AppConfig, AppSettings, NetworkMode};

#[derive(Default)]
struct CanaryExecutions(AtomicUsize);

#[tauri::command]
fn acl_denied_canary(executions: tauri::State<'_, CanaryExecutions>) {
    executions.0.fetch_add(1, Ordering::SeqCst);
}

fn minimal_handler<R: tauri::Runtime>() -> impl Fn(tauri::ipc::Invoke<R>) -> bool + Send + Sync {
    tauri::generate_handler![acl_denied_canary, crate::commands::get_network_mode]
}

fn request(command: &str, url: &str) -> InvokeRequest {
    InvokeRequest {
        cmd: command.into(),
        callback: tauri::ipc::CallbackFn(0),
        error: tauri::ipc::CallbackFn(1),
        url: url.parse().unwrap(),
        body: InvokeBody::default(),
        headers: Default::default(),
        invoke_key: tauri::test::INVOKE_KEY.into(),
    }
}

#[test]
fn generated_acl_denies_registered_canary_and_dispatches_allowed_command() {
    // This uses actual build.rs output and capabilities/default.json, rather
    // than mock_context (whose application authority would be empty).
    let app = tauri::test::mock_builder()
        .manage(CanaryExecutions::default())
        .manage(std::sync::Arc::new(AppConfig::temporary_test_config(
            AppSettings {
                network_mode: NetworkMode::StaticManual,
                ..AppSettings::default()
            },
        )))
        .invoke_handler(minimal_handler())
        .build(tauri::generate_context!())
        .expect("real generated context must build on MockRuntime");
    let main = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
        .build()
        .unwrap();

    let denied = tauri::test::get_ipc_response(
        &main,
        request("acl_denied_canary", "http://tauri.localhost"),
    )
    .expect_err("registered unpermitted canary must be denied");
    let error = denied.as_str().expect("ACL denial is a string");
    assert!(
        error.contains("acl_denied_canary not allowed")
            || error == "Command acl_denied_canary not allowed by ACL",
        "expected ACL rejection, got {error}"
    );
    assert_eq!(app.state::<CanaryExecutions>().0.load(Ordering::SeqCst), 0);
    println!("A-S1: ACL rejection={error}; denied canary executions=0");

    let allowed =
        tauri::test::get_ipc_response(&main, request("get_network_mode", "http://tauri.localhost"))
            .expect("allowed command must dispatch");
    assert_eq!(allowed.deserialize::<String>().unwrap(), "static_manual");
    println!("A-S1: allowed get_network_mode dispatched with isolated static_manual state");

    let other = tauri::WebviewWindowBuilder::new(&app, "other", Default::default())
        .build()
        .unwrap();
    assert!(tauri::test::get_ipc_response(
        &other,
        request("get_network_mode", "http://tauri.localhost"),
    )
    .is_err());
    assert!(tauri::test::get_ipc_response(
        &main,
        request("get_network_mode", "https://example.invalid"),
    )
    .is_err());
}

#[test]
fn denied_canary_is_present_in_the_minimal_handler() {
    // Control for optional Tauri command pruning: the very same handler must
    // execute the canary when the application ACL is deliberately absent.
    let app = tauri::test::mock_builder()
        .manage(CanaryExecutions::default())
        .invoke_handler(minimal_handler())
        .build(tauri::test::mock_context(tauri::test::noop_assets()))
        .unwrap();
    let main = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
        .build()
        .unwrap();
    tauri::test::get_ipc_response(
        &main,
        request("acl_denied_canary", "http://tauri.localhost"),
    )
    .expect("control must prove the denied canary was registered");
    assert_eq!(app.state::<CanaryExecutions>().0.load(Ordering::SeqCst), 1);
    println!("A-S1: registration control executed the canary once without an application ACL");
}
