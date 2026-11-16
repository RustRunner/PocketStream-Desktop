const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { test } = require("node:test");

const source = file => fs.readFileSync(path.join(__dirname, "../src-tauri/src", file), "utf8");

test("PTU and zoom use bound readiness while the system browser still requires its route", () => {
  const ptu = source("camera/flir_ptu.rs");
  const camera = source("commands/camera.rs");
  const zoom = camera.slice(camera.indexOf("pub async fn control_cgi_zoom_direct("),
    camera.indexOf("pub async fn set_zoom_position("));
  const browser = camera.slice(camera.indexOf("pub async fn open_device_browser("),
    camera.indexOf("pub async fn ptu_send("));
  for (const control of [ptu, zoom]) {
    assert.match(control, /readiness\.bound_now\(/);
    assert.match(control, /\|\| readiness\.bound_now\(&path\.target\)/);
    assert.match(control, /bound_http::post_form\(/);
    assert.doesNotMatch(control, /camera_ready|reqwest::Client/);
  }
  assert.match(browser, /manager\.camera_ready_now\(&target, &config\)/);
  const manager = source("network/mod.rs");
  const routeCheck = manager.slice(manager.indexOf("pub(crate) fn camera_ready_now("));
  assert.match(routeCheck.slice(0, routeCheck.indexOf("\n    }")),
    /camera_path_now\(target, config, false\)/);
});

test("PTU holds its send lock across the bound request and adds no resend", () => {
  const ptu = source("camera/flir_ptu.rs");
  assert(ptu.indexOf("self.send_lock.lock().await") < ptu.indexOf("readiness.bound_now(target)"));
  assert.match(ptu, /let _guard = self\.send_lock\.lock\(\)\.await/);
  assert.match(ptu, /&normalize_ptu_cmd\(cmd\)/);
  assert.doesNotMatch(ptu, /tokio::spawn|async_runtime::spawn|retry|for attempt/);
});
