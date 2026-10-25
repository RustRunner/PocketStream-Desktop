//! Application effects. Owners receive this bridge, never managed-state access.
use std::sync::OnceLock;

pub(crate) trait AppBridge: Send + Sync {
    fn emit(&self, event: &str, payload: serde_json::Value) -> Result<(), String>;
    fn run_on_main_thread(&self, work: Box<dyn FnOnce() + Send>) -> Result<(), String>;
}

pub(crate) fn emit<T: serde::Serialize + ?Sized>(
    bridge: &dyn AppBridge,
    event: &str,
    payload: &T,
) -> Result<(), String> {
    bridge.emit(
        event,
        serde_json::to_value(payload).map_err(|e| e.to_string())?,
    )
}

pub(crate) struct TauriBridge<R: tauri::Runtime = tauri::Wry> {
    handle: OnceLock<tauri::AppHandle<R>>,
}

impl<R: tauri::Runtime> Default for TauriBridge<R> {
    fn default() -> Self {
        Self {
            handle: OnceLock::new(),
        }
    }
}

impl<R: tauri::Runtime> TauriBridge<R> {
    pub(crate) fn bind(&self, handle: tauri::AppHandle<R>) -> Result<(), String> {
        self.handle
            .set(handle)
            .map_err(|_| "Application bridge already bound".into())
    }
}

impl<R: tauri::Runtime> AppBridge for TauriBridge<R> {
    fn emit(&self, event: &str, payload: serde_json::Value) -> Result<(), String> {
        use tauri::Emitter;
        match self.handle.get() {
            Some(handle) => handle.emit(event, payload).map_err(|e| e.to_string()),
            None => Ok(()),
        }
    }

    fn run_on_main_thread(&self, work: Box<dyn FnOnce() + Send>) -> Result<(), String> {
        self.handle
            .get()
            .ok_or("Application bridge is not bound")?
            .run_on_main_thread(work)
            .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
#[derive(Default)]
pub(crate) struct RecordingBridge(pub std::sync::Mutex<Vec<(String, serde_json::Value)>>);

#[cfg(test)]
impl AppBridge for RecordingBridge {
    fn emit(&self, event: &str, payload: serde_json::Value) -> Result<(), String> {
        self.0.lock().unwrap().push((event.into(), payload));
        Ok(())
    }
    fn run_on_main_thread(&self, work: Box<dyn FnOnce() + Send>) -> Result<(), String> {
        work();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unbound_bridge_drops_events_and_rejects_main_thread_work() {
        let bridge = TauriBridge::<tauri::test::MockRuntime>::default();
        assert!(emit(&bridge, "device-list-changed", &Vec::<String>::new()).is_ok());
        assert!(bridge
            .run_on_main_thread(Box::new(|| panic!("unbound work ran")))
            .is_err());
    }

    #[test]
    fn bridge_binds_once() {
        let app = tauri::test::mock_builder()
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .unwrap();
        let bridge = TauriBridge::<tauri::test::MockRuntime>::default();
        assert!(bridge.bind(app.handle().clone()).is_ok());
        assert!(bridge.bind(app.handle().clone()).is_err());
    }
}
