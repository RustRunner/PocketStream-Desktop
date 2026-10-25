//! Child-window lifetime and main-thread dispatch. No work starts at construction.
use super::video_embed;
use crate::{bridge::AppBridge, error::AppError};
use std::sync::{Arc, Mutex};

/// Includes an incarnation because Windows may recycle an HWND value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SurfaceToken {
    hwnd: isize,
    generation: u64,
}

#[derive(Default)]
struct SurfaceState {
    generation: u64,
    current: Option<SurfaceToken>,
}

trait SurfaceOps: Send + Sync {
    fn create(&self, parent: isize, rect: [i32; 4]) -> Result<isize, AppError>;
    fn reposition(&self, hwnd: isize, rect: [i32; 4]) -> Result<(), AppError>;
    fn visible(&self, hwnd: isize, visible: bool) -> Result<(), AppError>;
    fn destroy(&self, hwnd: isize);
}

struct NativeSurfaceOps;
impl SurfaceOps for NativeSurfaceOps {
    fn create(&self, parent: isize, [x, y, width, height]: [i32; 4]) -> Result<isize, AppError> {
        video_embed::create_video_child(parent, x, y, width, height)
    }
    fn reposition(&self, hwnd: isize, [x, y, width, height]: [i32; 4]) -> Result<(), AppError> {
        video_embed::reposition(hwnd, x, y, width, height)
    }
    fn visible(&self, hwnd: isize, visible: bool) -> Result<(), AppError> {
        video_embed::set_visible(hwnd, visible)
    }
    fn destroy(&self, hwnd: isize) {
        video_embed::destroy_video_child(hwnd);
    }
}

pub(crate) struct VideoSurface {
    state: Arc<Mutex<SurfaceState>>,
    bridge: Arc<dyn AppBridge>,
    ops: Arc<dyn SurfaceOps>,
}

impl VideoSurface {
    pub(super) fn new(bridge: Arc<dyn AppBridge>) -> Self {
        Self {
            state: Arc::new(Mutex::new(SurfaceState::default())),
            bridge,
            ops: Arc::new(NativeSurfaceOps),
        }
    }

    pub(crate) fn capture(&self) -> Option<SurfaceToken> {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).current
    }

    pub(crate) fn hwnd(&self) -> Option<isize> {
        self.capture().map(|token| token.hwnd)
    }

    pub(crate) async fn create(&self, parent: isize, rect: [i32; 4]) -> Result<String, AppError> {
        let state = self.state.clone();
        let ops = self.ops.clone();
        self.on_main(move || {
            let mut state = state.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(old) = state.current.take() {
                ops.destroy(old.hwnd);
            }
            let hwnd = ops.create(parent, rect)?;
            state.generation = state.generation.wrapping_add(1);
            state.current = Some(SurfaceToken {
                hwnd,
                generation: state.generation,
            });
            Ok(hwnd.to_string())
        })
        .await
    }

    pub(crate) fn release(&self, expected: Option<SurfaceToken>) {
        let Some(expected) = expected else { return };
        {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if state.current != Some(expected) {
                return;
            }
            // Preserve the command's synchronous conditional release point.
            state.current = None;
        }
        let state = self.state.clone();
        let ops = self.ops.clone();
        // The detached child stays alive until queued destruction. Never touch
        // its numeric handle if a replacement incarnation now owns that value.
        let _ = self.bridge.run_on_main_thread(Box::new(move || {
            let state = state.lock().unwrap_or_else(|p| p.into_inner());
            if !state
                .current
                .is_some_and(|current| current.hwnd == expected.hwnd)
            {
                ops.destroy(expected.hwnd);
            }
        }));
    }

    pub(crate) async fn reposition(&self, rect: [i32; 4]) -> Result<(), AppError> {
        let Some(expected) = self.capture() else {
            return Ok(());
        };
        let state = self.state.clone();
        let ops = self.ops.clone();
        self.on_main(move || {
            let state = state.lock().unwrap_or_else(|p| p.into_inner());
            if state.current == Some(expected) {
                ops.reposition(expected.hwnd, rect)
            } else {
                Ok(())
            }
        })
        .await
    }

    pub(crate) async fn set_visible(&self, visible: bool) -> Result<(), AppError> {
        let Some(expected) = self.capture() else {
            return Ok(());
        };
        let state = self.state.clone();
        let ops = self.ops.clone();
        self.on_main(move || {
            let state = state.lock().unwrap_or_else(|p| p.into_inner());
            if state.current == Some(expected) {
                ops.visible(expected.hwnd, visible)
            } else {
                Ok(())
            }
        })
        .await
    }

    async fn on_main<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> Result<T, AppError> + Send + 'static,
    ) -> Result<T, AppError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.bridge
            .run_on_main_thread(Box::new(move || {
                let _ = tx.send(work());
            }))
            .map_err(|e| AppError::Stream(format!("Failed to run on main thread: {}", e)))?;
        rx.await
            .map_err(|_| AppError::Stream("Main thread channel closed".into()))?
    }

    #[cfg(test)]
    pub(super) fn set_hwnd(&self, hwnd: isize) {
        let mut state = self.state.lock().unwrap();
        state.generation += 1;
        state.current = (hwnd != 0).then_some(SurfaceToken {
            hwnd,
            generation: state.generation,
        });
    }

    #[cfg(test)]
    pub(super) fn clear_hwnd_if(&self, expected: isize) -> bool {
        let mut state = self.state.lock().unwrap();
        if state.current.is_some_and(|token| token.hwnd == expected) {
            state.current = None;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type MainWork = Box<dyn FnOnce() + Send>;
    #[derive(Default)]
    struct QueuedBridge(Mutex<Vec<MainWork>>);
    impl AppBridge for QueuedBridge {
        fn emit(&self, _: &str, _: serde_json::Value) -> Result<(), String> {
            Ok(())
        }
        fn run_on_main_thread(&self, work: MainWork) -> Result<(), String> {
            self.0.lock().unwrap().push(work);
            Ok(())
        }
    }
    impl QueuedBridge {
        async fn wait_for(&self, count: usize) {
            while self.0.lock().unwrap().len() < count {
                tokio::task::yield_now().await;
            }
        }
        fn run(&self, index: usize) {
            let work = self.0.lock().unwrap().remove(index);
            work();
        }
    }
    #[derive(Default)]
    struct FakeOps {
        calls: Mutex<Vec<&'static str>>,
        fail: std::sync::atomic::AtomicBool,
    }
    impl SurfaceOps for FakeOps {
        fn create(&self, _: isize, _: [i32; 4]) -> Result<isize, AppError> {
            self.calls.lock().unwrap().push("create");
            if self.fail.load(std::sync::atomic::Ordering::Relaxed) {
                Err(AppError::Stream("create failed".into()))
            } else {
                Ok(42)
            }
        }
        fn reposition(&self, _: isize, _: [i32; 4]) -> Result<(), AppError> {
            self.calls.lock().unwrap().push("position");
            Ok(())
        }
        fn visible(&self, _: isize, _: bool) -> Result<(), AppError> {
            self.calls.lock().unwrap().push("visible");
            Ok(())
        }
        fn destroy(&self, _: isize) {
            self.calls.lock().unwrap().push("destroy");
        }
    }
    fn fixture() -> (Arc<VideoSurface>, Arc<QueuedBridge>, Arc<FakeOps>) {
        let bridge = Arc::new(QueuedBridge::default());
        let ops = Arc::new(FakeOps::default());
        let mut surface = VideoSurface::new(bridge.clone());
        surface.ops = ops.clone();
        (Arc::new(surface), bridge, ops)
    }
    #[tokio::test]
    async fn stale_main_thread_work_cannot_touch_recycled_replacement_hwnd() {
        let (surface, bridge, ops) = fixture();
        surface.set_hwnd(42);
        let old = surface.capture();
        let s = surface.clone();
        let position = tokio::spawn(async move { s.reposition([0, 0, 1, 1]).await });
        let s = surface.clone();
        let visibility = tokio::spawn(async move { s.set_visible(false).await });
        bridge.wait_for(2).await;
        let s = surface.clone();
        let create = tokio::spawn(async move { s.create(1, [0, 0, 1, 1]).await });
        bridge.wait_for(3).await;
        bridge.run(2); // replacement runs before previously queued old work
        assert_eq!(create.await.unwrap().unwrap(), "42");
        assert_ne!(surface.capture(), old);
        surface.release(old);
        bridge.run(0);
        bridge.run(0);
        position.await.unwrap().unwrap();
        visibility.await.unwrap().unwrap();
        assert_eq!(*ops.calls.lock().unwrap(), ["destroy", "create"]);
        assert_eq!(surface.hwnd(), Some(42));
        surface.release(surface.capture());
        bridge.run(0);
        assert!(surface.hwnd().is_none());
        assert_eq!(*ops.calls.lock().unwrap(), ["destroy", "create", "destroy"]);
    }

    #[tokio::test]
    async fn conditional_release_is_immediate_and_stale_destroy_preserves_recycled_hwnd() {
        let (surface, bridge, ops) = fixture();
        surface.set_hwnd(42);
        let old = surface.capture();
        surface.release(old);
        assert!(surface.hwnd().is_none());
        surface.set_hwnd(42); // model reuse before queued old destruction
        assert_ne!(surface.capture(), old);
        bridge.run(0);
        assert_eq!(surface.hwnd(), Some(42));
        assert!(ops.calls.lock().unwrap().is_empty());
        surface.release(surface.capture());
        assert!(surface.hwnd().is_none());
        bridge.run(0);
        assert_eq!(*ops.calls.lock().unwrap(), ["destroy"]);
    }
    #[tokio::test]
    async fn failed_surface_replacement_retires_previous_handle() {
        let (surface, bridge, ops) = fixture();
        surface.set_hwnd(42);
        ops.fail.store(true, std::sync::atomic::Ordering::Relaxed);
        let s = surface.clone();
        let create = tokio::spawn(async move { s.create(1, [0, 0, 1, 1]).await });
        bridge.wait_for(1).await;
        bridge.run(0);
        assert_eq!(
            create.await.unwrap().unwrap_err().to_string(),
            "Stream error: create failed"
        );
        assert!(surface.hwnd().is_none());
        assert_eq!(*ops.calls.lock().unwrap(), ["destroy", "create"]);
    }

    #[test]
    fn stream_manager_video_hwnd_roundtrip() {
        let mgr = VideoSurface::new(Arc::new(crate::bridge::RecordingBridge::default()));
        assert!(mgr.hwnd().is_none());
        mgr.set_hwnd(0x12345);
        assert_eq!(mgr.hwnd(), Some(0x12345));
    }

    #[test]
    fn stale_stop_does_not_clear_replacement_video_hwnd() {
        let mgr = VideoSurface::new(Arc::new(crate::bridge::RecordingBridge::default()));
        mgr.set_hwnd(0x12345);
        mgr.set_hwnd(0x67890);

        assert!(!mgr.clear_hwnd_if(0x12345));
        assert_eq!(mgr.hwnd(), Some(0x67890));
        assert!(mgr.clear_hwnd_if(0x67890));
        assert!(mgr.hwnd().is_none());
    }
}
