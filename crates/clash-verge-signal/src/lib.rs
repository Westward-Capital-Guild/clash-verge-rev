//! Termination signal bridge for Linux and macOS.
//!
//! Shell termination signals must enter the app quit flow before the process
//! exits so its sidecar and system proxy are cleaned up.

#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::sync::{
    OnceLock,
    atomic::{AtomicBool, Ordering},
};

use clash_verge_logging::{Type, logging};

mod unix;

pub(crate) static RUNTIME: OnceLock<Option<tokio::runtime::Runtime>> = OnceLock::new();
pub(crate) static SHUTDOWN_LATCH: ShutdownLatch = ShutdownLatch::new();

/// Serializes signal-triggered cleanups: a signal arriving while a quit
/// attempt is still in flight is dropped instead of overlapping it.
pub(crate) struct ShutdownLatch {
    is_cleaning_up: AtomicBool,
}

impl ShutdownLatch {
    const fn new() -> Self {
        Self {
            is_cleaning_up: AtomicBool::new(false),
        }
    }

    fn try_begin(&self) -> bool {
        self.is_cleaning_up
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn finish(&self) {
        self.is_cleaning_up.store(false, Ordering::Release);
    }
}

/// Spawns the Unix signal loop on a dedicated runtime so it survives the
/// teardown of any app-owned runtime. The handler runs once per accepted
/// signal; the quit flow it invokes owns the exit-or-cancel decision.
pub fn register<F, Fut>(f: F)
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    RUNTIME.get_or_init(|| match tokio::runtime::Runtime::new() {
        Ok(rt) => Some(rt),
        Err(e) => {
            logging!(
                info,
                Type::SystemSignal,
                "register shutdown signal failed, create tokio runtime error: {}",
                e
            );
            None
        }
    });

    unix::register(f);
}

#[cfg(test)]
mod tests {
    use super::ShutdownLatch;

    #[test]
    fn finished_attempt_releases_latch_for_the_next_signal() {
        let latch = ShutdownLatch::new();

        assert!(latch.try_begin());
        assert!(!latch.try_begin());

        latch.finish();

        assert!(latch.try_begin());
    }
}
