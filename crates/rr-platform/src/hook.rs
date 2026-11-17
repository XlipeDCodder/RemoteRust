//! System shortcuts for the Viewer (blueprint v2 §8.7): while the Viewer
//! controls a remote desktop and has the focus, every physical key goes to
//! the remote instead of the local system, Alt+Tab and the Windows key
//! included. Ctrl+Alt+Del and Win+L always stay with the local system.
//!
//! Windows only for now (a low-level keyboard hook). Elsewhere
//! [`KeyboardHook::install`] fails and the window's own key events are
//! used, so system shortcuts stay local.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::input::{InputError, KeyCode};

/// Takes physical keys from the local system while active.
pub struct KeyboardHook {
    active: Arc<AtomicBool>,
    #[cfg(windows)]
    _hook: crate::win::hook::Hook,
}

impl KeyboardHook {
    /// Installs the hook, inactive. `forward` receives every key the hook
    /// takes, with `true` for a press (repeats included) and `false` for a
    /// release; it runs on the hook's own thread and must return quickly,
    /// since the whole desktop's keyboard waits for it.
    ///
    /// # Errors
    /// [`InputError::Unsupported`] outside Windows, or an OS failure.
    pub fn install(
        forward: impl FnMut(KeyCode, bool) + Send + 'static,
    ) -> Result<Self, InputError> {
        #[cfg(windows)]
        {
            let active = Arc::new(AtomicBool::new(false));
            let hook = crate::win::hook::install(Arc::clone(&active), Box::new(forward))?;
            Ok(Self {
                active,
                _hook: hook,
            })
        }
        #[cfg(not(windows))]
        {
            let _ = forward;
            Err(InputError::Unsupported(
                "capturing system shortcuts is only implemented on Windows",
            ))
        }
    }

    /// Starts (`true`) or stops taking keys: on while the Viewer has the
    /// focus and controls the remote. Keys already taken still have their
    /// release taken after this turns off.
    pub fn set_active(&self, active: bool) {
        self.active.store(active, Ordering::Relaxed);
    }
}

impl std::fmt::Debug for KeyboardHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyboardHook")
            .field("active", &self.active.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}
