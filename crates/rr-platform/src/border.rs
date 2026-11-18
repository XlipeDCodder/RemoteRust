//! The session indicator (blueprint v2 §7.5): a colored frame around the
//! monitor being shared, drawn as four thin always-on-top strips that
//! clicks pass through.
//!
//! - Windows: four layered tool windows painted by the system with a solid
//!   brush, on a thread of their own. They are excluded from screen capture
//!   (Windows 10 2004 and later), so the Viewer does not see them.
//! - X11: four override-redirect windows whose background the X server
//!   paints, with an empty input shape. They show in the capture: X11 has
//!   no way to leave a window out of it.
//! - Wayland: unsupported (clients cannot place windows); GNOME and KDE
//!   show their own screen-sharing indicator.

use std::time::{Duration, Instant};

use crate::input::Area;

/// How often the strips are put back on top of other always-on-top
/// windows.
const RAISE_EVERY: Duration = Duration::from_secs(2);

/// Strip thickness, in pixels.
pub const THICKNESS: u32 = 6;

/// Strip color (red), as `0xRRGGBB`.
pub const COLOR: u32 = 0x00E5_3935;

/// Why the border cannot be shown.
#[derive(Debug, thiserror::Error)]
pub enum BorderError {
    /// Not possible in this session (Wayland, no display).
    #[error("the session border is not supported here: {0}")]
    Unsupported(&'static str),
    /// A system call failed.
    #[error("{context} failed: {message}")]
    Os {
        /// The failing call.
        context: &'static str,
        /// The error text.
        message: String,
    },
}

/// One strip: left, top, width, height.
pub(crate) type Rect = (i32, i32, u32, u32);

/// The four strips framing `area`, inside its edges: top, bottom, left,
/// right. A monitor too small for a frame gets whatever fits.
pub(crate) fn strips(area: Area) -> [Rect; 4] {
    let thickness = THICKNESS.min(area.width / 2).min(area.height / 2).max(1);
    let step = i32::try_from(thickness).unwrap_or(1);
    let right = area
        .left
        .saturating_add(i32::try_from(area.width).unwrap_or(i32::MAX))
        .saturating_sub(step);
    let bottom = area
        .top
        .saturating_add(i32::try_from(area.height).unwrap_or(i32::MAX))
        .saturating_sub(step);
    let side = area.height.saturating_sub(2 * thickness).max(1);
    [
        (area.left, area.top, area.width, thickness),
        (area.left, bottom, area.width, thickness),
        (area.left, area.top.saturating_add(step), thickness, side),
        (right, area.top.saturating_add(step), thickness, side),
    ]
}

/// The border on screen; removed on drop.
pub struct Border {
    #[cfg(windows)]
    inner: crate::win::border::Border,
    #[cfg(target_os = "linux")]
    inner: crate::linux::x11_border::Border,
    area: Area,
    raised: Instant,
}

impl Border {
    /// Shows the border around `area` (desktop pixels, as for input).
    ///
    /// # Errors
    /// [`BorderError::Unsupported`] on Wayland and other systems; a system
    /// failure.
    pub fn show(area: Area) -> Result<Self, BorderError> {
        #[cfg(windows)]
        {
            Ok(Self {
                inner: crate::win::border::Border::show(area)?,
                area,
                raised: Instant::now(),
            })
        }
        #[cfg(target_os = "linux")]
        {
            match crate::linux::backend() {
                Ok(crate::linux::Backend::X11) => Ok(Self {
                    inner: crate::linux::x11_border::Border::show(area)?,
                    area,
                    raised: Instant::now(),
                }),
                Ok(crate::linux::Backend::Portal) => Err(BorderError::Unsupported(
                    "Wayland compositors do not let applications place windows",
                )),
                Err(_) => Err(BorderError::Unsupported("no graphical session")),
            }
        }
        #[cfg(not(any(windows, target_os = "linux")))]
        {
            let _ = area;
            Err(BorderError::Unsupported("no backend for this system"))
        }
    }

    /// Keeps the border around `area` (the monitor may have moved or
    /// changed resolution) and above other windows. Cheap: call it often.
    pub fn follow(&mut self, area: Area) {
        if area == self.area && self.raised.elapsed() < RAISE_EVERY {
            return;
        }
        self.area = area;
        self.raised = Instant::now();
        #[cfg(any(windows, target_os = "linux"))]
        self.inner.move_to(area);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_frame_the_monitor_without_overlapping() {
        let area = Area {
            left: -1920,
            top: 0,
            width: 1920,
            height: 1080,
        };
        assert_eq!(
            strips(area),
            [
                (-1920, 0, 1920, 6),
                (-1920, 1074, 1920, 6),
                (-1920, 6, 6, 1068),
                (-6, 6, 6, 1068),
            ]
        );
    }

    #[test]
    fn tiny_monitors_still_get_a_frame() {
        let area = Area {
            left: 0,
            top: 0,
            width: 4,
            height: 3,
        };
        for (_, _, width, height) in strips(area) {
            assert!(width >= 1 && height >= 1);
        }
    }
}
