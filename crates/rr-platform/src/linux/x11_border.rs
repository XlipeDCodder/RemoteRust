//! The session border on X11 (see [`crate::border`]): four override-redirect
//! windows whose background the X server paints, with an empty input shape
//! so clicks reach the windows below. Nothing needs a thread: the server
//! repaints the background by itself.

use x11rb::connection::Connection as _;
use x11rb::protocol::shape::SK;
use x11rb::protocol::xfixes::ConnectionExt as _;
use x11rb::protocol::xproto::{
    ConfigureWindowAux, ConnectionExt as _, CreateWindowAux, StackMode, Window, WindowClass,
};
use x11rb::rust_connection::RustConnection;
use x11rb::wrapper::ConnectionExt as _;
use x11rb::{COPY_DEPTH_FROM_PARENT, COPY_FROM_PARENT};

use crate::border::{BorderError, COLOR, Rect, strips};
use crate::input::Area;

fn os_error(context: &'static str, err: impl std::fmt::Display) -> BorderError {
    BorderError::Os {
        context,
        message: err.to_string(),
    }
}

/// The four windows; destroyed on drop.
pub(crate) struct Border {
    conn: RustConnection,
    windows: Vec<Window>,
}

impl Border {
    pub(crate) fn show(area: Area) -> Result<Self, BorderError> {
        let (conn, screen) =
            x11rb::connect(None).map_err(|err| os_error("connecting to the X server", err))?;
        let (root, colormap) = conn
            .setup()
            .roots
            .get(screen)
            .map(|screen| (screen.root, screen.default_colormap))
            .ok_or_else(|| os_error("connecting to the X server", "no such screen"))?;
        let pixel = red_pixel(&conn, colormap);
        // XFixes 2 sets input shapes; an empty region lets every click
        // through.
        conn.xfixes_query_version(5, 0)
            .map_err(|err| os_error("XFixesQueryVersion", err))?
            .reply()
            .map_err(|err| os_error("XFixesQueryVersion", err))?;
        let region = conn
            .generate_id()
            .map_err(|err| os_error("allocating an X id", err))?;
        conn.xfixes_create_region(region, &[])
            .map_err(|err| os_error("XFixesCreateRegion", err))?;

        let mut border = Self {
            conn,
            windows: Vec::with_capacity(4),
        };
        for (left, top, width, height) in strips(area) {
            let window = border
                .conn
                .generate_id()
                .map_err(|err| os_error("allocating an X id", err))?;
            border
                .conn
                .create_window(
                    COPY_DEPTH_FROM_PARENT,
                    window,
                    root,
                    clamp16(left),
                    clamp16(top),
                    clamp_size(width),
                    clamp_size(height),
                    0,
                    WindowClass::INPUT_OUTPUT,
                    COPY_FROM_PARENT,
                    &CreateWindowAux::new()
                        .background_pixel(pixel)
                        .override_redirect(1),
                )
                .map_err(|err| os_error("CreateWindow", err))?;
            border.windows.push(window);
            border
                .conn
                .xfixes_set_window_shape_region(window, SK::INPUT, 0, 0, region)
                .map_err(|err| os_error("XFixesSetWindowShapeRegion", err))?;
            border
                .conn
                .map_window(window)
                .map_err(|err| os_error("MapWindow", err))?;
        }
        let _ = border.conn.xfixes_destroy_region(region);
        border.raise();
        border
            .conn
            .sync()
            .map_err(|err| os_error("creating the border", err))?;
        Ok(border)
    }

    pub(crate) fn move_to(&self, area: Area) {
        for (window, rect) in self.windows.iter().zip(strips(area)) {
            let _ = self.conn.configure_window(*window, &aux(rect));
        }
        let _ = self.conn.flush();
    }

    fn raise(&self) {
        for window in &self.windows {
            let _ = self.conn.configure_window(
                *window,
                &ConfigureWindowAux::new().stack_mode(StackMode::ABOVE),
            );
        }
        let _ = self.conn.flush();
    }
}

impl Drop for Border {
    fn drop(&mut self) {
        for window in &self.windows {
            let _ = self.conn.destroy_window(*window);
        }
        let _ = self.conn.flush();
    }
}

fn aux((left, top, width, height): Rect) -> ConfigureWindowAux {
    ConfigureWindowAux::new()
        .x(left)
        .y(top)
        .width(width.max(1))
        .height(height.max(1))
        .stack_mode(StackMode::ABOVE)
}

/// The border color in the default colormap; the plain `0xRRGGBB` value
/// (right for the usual TrueColor visuals) if the server will not say.
fn red_pixel(conn: &RustConnection, colormap: u32) -> u32 {
    let channel = |shift: u32| {
        let value = u16::try_from((COLOR >> shift) & 0xFF).unwrap_or(0);
        value.saturating_mul(0x101)
    };
    conn.alloc_color(colormap, channel(16), channel(8), channel(0))
        .ok()
        .and_then(|cookie| cookie.reply().ok())
        .map_or(COLOR, |reply| reply.pixel)
}

fn clamp16(value: i32) -> i16 {
    i16::try_from(value).unwrap_or(if value < 0 { i16::MIN } else { i16::MAX })
}

fn clamp_size(value: u32) -> u16 {
    u16::try_from(value.max(1)).unwrap_or(u16::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coordinates_are_clamped_to_the_protocol() {
        assert_eq!(clamp16(-40_000), i16::MIN);
        assert_eq!(clamp16(70_000), i16::MAX);
        assert_eq!(clamp16(-6), -6);
        assert_eq!(clamp_size(0), 1);
        assert_eq!(clamp_size(100_000), u16::MAX);
    }

    /// Run under Xvfb: `xvfb-run -a cargo test -- --ignored`.
    #[test]
    #[ignore = "needs an X server"]
    fn shows_moves_and_removes_the_border() {
        let border = Border::show(Area {
            left: 0,
            top: 0,
            width: 640,
            height: 480,
        })
        .unwrap();
        assert_eq!(border.windows.len(), 4);
        border.move_to(Area {
            left: 10,
            top: 10,
            width: 320,
            height: 240,
        });
        border.conn.sync().unwrap();
        drop(border);
    }
}
