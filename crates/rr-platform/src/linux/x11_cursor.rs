//! The pointer on X11 (blueprint v2 §6.2): `QueryPointer` for the
//! position, XFixes for the image, fetched only after a `CursorNotify`
//! says it changed.

use x11rb::connection::Connection as _;
use x11rb::protocol::Event;
use x11rb::protocol::xfixes::{self, ConnectionExt as _, CursorNotifyMask};
use x11rb::protocol::xproto::{self, ConnectionExt as _};
use x11rb::rust_connection::RustConnection;

use crate::capture::CaptureError;
use crate::cursor::{self, CursorSource, Pointer, Shape};
use crate::linux::x11::{connect, has_extension, x11_error};

/// Follows the pointer of the display named by `$DISPLAY`.
pub(crate) struct XFixesCursor {
    conn: RustConnection,
    root: xproto::Window,
    /// The image changed since it was last read (starts `true`).
    changed: bool,
}

impl XFixesCursor {
    pub(crate) fn open() -> Result<Self, CaptureError> {
        let (conn, screen) = connect()?;
        if !has_extension(&conn, xfixes::X11_EXTENSION_NAME)? {
            return Err(CaptureError::Unsupported(
                "the X server has no XFixes extension",
            ));
        }
        conn.xfixes_query_version(4, 0)
            .map_err(|err| x11_error("XFixesQueryVersion", err))?
            .reply()
            .map_err(|err| x11_error("XFixesQueryVersion", err))?;
        conn.xfixes_select_cursor_input(screen.root, CursorNotifyMask::DISPLAY_CURSOR)
            .map_err(|err| x11_error("XFixesSelectCursorInput", err))?
            .check()
            .map_err(|err| x11_error("XFixesSelectCursorInput", err))?;
        Ok(Self {
            conn,
            root: screen.root,
            changed: true,
        })
    }

    fn read_shape(&self) -> Result<Option<Shape>, CaptureError> {
        let image = self
            .conn
            .xfixes_get_cursor_image()
            .map_err(|err| x11_error("XFixesGetCursorImage", err))?
            .reply()
            .map_err(|err| x11_error("XFixesGetCursorImage", err))?;
        let rgba = cursor::from_premultiplied_argb(&image.cursor_image);
        Ok(Shape::new(
            usize::from(image.width),
            usize::from(image.height),
            (u32::from(image.xhot), u32::from(image.yhot)),
            &rgba,
        ))
    }
}

impl CursorSource for XFixesCursor {
    fn poll(&mut self) -> Result<(Pointer, Option<Shape>), CaptureError> {
        while let Some(event) = self
            .conn
            .poll_for_event()
            .map_err(|err| x11_error("reading X events", err))?
        {
            if matches!(event, Event::XfixesCursorNotify(_)) {
                self.changed = true;
            }
        }
        let position = self
            .conn
            .query_pointer(self.root)
            .map_err(|err| x11_error("QueryPointer", err))?
            .reply()
            .map_err(|err| x11_error("QueryPointer", err))?;
        let pointer = Pointer {
            x: i32::from(position.root_x),
            y: i32::from(position.root_y),
            visible: position.same_screen,
        };
        let shape = if self.changed {
            self.changed = false;
            self.read_shape()?
        } else {
            None
        };
        Ok((pointer, shape))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run under Xvfb: `xvfb-run -a cargo test -- --ignored`.
    #[test]
    #[ignore = "needs an X server"]
    fn reads_position_and_shape_once() {
        let mut source = XFixesCursor::open().unwrap();
        let (_, first) = source.poll().unwrap();
        let shape = first.expect("the first poll reads the image");
        assert!(shape.width > 0 && shape.height > 0);
        assert_eq!(
            shape.rgba.len(),
            usize::from(shape.width) * usize::from(shape.height) * 4
        );
        let (_, second) = source.poll().unwrap();
        assert!(second.is_none(), "unchanged image is not read again");
    }
}
