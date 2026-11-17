//! The Agent's pointer on the Viewer (blueprint v2 §6.2).
//!
//! With control, the local pointer takes the remote shape over the picture
//! (a native cursor follows the hand with no network delay). Viewing only,
//! the remote pointer is drawn into the picture where the Agent says it is.
//! Shapes arrive once and are then named by id.

use std::collections::VecDeque;

use rr_proto::CursorMsg;
use rr_proto::cursor::CACHED_SHAPES;
use winit::event_loop::ActiveEventLoop;
use winit::window::CustomCursor;

/// Shapes kept: more than the Agent ever refers back to.
const KEPT_SHAPES: usize = 2 * CACHED_SHAPES;

struct Shape {
    id: u32,
    width: u16,
    height: u16,
    hot: (u16, u16),
    rgba: Vec<u8>,
    /// Made on first use with control.
    native: Option<CustomCursor>,
    /// Made on first use when viewing only.
    texture: Option<egui::TextureHandle>,
}

/// A shape ready to paint with egui.
pub struct Sprite {
    pub texture: egui::TextureId,
    /// Size in remote pixels.
    pub size: (f32, f32),
    /// Hot spot in remote pixels.
    pub hot: (f32, f32),
    /// Where the hot spot is, in protocol coordinates.
    pub position: (u16, u16),
}

/// What the Agent last said about its pointer.
#[derive(Default)]
pub struct RemoteCursor {
    shapes: VecDeque<Shape>,
    current: Option<u32>,
    position: Option<(u16, u16)>,
    visible: bool,
}

impl RemoteCursor {
    /// Takes one update. Returns whether the shape changed.
    pub fn update(&mut self, msg: CursorMsg) -> bool {
        match msg {
            CursorMsg::Position { x, y, visible } => {
                self.position = Some((x, y));
                self.visible = visible;
                false
            }
            CursorMsg::Shape {
                id,
                hot_x,
                hot_y,
                width,
                height,
                rgba,
            } => {
                self.shapes.retain(|shape| shape.id != id);
                self.shapes.push_back(Shape {
                    id,
                    width,
                    height,
                    hot: (hot_x, hot_y),
                    rgba: rgba.into_inner(),
                    native: None,
                    texture: None,
                });
                if self.shapes.len() > KEPT_SHAPES {
                    self.shapes.pop_front();
                }
                self.current = Some(id);
                true
            }
            CursorMsg::UseCachedShape { id } => {
                let known = self.shapes.iter().any(|shape| shape.id == id);
                if !known {
                    tracing::debug!(id, "unknown cursor shape");
                }
                let changed = self.current != Some(id);
                self.current = known.then_some(id);
                changed
            }
        }
    }

    /// Whether the Agent shows its pointer.
    pub const fn visible(&self) -> bool {
        self.visible
    }

    /// Whether a shape is known.
    pub const fn has_shape(&self) -> bool {
        self.current.is_some()
    }

    fn current_mut(&mut self) -> Option<&mut Shape> {
        let id = self.current?;
        self.shapes.iter_mut().find(|shape| shape.id == id)
    }

    /// The current shape as a native cursor (made once per shape).
    pub fn native(&mut self, event_loop: &ActiveEventLoop) -> Option<CustomCursor> {
        let shape = self.current_mut()?;
        if shape.native.is_none() {
            let source = CustomCursor::from_rgba(
                shape.rgba.clone(),
                shape.width,
                shape.height,
                shape.hot.0,
                shape.hot.1,
            )
            .inspect_err(|err| tracing::debug!(error = %err, "unusable cursor shape"))
            .ok()?;
            shape.native = Some(event_loop.create_custom_cursor(source));
        }
        shape.native.clone()
    }

    /// The pointer to paint, when the Agent shows it (viewing only).
    pub fn sprite(&mut self, ctx: &egui::Context) -> Option<Sprite> {
        let position = self.position.filter(|_| self.visible)?;
        let shape = self.current_mut()?;
        let texture = shape.texture.get_or_insert_with(|| {
            let image = egui::ColorImage::from_rgba_unmultiplied(
                [usize::from(shape.width), usize::from(shape.height)],
                &shape.rgba,
            );
            ctx.load_texture(
                format!("remote-cursor-{}", shape.id),
                image,
                egui::TextureOptions::LINEAR,
            )
        });
        Some(Sprite {
            texture: texture.id(),
            size: (f32::from(shape.width), f32::from(shape.height)),
            hot: (f32::from(shape.hot.0), f32::from(shape.hot.1)),
            position,
        })
    }
}

#[cfg(test)]
mod tests {
    use rr_proto::BoundedBytes;

    use super::*;

    fn shape(id: u32) -> CursorMsg {
        CursorMsg::Shape {
            id,
            hot_x: 0,
            hot_y: 0,
            width: 1,
            height: 1,
            rgba: BoundedBytes::new(vec![0, 0, 0, 255]).unwrap(),
        }
    }

    #[test]
    fn shapes_are_kept_and_reused_by_id() {
        let mut cursor = RemoteCursor::default();
        assert!(!cursor.has_shape());
        assert!(cursor.update(shape(1)));
        assert!(cursor.update(shape(2)));
        assert!(cursor.update(CursorMsg::UseCachedShape { id: 1 }));
        assert!(!cursor.update(CursorMsg::UseCachedShape { id: 1 }));
        assert!(cursor.has_shape());
        // An id the Agent never sent leaves no shape.
        cursor.update(CursorMsg::UseCachedShape { id: 99 });
        assert!(!cursor.has_shape());
    }

    #[test]
    fn the_viewer_keeps_more_shapes_than_the_agent_refers_to() {
        let mut cursor = RemoteCursor::default();
        for id in 0..u32::try_from(KEPT_SHAPES).unwrap() + 1 {
            cursor.update(shape(id));
        }
        // The Agent only refers to its last CACHED_SHAPES, all still here.
        let oldest = u32::try_from(KEPT_SHAPES + 1 - CACHED_SHAPES).unwrap();
        cursor.update(CursorMsg::UseCachedShape { id: oldest });
        assert!(cursor.has_shape());
        cursor.update(CursorMsg::UseCachedShape { id: 0 });
        assert!(!cursor.has_shape());
    }

    #[test]
    fn positions_and_visibility_are_tracked() {
        let mut cursor = RemoteCursor::default();
        assert!(!cursor.update(CursorMsg::Position {
            x: 5,
            y: 6,
            visible: true
        }));
        assert!(cursor.visible());
        let ctx = egui::Context::default();
        assert!(cursor.sprite(&ctx).is_none(), "no shape yet");
        cursor.update(shape(1));
        let sprite = cursor.sprite(&ctx).unwrap();
        assert_eq!(sprite.position, (5, 6));
        cursor.update(CursorMsg::Position {
            x: 5,
            y: 6,
            visible: false,
        });
        assert!(cursor.sprite(&ctx).is_none());
    }
}
