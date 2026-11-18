//! The Agent's icon, drawn in code: a small monitor, gray while idle and
//! red while the screen is shared (the color of the session border).

/// Icon side, in pixels.
pub const SIZE: u32 = 32;

const GRAY: [u8; 3] = [0x60, 0x7D, 0x8B];
const RED: [u8; 3] = [0xE5, 0x39, 0x35];
const LIGHT: [u8; 3] = [0xEC, 0xEF, 0xF1];
const WHITE: [u8; 3] = [0xFF, 0xFF, 0xFF];

/// RGBA pixels, `SIZE` × `SIZE`.
pub fn pixels(sharing: bool) -> Vec<u8> {
    let body = if sharing { RED } else { GRAY };
    let screen = if sharing { WHITE } else { LIGHT };
    let side = SIZE as usize;
    let mut rgba = vec![0_u8; side * side * 4];
    let mut fill = |x0: usize, y0: usize, x1: usize, y1: usize, color: [u8; 3]| {
        for y in y0..y1.min(side) {
            for x in x0..x1.min(side) {
                let at = (y * side + x) * 4;
                if let Some(pixel) = rgba.get_mut(at..at + 4) {
                    pixel.copy_from_slice(&[color[0], color[1], color[2], 0xFF]);
                }
            }
        }
    };
    // Frame, screen, stand and base.
    fill(2, 4, 30, 23, body);
    fill(5, 7, 27, 20, screen);
    fill(13, 23, 19, 26, body);
    fill(8, 26, 24, 29, body);
    if sharing {
        // A dot on the screen: "on air".
        fill(13, 10, 19, 17, RED);
    }
    rgba
}

/// The window icon.
pub fn window_icon(sharing: bool) -> Option<winit::window::Icon> {
    winit::window::Icon::from_rgba(pixels(sharing), SIZE, SIZE).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icons_have_the_right_size_and_differ() {
        let idle = pixels(false);
        let sharing = pixels(true);
        assert_eq!(idle.len(), (SIZE * SIZE * 4) as usize);
        assert_ne!(idle, sharing);
        // Corners stay transparent.
        assert_eq!(idle[3], 0);
    }
}
