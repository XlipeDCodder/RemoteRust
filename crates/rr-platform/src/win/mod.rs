//! Windows backends: DXGI Desktop Duplication, D3D11, `SendInput`,
//! WTS session APIs, named pipes and low-level keyboard hooks.
//!
//! Named `win` (not `windows`) so it never clashes with the `windows` crate.

pub(crate) mod dpapi;
