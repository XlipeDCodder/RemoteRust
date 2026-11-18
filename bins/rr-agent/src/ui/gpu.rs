//! egui on wgpu for the Agent's small windows: one graphics device, opened
//! with the first window, and one surface per window.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use winit::event::WindowEvent;
use winit::event_loop::ActiveEventLoop;
use winit::window::{Window, WindowId};

/// Repaint requests further away than this are treated as "never".
const FAR_FUTURE: Duration = Duration::from_secs(3600);

/// The wgpu instance and, once a window exists, the device.
pub struct Graphics {
    instance: wgpu::Instance,
    device: Option<(wgpu::Adapter, wgpu::Device, wgpu::Queue)>,
}

impl Graphics {
    pub fn new(event_loop: &ActiveEventLoop) -> Self {
        let instance = wgpu::Instance::new(wgpu::InstanceDescriptor::new_with_display_handle(
            Box::new(event_loop.owned_display_handle()),
        ));
        Self {
            instance,
            device: None,
        }
    }

    /// Draws egui into `window`.
    pub fn painter(&mut self, window: Arc<Window>) -> anyhow::Result<Painter> {
        let surface = self
            .instance
            .create_surface(Arc::clone(&window))
            .context("cannot create a drawing surface for the window")?;
        if self.device.is_none() {
            self.device = Some(pollster::block_on(open_device(&self.instance, &surface))?);
        }
        let (adapter, device, queue) = self.device.as_ref().context("no graphics device")?;
        Painter::new(window, surface, adapter, device.clone(), queue.clone())
    }
}

async fn open_device(
    instance: &wgpu::Instance,
    surface: &wgpu::Surface<'_>,
) -> anyhow::Result<(wgpu::Adapter, wgpu::Device, wgpu::Queue)> {
    let adapter = instance
        .request_adapter(&wgpu::RequestAdapterOptions {
            power_preference: wgpu::PowerPreference::LowPower,
            compatible_surface: Some(surface),
            ..Default::default()
        })
        .await
        .context("no graphics adapter can draw the Agent window")?;
    let (device, queue) = adapter
        .request_device(&wgpu::DeviceDescriptor {
            label: Some("rr-agent"),
            ..Default::default()
        })
        .await
        .context("cannot open the graphics device")?;
    // wgpu's default treats any error nobody asked about as fatal (a
    // panic). A window that fails to draw must not take the Agent down.
    device.on_uncaptured_error(Arc::new(|error: wgpu::Error| {
        tracing::error!(%error, "graphics error in the Agent window");
    }));
    let info = adapter.get_info();
    tracing::debug!(adapter = %info.name, backend = ?info.backend, "Agent window graphics");
    Ok((adapter, device, queue))
}

/// One window drawn with egui.
pub struct Painter {
    window: Arc<Window>,
    surface: wgpu::Surface<'static>,
    config: wgpu::SurfaceConfiguration,
    view_format: wgpu::TextureFormat,
    device: wgpu::Device,
    queue: wgpu::Queue,
    renderer: egui_wgpu::Renderer,
    ctx: egui::Context,
    state: egui_winit::State,
    /// When egui wants the next frame (an animation), if ever.
    pub repaint_at: Option<Instant>,
}

impl Painter {
    fn new(
        window: Arc<Window>,
        surface: wgpu::Surface<'static>,
        adapter: &wgpu::Adapter,
        device: wgpu::Device,
        queue: wgpu::Queue,
    ) -> anyhow::Result<Self> {
        let caps = surface.get_capabilities(adapter);
        let format = caps
            .formats
            .iter()
            .copied()
            .find(|format| !format.is_srgb())
            .or_else(|| caps.formats.first().copied())
            .context("the window surface supports no pixel format")?;
        let view_format = format.remove_srgb_suffix();
        let size = window.inner_size();
        let config = wgpu::SurfaceConfiguration {
            usage: wgpu::TextureUsages::RENDER_ATTACHMENT,
            format,
            color_space: wgpu::SurfaceColorSpace::Auto,
            width: size.width.max(1),
            height: size.height.max(1),
            present_mode: wgpu::PresentMode::Fifo,
            desired_maximum_frame_latency: 2,
            alpha_mode: caps
                .alpha_modes
                .first()
                .copied()
                .unwrap_or(wgpu::CompositeAlphaMode::Auto),
            view_formats: if view_format == format {
                Vec::new()
            } else {
                vec![view_format]
            },
        };
        surface.configure(&device, &config);
        let renderer =
            egui_wgpu::Renderer::new(&device, view_format, egui_wgpu::RendererOptions::default());
        let ctx = egui::Context::default();
        #[allow(clippy::cast_possible_truncation)] // a scale factor fits an f32
        let scale = window.scale_factor() as f32;
        let max_texture = usize::try_from(device.limits().max_texture_dimension_2d).ok();
        let state = egui_winit::State::new(
            ctx.clone(),
            egui::ViewportId::ROOT,
            &window,
            Some(scale),
            window.theme(),
            max_texture,
        );
        Ok(Self {
            window,
            surface,
            config,
            view_format,
            device,
            queue,
            renderer,
            ctx,
            state,
            repaint_at: None,
        })
    }

    pub fn window(&self) -> &Window {
        &self.window
    }

    pub fn id(&self) -> WindowId {
        self.window.id()
    }

    /// Feeds a window event to egui; asks for a redraw if egui wants one.
    pub fn on_event(&mut self, event: &WindowEvent) {
        if let WindowEvent::Resized(size) = event
            && size.width > 0
            && size.height > 0
        {
            self.config.width = size.width;
            self.config.height = size.height;
            self.surface.configure(&self.device, &self.config);
        }
        if self.state.on_window_event(&self.window, event).repaint {
            self.window.request_redraw();
        }
    }

    /// Builds the frame with `ui` and draws it.
    pub fn paint(&mut self, ui: impl FnMut(&mut egui::Ui)) {
        let input = self.state.take_egui_input(&self.window);
        let output = self.ctx.run_ui(input, ui);
        self.state
            .handle_platform_output(&self.window, output.platform_output);
        let primitives = self.ctx.tessellate(output.shapes, output.pixels_per_point);
        for (id, deltas) in &output.textures_delta.set {
            for delta in deltas {
                self.renderer
                    .update_texture(&self.device, &self.queue, *id, delta);
            }
        }
        self.draw(&primitives, output.pixels_per_point);
        for id in &output.textures_delta.free {
            self.renderer.free_texture(id);
        }
        self.repaint_at = output
            .viewport_output
            .get(&egui::ViewportId::ROOT)
            .map(|viewport| viewport.repaint_delay)
            .filter(|delay| *delay < FAR_FUTURE)
            .and_then(|delay| Instant::now().checked_add(delay));
    }

    fn draw(&mut self, primitives: &[egui::ClippedPrimitive], pixels_per_point: f32) {
        let frame = match self.surface.get_current_texture() {
            wgpu::CurrentSurfaceTexture::Success(frame)
            | wgpu::CurrentSurfaceTexture::Suboptimal(frame) => frame,
            wgpu::CurrentSurfaceTexture::Outdated | wgpu::CurrentSurfaceTexture::Lost => {
                self.surface.configure(&self.device, &self.config);
                self.window.request_redraw();
                return;
            }
            wgpu::CurrentSurfaceTexture::Timeout
            | wgpu::CurrentSurfaceTexture::Occluded
            | wgpu::CurrentSurfaceTexture::Validation => return,
        };
        let view = frame.texture.create_view(&wgpu::TextureViewDescriptor {
            format: Some(self.view_format),
            ..Default::default()
        });
        let mut encoder = self
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("agent window"),
            });
        let screen = egui_wgpu::ScreenDescriptor {
            size_in_pixels: [self.config.width, self.config.height],
            pixels_per_point,
        };
        let commands = self.renderer.update_buffers(
            &self.device,
            &self.queue,
            &mut encoder,
            primitives,
            &screen,
        );
        {
            let mut pass = encoder
                .begin_render_pass(&wgpu::RenderPassDescriptor {
                    label: Some("agent window"),
                    color_attachments: &[Some(wgpu::RenderPassColorAttachment {
                        view: &view,
                        depth_slice: None,
                        resolve_target: None,
                        ops: wgpu::Operations {
                            load: wgpu::LoadOp::Clear(wgpu::Color::BLACK),
                            store: wgpu::StoreOp::Store,
                        },
                    })],
                    depth_stencil_attachment: None,
                    timestamp_writes: None,
                    occlusion_query_set: None,
                    multiview_mask: None,
                })
                .forget_lifetime();
            self.renderer.render(&mut pass, primitives, &screen);
        }
        self.queue
            .submit(commands.into_iter().chain([encoder.finish()]));
        self.window.pre_present_notify();
        self.queue.present(frame);
    }
}
