//! Screen sessions on the Agent: the consent request handed to the local
//! user, and the running session handed to the media pipeline
//! (blueprint v2 §6.5, §7.3).
//!
//! The control loop that drives these lives in [`crate::agent`]; this
//! module only defines the hand-off types.

use std::fmt;
use std::time::Duration;

use rr_proto::{DesktopState, DevicePublicKey, DisconnectReason, MonitorInfo, Permissions};
use tokio::sync::{mpsc, oneshot};

use crate::SessionError;
use crate::cursor::CursorSender;
use crate::identity::Fingerprint;
use crate::input::InputReceiver;
use crate::video::VideoSender;

/// How long the local user has to answer the consent prompt before it is
/// denied automatically (blueprint v2 §7.3).
pub const CONSENT_TIMEOUT: Duration = Duration::from_secs(30);

/// A paired Viewer asks to see this screen. Answer with
/// [`SessionRequest::accept`] or [`SessionRequest::deny`]. Dropping it
/// denies, and the Agent denies by itself after the consent timeout.
pub struct SessionRequest {
    pub(crate) viewer_name: String,
    pub(crate) viewer_key: DevicePublicKey,
    pub(crate) permissions: Permissions,
    pub(crate) reply: oneshot::Sender<Answer>,
}

/// The local user's answer, as passed to the control loop.
pub(crate) enum Answer {
    Accept {
        grant: Grant,
        session: oneshot::Sender<Result<AgentSession, SessionError>>,
    },
    Deny,
}

/// What the local user accepted.
#[derive(Debug, Clone)]
pub struct Grant {
    /// Permissions granted; intersected with the requested ones.
    pub permissions: Permissions,
    /// The Agent's monitors.
    pub monitors: Vec<MonitorInfo>,
    /// The monitor that will be streamed.
    pub monitor: u8,
    /// Encoder name shown on the Viewer.
    pub encoder: String,
}

impl SessionRequest {
    /// The Viewer's name (sanitized).
    #[must_use]
    pub fn viewer_name(&self) -> &str {
        &self.viewer_name
    }

    /// The Viewer's pinned key.
    #[must_use]
    pub const fn viewer_key(&self) -> DevicePublicKey {
        self.viewer_key
    }

    /// The Viewer's fingerprint, for the prompt.
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of(&self.viewer_key)
    }

    /// What the Viewer asks for.
    #[must_use]
    pub const fn permissions(&self) -> Permissions {
        self.permissions
    }

    /// Whether the request is gone (the Viewer left, or the consent
    /// timeout expired). A prompt should close when this resolves.
    pub async fn withdrawn(&mut self) {
        self.reply.closed().await;
    }

    /// Whether the request is gone already (see
    /// [`SessionRequest::withdrawn`]), for prompts that poll.
    #[must_use]
    pub fn is_withdrawn(&self) -> bool {
        self.reply.is_closed()
    }

    /// Accepts: the Agent sends `SessionStart`, opens the video stream and
    /// returns the running session.
    ///
    /// # Errors
    /// [`SessionError::Refused`] if the request was withdrawn meanwhile or
    /// `grant` allows nothing that was requested; stream errors.
    pub async fn accept(self, grant: Grant) -> Result<AgentSession, SessionError> {
        let (tx, rx) = oneshot::channel();
        self.reply
            .send(Answer::Accept { grant, session: tx })
            .map_err(|_| SessionError::Refused(DisconnectReason::ConsentTimeout))?;
        rx.await
            .map_err(|_| SessionError::Refused(DisconnectReason::ConsentTimeout))?
    }

    /// Denies the request; the Viewer is told so and disconnected.
    pub fn deny(self) {
        let _ = self.reply.send(Answer::Deny);
    }
}

impl fmt::Debug for SessionRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionRequest")
            .field("viewer_name", &self.viewer_name)
            .field("viewer_key", &self.viewer_key)
            .field("permissions", &self.permissions)
            .finish_non_exhaustive()
    }
}

/// Something the Viewer did during a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEvent {
    /// The Viewer cannot decode: the next frame must be a keyframe.
    KeyframeRequested,
}

/// A request from the media side to the control loop.
#[derive(Debug)]
pub(crate) enum Command {
    Encoder(String),
    Desktop(DesktopState),
    End(DisconnectReason),
}

/// A running screen session on the Agent.
#[derive(Debug)]
pub struct AgentSession {
    /// Where encoded frames go.
    pub video: VideoSender,
    pub(crate) cursor: Option<CursorSender>,
    pub(crate) input: Option<InputReceiver>,
    pub(crate) events: mpsc::Receiver<SessionEvent>,
    pub(crate) handle: SessionHandle,
    pub(crate) permissions: Permissions,
    pub(crate) viewer_name: String,
}

impl AgentSession {
    /// The next Viewer event, or `None` once the session is over.
    pub async fn next_event(&mut self) -> Option<SessionEvent> {
        self.events.recv().await
    }

    /// The Viewer's keyboard and mouse: `Some` (once) when `CONTROL` was
    /// granted. Its first `recv` waits until the Viewer opens the stream.
    pub fn take_input(&mut self) -> Option<InputReceiver> {
        self.input.take()
    }

    /// Where pointer updates go: `Some` once, so a separate task can own
    /// it. The stream opens with the first update.
    pub fn take_cursor(&mut self) -> Option<CursorSender> {
        self.cursor.take()
    }

    /// A handle that can end the session or update it from elsewhere.
    #[must_use]
    pub fn handle(&self) -> SessionHandle {
        self.handle.clone()
    }

    /// Granted permissions.
    #[must_use]
    pub const fn permissions(&self) -> Permissions {
        self.permissions
    }

    /// The Viewer's name (sanitized).
    #[must_use]
    pub fn viewer_name(&self) -> &str {
        &self.viewer_name
    }
}

/// Cheap, cloneable control over a running session. The session ends when
/// [`SessionHandle::end`] is called or when every handle (including the one
/// inside [`AgentSession`]) is dropped.
#[derive(Debug, Clone)]
pub struct SessionHandle {
    pub(crate) commands: mpsc::Sender<Command>,
}

impl SessionHandle {
    /// Tells the Viewer which encoder is now in use.
    pub fn set_encoder(&self, name: &str) {
        let _ = self.commands.try_send(Command::Encoder(name.to_owned()));
    }

    /// Tells the Viewer that the secure desktop appeared or went away
    /// (blueprint v2 §7.3).
    pub fn set_desktop_state(&self, state: DesktopState) {
        let _ = self.commands.try_send(Command::Desktop(state));
    }

    /// Ends the session, telling the Viewer why.
    pub fn end(&self, reason: DisconnectReason) {
        let _ = self.commands.try_send(Command::End(reason));
    }

    /// Whether the session is over.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.commands.is_closed()
    }
}
