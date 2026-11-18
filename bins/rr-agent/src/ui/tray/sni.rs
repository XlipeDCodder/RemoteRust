//! The Linux tray: our own StatusNotifierItem (`org.kde.StatusNotifierItem`)
//! and its menu (`com.canonical.dbusmenu`) on the session bus, registered
//! with the StatusNotifierWatcher that the desktop's tray runs (KDE's own,
//! GNOME's AppIndicator extension, most other panels).
//!
//! Any program of this user can call these methods, as with every tray
//! icon; the menu only offers Open, Stop sharing and Quit, none of which
//! grants access.
//!
//! The watcher is followed on the bus: when the panel restarts (or the
//! extension is turned on later), the icon registers again; while there is
//! none, [`Tray::shown`] is false and the window minimizes instead of
//! hiding.

use std::collections::HashMap;
use std::future::poll_fn;
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::Serialize;
use tokio::sync::watch;
use zbus::export::futures_core::Stream;
use zbus::object_server::SignalEmitter;
use zbus::{Connection, ObjectPath, OwnedVariant, Type, Variant};

use super::{OnAction, TrayAction, icon, status_text};

/// Where the item and its menu live (what hosts expect).
const ITEM_PATH: &str = "/StatusNotifierItem";
const MENU_PATH: &str = "/MenuBar";
/// The watcher's well-known name.
const WATCHER: &str = "org.kde.StatusNotifierWatcher";

/// Menu item ids; 0 is the root.
const ROOT: i32 = 0;
const OPEN: i32 = 1;
const STOP: i32 = 2;
const SEPARATOR: i32 = 3;
const QUIT: i32 = 4;
/// The root's children, in order.
const ITEMS: [i32; 4] = [OPEN, STOP, SEPARATOR, QUIT];

/// What the icon and menu show.
#[derive(Debug, Clone, Default)]
struct Status {
    /// The Viewer the screen is shared with.
    viewer: Option<String>,
    /// The menu's layout revision, raised on every change.
    revision: u32,
}

pub struct Tray {
    status: watch::Sender<Status>,
    shown: Arc<AtomicBool>,
}

impl Tray {
    /// Starts the D-Bus side on `runtime`; it ends when this is dropped.
    /// Never fails here: without a session bus or a tray, the icon is just
    /// not shown (logged).
    pub fn new(runtime: &tokio::runtime::Handle, on_action: OnAction) -> anyhow::Result<Self> {
        let (status, watched) = watch::channel(Status {
            viewer: None,
            revision: 1,
        });
        let shown = Arc::new(AtomicBool::new(false));
        let task_shown = Arc::clone(&shown);
        runtime.spawn(async move {
            if let Err(err) = serve(watched, on_action, &task_shown).await {
                task_shown.store(false, Ordering::SeqCst);
                tracing::warn!(error = %err, "no tray icon (D-Bus)");
            }
        });
        Ok(Self { status, shown })
    }

    /// Shows whether, and with whom, the screen is shared.
    pub fn update(&mut self, viewer: Option<&str>) {
        self.status.send_modify(|status| {
            status.viewer = viewer.map(str::to_owned);
            status.revision = status.revision.wrapping_add(1);
        });
    }

    /// Whether a watcher accepted the icon.
    pub fn shown(&self) -> bool {
        self.shown.load(Ordering::SeqCst)
    }
}

/// Serves the item and menu, registers with the watcher (again whenever a
/// new one appears) and announces changes, until the [`Tray`] is dropped.
async fn serve(
    mut status: watch::Receiver<Status>,
    on_action: OnAction,
    shown: &AtomicBool,
) -> zbus::Result<()> {
    let name = format!("org.kde.StatusNotifierItem-{}-1", std::process::id());
    let item = Item {
        status: status.clone(),
        on_action: on_action.clone(),
    };
    let menu = Menu {
        status: status.clone(),
        on_action,
    };
    let conn = zbus::connection::Builder::session()
        .serve_at(ITEM_PATH, item)
        .serve_at(MENU_PATH, menu)
        .name(name.as_str())
        .build()
        .await?;
    // Listen before the first registration, so a watcher starting in
    // between is not missed.
    let bus = zbus::fdo::DBusProxy::new(&conn).await?;
    let mut owners = pin!(
        bus.receive_name_owner_changed_with_args(&[(0, WATCHER)])
            .await?
    );
    let watcher = WatcherProxy::builder(&conn)
        .cache_properties(zbus::proxy::CacheProperties::No)
        .build()
        .await?;
    register(&watcher, &name, shown).await;

    loop {
        tokio::select! {
            changed = status.changed() => {
                if changed.is_err() {
                    // The Tray is gone: dropping the connection removes
                    // the icon.
                    break;
                }
                let now = status.borrow_and_update().clone();
                if let Err(err) = announce(&conn, &now).await {
                    tracing::debug!(error = %err, "cannot announce the tray change");
                }
            }
            signal = next(owners.as_mut()) => {
                let Some(signal) = signal else {
                    break;
                };
                let appeared = signal.args().is_ok_and(|args| args.new_owner().is_some());
                if appeared {
                    register(&watcher, &name, shown).await;
                } else {
                    shown.store(false, Ordering::SeqCst);
                    tracing::info!("the desktop's tray went away");
                }
            }
        }
    }
    Ok(())
}

/// The next item of `stream`.
async fn next<S: Stream>(mut stream: Pin<&mut S>) -> Option<S::Item> {
    poll_fn(|cx| stream.as_mut().poll_next(cx)).await
}

/// Asks the watcher to show the icon.
async fn register(watcher: &WatcherProxy<'_>, name: &str, shown: &AtomicBool) {
    match watcher.register_status_notifier_item(name).await {
        Ok(()) => {
            shown.store(true, Ordering::SeqCst);
            tracing::info!("tray icon shown");
        }
        Err(err) => {
            shown.store(false, Ordering::SeqCst);
            tracing::info!(
                error = %err,
                "no tray to show the icon (on GNOME, the AppIndicator extension adds one)"
            );
        }
    }
}

/// Tells hosts to read the icon, tooltip and menu again.
async fn announce(conn: &Connection, status: &Status) -> zbus::Result<()> {
    let item = conn.object_server().interface::<_, Item>(ITEM_PATH).await?;
    let emitter = item.signal_emitter();
    Item::new_icon(emitter).await?;
    Item::new_tool_tip(emitter).await?;
    // Hosts that cache properties (GDBus proxies) learn of it too.
    {
        let item = item.get().await;
        item.icon_pixmap_changed(emitter).await?;
        item.tool_tip_changed(emitter).await?;
    }
    let menu = SignalEmitter::new(conn, MENU_PATH)?;
    let sharing = status.viewer.is_some();
    let stop = properties(STOP, sharing, &[]).unwrap_or_default();
    Menu::items_properties_updated(&menu, vec![(STOP, stop)], Vec::new()).await?;
    Menu::layout_updated(&menu, status.revision, ROOT).await
}

#[zbus::proxy(
    interface = "org.kde.StatusNotifierWatcher",
    default_service = "org.kde.StatusNotifierWatcher",
    default_path = "/StatusNotifierWatcher"
)]
trait Watcher {
    /// Shows the item owned by `service` (a bus name).
    fn register_status_notifier_item(&self, service: &str) -> zbus::Result<()>;
}

/// An icon: ARGB32 pixels in network byte order (`(iiay)`).
#[derive(Debug, Serialize, Type)]
struct Pixmap {
    width: i32,
    height: i32,
    data: Vec<u8>,
}

/// The icon, from the RGBA drawing.
fn pixmap(sharing: bool) -> Pixmap {
    let rgba = icon::pixels(sharing);
    let (pixels, _) = rgba.as_chunks::<4>();
    let data = pixels
        .iter()
        .flat_map(|&[r, g, b, a]| [a, r, g, b])
        .collect();
    let side = i32::try_from(icon::SIZE).unwrap_or(i32::MAX);
    Pixmap {
        width: side,
        height: side,
        data,
    }
}

/// A tooltip (`(sa(iiay)ss)`): icon name, icon, title, text.
#[derive(Debug, Serialize, Type)]
struct ToolTip {
    icon_name: String,
    icon: Vec<Pixmap>,
    title: String,
    text: String,
}

/// `org.kde.StatusNotifierItem`.
struct Item {
    status: watch::Receiver<Status>,
    on_action: OnAction,
}

impl Item {
    fn sharing(&self) -> bool {
        self.status.borrow().viewer.is_some()
    }
}

#[zbus::interface(name = "org.kde.StatusNotifierItem")]
impl Item {
    /// A click on the icon: show the window.
    fn activate(&self, x: i32, y: i32) {
        let _ = (x, y);
        (self.on_action)(TrayAction::Open);
    }

    /// A middle click: nothing.
    fn secondary_activate(&self, x: i32, y: i32) {
        let _ = (x, y);
    }

    /// Hosts show the menu at [`Item::menu`] themselves.
    fn context_menu(&self, x: i32, y: i32) -> zbus::fdo::Result<()> {
        let _ = (x, y);
        Err(zbus::fdo::Error::NotSupported(
            "the menu is the Menu property".to_owned(),
        ))
    }

    /// Scrolling over the icon: nothing.
    fn scroll(&self, delta: i32, orientation: &str) {
        let _ = (delta, orientation);
    }

    #[zbus(property)]
    fn category(&self) -> String {
        "ApplicationStatus".to_owned()
    }

    #[zbus(property)]
    fn id(&self) -> String {
        "rustremote-agent".to_owned()
    }

    #[zbus(property)]
    fn title(&self) -> String {
        "RustRemote".to_owned()
    }

    #[zbus(property)]
    fn status(&self) -> String {
        "Active".to_owned()
    }

    #[zbus(property)]
    fn window_id(&self) -> i32 {
        0
    }

    #[zbus(property)]
    fn icon_theme_path(&self) -> String {
        String::new()
    }

    #[zbus(property)]
    fn icon_name(&self) -> String {
        String::new()
    }

    #[zbus(property)]
    fn icon_pixmap(&self) -> Vec<Pixmap> {
        vec![pixmap(self.sharing())]
    }

    #[zbus(property)]
    fn overlay_icon_name(&self) -> String {
        String::new()
    }

    #[zbus(property)]
    fn overlay_icon_pixmap(&self) -> Vec<Pixmap> {
        Vec::new()
    }

    #[zbus(property)]
    fn attention_icon_name(&self) -> String {
        String::new()
    }

    #[zbus(property)]
    fn attention_icon_pixmap(&self) -> Vec<Pixmap> {
        Vec::new()
    }

    #[zbus(property)]
    fn attention_movie_name(&self) -> String {
        String::new()
    }

    #[zbus(property)]
    fn tool_tip(&self) -> ToolTip {
        ToolTip {
            icon_name: String::new(),
            icon: Vec::new(),
            title: "RustRemote".to_owned(),
            text: status_text(self.status.borrow().viewer.as_deref()),
        }
    }

    /// Clicks show the window; the menu is separate.
    #[zbus(property)]
    fn item_is_menu(&self) -> bool {
        false
    }

    #[zbus(property)]
    fn menu(&self) -> ObjectPath<'static> {
        ObjectPath::from_static_str_unchecked(MENU_PATH)
    }

    #[zbus(signal)]
    async fn new_icon(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn new_tool_tip(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;
}

/// A menu item's properties (`a{sv}`).
type Props = HashMap<&'static str, Variant<'static>>;

/// A menu (sub)tree (`(ia{sv}av)`): id, properties, children (each a
/// variant holding the same structure).
type Layout = (i32, Props, Vec<Variant<'static>>);

/// Item `id`'s properties, or `None` for an unknown id. With `names`
/// non-empty, only those.
fn properties(id: i32, sharing: bool, names: &[String]) -> Option<Props> {
    let all: Vec<(&'static str, Variant<'static>)> = match id {
        ROOT => vec![("children-display", "submenu".into())],
        OPEN => vec![("label", "Open RustRemote".into())],
        STOP => vec![
            ("label", "Stop sharing".into()),
            ("enabled", sharing.into()),
        ],
        SEPARATOR => vec![("type", "separator".into())],
        QUIT => vec![("label", "Quit RustRemote".into())],
        _ => return None,
    };
    Some(
        all.into_iter()
            .filter(|(name, _)| names.is_empty() || names.iter().any(|wanted| wanted == name))
            .collect(),
    )
}

/// The tree under `parent` (only the root has children); `depth` 0 leaves
/// them out, as dbusmenu asks.
fn layout(parent: i32, depth: i32, sharing: bool, names: &[String]) -> Option<Layout> {
    let props = properties(parent, sharing, names)?;
    let children = if parent == ROOT && depth != 0 {
        ITEMS
            .iter()
            .filter_map(|&id| {
                let props = properties(id, sharing, names)?;
                Some(Variant::from((id, props, Vec::<Variant<'static>>::new())))
            })
            .collect()
    } else {
        Vec::new()
    };
    Some((parent, props, children))
}

/// What clicking item `id` asks for (Stop sharing only while sharing).
fn action(id: i32, sharing: bool) -> Option<TrayAction> {
    match id {
        OPEN => Some(TrayAction::Open),
        STOP if sharing => Some(TrayAction::Stop),
        QUIT => Some(TrayAction::Quit),
        _ => None,
    }
}

fn unknown(id: i32) -> zbus::fdo::Error {
    zbus::fdo::Error::InvalidArgs(format!("no menu item {id}"))
}

/// `com.canonical.dbusmenu`.
struct Menu {
    status: watch::Receiver<Status>,
    on_action: OnAction,
}

impl Menu {
    fn sharing(&self) -> bool {
        self.status.borrow().viewer.is_some()
    }

    /// Runs a "clicked" event; `false` for an unknown id.
    fn event_for(&self, id: i32, event: &str) -> bool {
        if properties(id, false, &[]).is_none() {
            return false;
        }
        if event == "clicked"
            && let Some(action) = action(id, self.sharing())
        {
            (self.on_action)(action);
        }
        true
    }
}

#[zbus::interface(name = "com.canonical.dbusmenu")]
impl Menu {
    #[zbus(out_args("revision", "layout"))]
    fn get_layout(
        &self,
        parent_id: i32,
        recursion_depth: i32,
        property_names: Vec<String>,
    ) -> zbus::fdo::Result<(u32, Layout)> {
        let status = self.status.borrow();
        let layout = layout(
            parent_id,
            recursion_depth,
            status.viewer.is_some(),
            &property_names,
        )
        .ok_or_else(|| unknown(parent_id))?;
        Ok((status.revision, layout))
    }

    /// With no ids, every item.
    fn get_group_properties(
        &self,
        ids: Vec<i32>,
        property_names: Vec<String>,
    ) -> Vec<(i32, Props)> {
        let sharing = self.sharing();
        let ids = if ids.is_empty() { ITEMS.to_vec() } else { ids };
        ids.into_iter()
            .filter_map(|id| Some((id, properties(id, sharing, &property_names)?)))
            .collect()
    }

    fn get_property(&self, id: i32, name: String) -> zbus::fdo::Result<Variant<'static>> {
        let props = properties(id, self.sharing(), &[]).ok_or_else(|| unknown(id))?;
        props
            .get(name.as_str())
            .cloned()
            .ok_or_else(|| zbus::fdo::Error::InvalidArgs(format!("no property {name:?}")))
    }

    fn event(
        &self,
        id: i32,
        event_id: &str,
        data: OwnedVariant,
        timestamp: u32,
    ) -> zbus::fdo::Result<()> {
        let _ = (data, timestamp);
        if self.event_for(id, event_id) {
            Ok(())
        } else {
            Err(unknown(id))
        }
    }

    /// Returns the unknown ids; fails when none is known.
    fn event_group(
        &self,
        events: Vec<(i32, String, OwnedVariant, u32)>,
    ) -> zbus::fdo::Result<Vec<i32>> {
        let count = events.len();
        let errors: Vec<i32> = events
            .into_iter()
            .filter(|(id, event, _, _)| !self.event_for(*id, event))
            .map(|(id, ..)| id)
            .collect();
        if count > 0 && errors.len() == count {
            Err(zbus::fdo::Error::InvalidArgs(
                "none of the menu items exists".to_owned(),
            ))
        } else {
            Ok(errors)
        }
    }

    /// The menu never changes on opening.
    fn about_to_show(&self, id: i32) -> zbus::fdo::Result<bool> {
        properties(id, false, &[])
            .map(|_| false)
            .ok_or_else(|| unknown(id))
    }

    #[zbus(out_args("updates_needed", "id_errors"))]
    fn about_to_show_group(&self, ids: Vec<i32>) -> (Vec<i32>, Vec<i32>) {
        let errors = ids
            .into_iter()
            .filter(|&id| properties(id, false, &[]).is_none())
            .collect();
        (Vec::new(), errors)
    }

    #[zbus(property)]
    fn version(&self) -> u32 {
        3
    }

    #[zbus(property)]
    fn text_direction(&self) -> String {
        "ltr".to_owned()
    }

    #[zbus(property)]
    fn status(&self) -> String {
        "normal".to_owned()
    }

    #[zbus(property)]
    fn icon_theme_path(&self) -> Vec<String> {
        Vec::new()
    }

    #[zbus(signal)]
    async fn layout_updated(
        emitter: &SignalEmitter<'_>,
        revision: u32,
        parent: i32,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn items_properties_updated(
        emitter: &SignalEmitter<'_>,
        updated_props: Vec<(i32, Props)>,
        removed_props: Vec<(i32, Vec<String>)>,
    ) -> zbus::Result<()>;
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::time::Duration;

    use zbus::OwnedObjectPath;

    use super::*;

    fn label(props: &Props) -> Option<&str> {
        match props.get("label") {
            Some(Variant::Str(label)) => Some(label.as_str()),
            _ => None,
        }
    }

    #[test]
    fn the_menu_lists_its_items_in_order() {
        let (id, root, children) = layout(ROOT, -1, false, &[]).unwrap();
        assert_eq!(id, ROOT);
        assert!(root.contains_key("children-display"));
        let ids: Vec<i32> = children
            .iter()
            .map(|child| match child {
                Variant::Structure(item) => match item.fields().first() {
                    Some(Variant::I32(id)) => *id,
                    other => panic!("unexpected id {other:?}"),
                },
                other => panic!("unexpected child {other:?}"),
            })
            .collect();
        assert_eq!(ids, ITEMS);
        assert_eq!(
            label(&properties(QUIT, false, &[]).unwrap()),
            Some("Quit RustRemote")
        );
    }

    #[test]
    fn depth_zero_and_items_have_no_children() {
        assert!(layout(ROOT, 0, true, &[]).unwrap().2.is_empty());
        assert!(layout(STOP, -1, true, &[]).unwrap().2.is_empty());
    }

    #[test]
    fn stop_sharing_works_only_while_sharing() {
        let idle = properties(STOP, false, &[]).unwrap();
        assert!(matches!(idle.get("enabled"), Some(Variant::Bool(false))));
        let sharing = properties(STOP, true, &[]).unwrap();
        assert!(matches!(sharing.get("enabled"), Some(Variant::Bool(true))));
        assert_eq!(action(STOP, false), None);
        assert_eq!(action(STOP, true), Some(TrayAction::Stop));
        assert_eq!(action(OPEN, false), Some(TrayAction::Open));
        assert_eq!(action(QUIT, true), Some(TrayAction::Quit));
        assert_eq!(action(SEPARATOR, true), None);
    }

    #[test]
    fn property_names_filter_and_unknown_ids_are_refused() {
        let only = properties(STOP, true, &["label".to_owned()]).unwrap();
        assert_eq!(only.len(), 1);
        assert_eq!(label(&only), Some("Stop sharing"));
        assert!(properties(99, true, &[]).is_none());
        assert!(layout(99, -1, true, &[]).is_none());
    }

    #[test]
    fn the_icon_is_argb_in_network_order() {
        let icon = pixmap(true);
        assert_eq!((icon.width, icon.height), (32, 32));
        assert_eq!(icon.data.len(), 32 * 32 * 4);
        // A corner is transparent; the frame (x = 2, y = 4) is opaque red.
        assert_eq!(icon.data.get(..4), Some(&[0, 0, 0, 0][..]));
        let at = (4 * 32 + 2) * 4;
        assert_eq!(
            icon.data.get(at..at + 4),
            Some(&[0xFF, 0xE5, 0x39, 0x35][..])
        );
    }

    /// Stands in for the desktop's watcher.
    struct FakeWatcher(tokio::sync::mpsc::UnboundedSender<String>);

    #[zbus::interface(name = "org.kde.StatusNotifierWatcher")]
    impl FakeWatcher {
        fn register_status_notifier_item(&self, service: String) {
            let _ = self.0.send(service);
        }
    }

    async fn start_watcher() -> (Connection, tokio::sync::mpsc::UnboundedReceiver<String>) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let conn = zbus::connection::Builder::session()
            .serve_at("/StatusNotifierWatcher", FakeWatcher(tx))
            .name(WATCHER)
            .build()
            .await
            .unwrap();
        (conn, rx)
    }

    async fn wait_until(what: &str, done: impl Fn() -> bool) {
        for _ in 0..100 {
            if done() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("timed out waiting until {what}");
    }

    #[zbus::proxy(interface = "org.kde.StatusNotifierItem", assume_defaults = true)]
    trait ItemClient {
        fn activate(&self, x: i32, y: i32) -> zbus::Result<()>;
        #[zbus(property)]
        fn icon_pixmap(&self) -> zbus::Result<Vec<(i32, i32, Vec<u8>)>>;
        #[zbus(property)]
        fn tool_tip(&self) -> zbus::Result<(String, Vec<(i32, i32, Vec<u8>)>, String, String)>;
        #[zbus(property)]
        fn menu(&self) -> zbus::Result<OwnedObjectPath>;
    }

    #[zbus::proxy(interface = "com.canonical.dbusmenu", assume_defaults = true)]
    trait MenuClient {
        fn get_layout(
            &self,
            parent_id: i32,
            recursion_depth: i32,
            property_names: &[&str],
        ) -> zbus::Result<(u32, (i32, HashMap<String, OwnedVariant>, Vec<OwnedVariant>))>;
        fn get_property(&self, id: i32, name: &str) -> zbus::Result<OwnedVariant>;
        fn event(
            &self,
            id: i32,
            event_id: &str,
            data: &Variant<'_>,
            timestamp: u32,
        ) -> zbus::Result<()>;
    }

    /// The tray against a stand-in watcher on a real session bus, as a
    /// host would use it. Run with `dbus-run-session -- cargo test ...`.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs a session bus (dbus-run-session)"]
    async fn registers_and_answers_on_the_session_bus() {
        let (watcher, mut registered) = start_watcher().await;
        let (actions_tx, actions) = mpsc::channel();
        let on_action: OnAction = Arc::new(move |action| {
            let _ = actions_tx.send(action);
        });
        let mut tray = Tray::new(&tokio::runtime::Handle::current(), on_action).unwrap();
        let service = tokio::time::timeout(Duration::from_secs(5), registered.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(
            service.starts_with("org.kde.StatusNotifierItem-"),
            "{service}"
        );
        wait_until("the icon is shown", || tray.shown()).await;

        let client = Connection::session().await.unwrap();
        // The wire types the specifications ask for; hosts ignore an item
        // whose types differ.
        for (path, types) in [
            (
                ITEM_PATH,
                &[
                    r#"name="IconPixmap" type="a(iiay)""#,
                    r#"name="ToolTip" type="(sa(iiay)ss)""#,
                    r#"name="Menu" type="o""#,
                    r#"name="WindowId" type="i""#,
                    r#"name="ItemIsMenu" type="b""#,
                ][..],
            ),
            (
                MENU_PATH,
                &[
                    r#"name="layout" type="(ia{sv}av)""#,
                    r#"type="a(ia{sv})""#,
                    r#"name="data" type="v""#,
                    r#"name="Version" type="u""#,
                ][..],
            ),
        ] {
            let xml = zbus::fdo::IntrospectableProxy::builder(&client)
                .destination(service.as_str())
                .path(path)
                .build()
                .await
                .unwrap()
                .introspect()
                .await
                .unwrap();
            for wanted in types {
                assert!(xml.contains(wanted), "{wanted} missing at {path}:\n{xml}");
            }
        }
        // Reads every property afresh; PropertiesChanged is checked below.
        let item = ItemClientProxy::builder(&client)
            .destination(service.as_str())
            .path(ITEM_PATH)
            .cache_properties(zbus::proxy::CacheProperties::No)
            .build()
            .await
            .unwrap();
        let icons = item.icon_pixmap().await.unwrap();
        assert_eq!(icons.len(), 1);
        assert_eq!((icons[0].0, icons[0].1, icons[0].2.len()), (32, 32, 4096));
        assert_eq!(item.menu().await.unwrap().as_str(), MENU_PATH);
        assert_eq!(item.tool_tip().await.unwrap().3, "Not sharing");
        item.activate(0, 0).await.unwrap();
        assert_eq!(
            actions.recv_timeout(Duration::from_secs(1)),
            Ok(TrayAction::Open)
        );

        let menu = MenuClientProxy::builder(&client)
            .destination(service.as_str())
            .path(MENU_PATH)
            .build()
            .await
            .unwrap();
        let (revision, (root, _, children)) = menu.get_layout(ROOT, -1, &[]).await.unwrap();
        assert_eq!((root, children.len()), (ROOT, 4));
        // Stop sharing does nothing while idle.
        let nothing = Variant::from(0_i32);
        menu.event(STOP, "clicked", &nothing, 0).await.unwrap();
        assert!(menu.event(99, "clicked", &nothing, 0).await.is_err());

        // Sharing: hosts that cache properties get the new values.
        let properties = zbus::fdo::PropertiesProxy::builder(&client)
            .destination(service.as_str())
            .path(ITEM_PATH)
            .build()
            .await
            .unwrap();
        let mut changes = pin!(properties.receive_properties_changed().await.unwrap());
        tray.update(Some("office-pc"));
        let change = tokio::time::timeout(Duration::from_secs(5), next(changes.as_mut()))
            .await
            .unwrap()
            .unwrap();
        let args = change.args().unwrap();
        assert_eq!(args.interface_name().as_str(), "org.kde.StatusNotifierItem");
        assert!(
            args.changed_properties()
                .keys()
                .any(|name| *name == "IconPixmap" || *name == "ToolTip")
        );
        let enabled = menu.get_property(STOP, "enabled").await.unwrap();
        assert!(matches!(bool::try_from(enabled), Ok(true)));
        assert!(menu.get_layout(ROOT, -1, &[]).await.unwrap().0 > revision);
        assert!(item.tool_tip().await.unwrap().3.contains("\"office-pc\""));
        menu.event(STOP, "clicked", &nothing, 0).await.unwrap();
        // The idle click above sent nothing: Stop is the next action.
        assert_eq!(
            actions.recv_timeout(Duration::from_secs(1)),
            Ok(TrayAction::Stop)
        );
        menu.event(QUIT, "clicked", &nothing, 0).await.unwrap();
        assert_eq!(
            actions.recv_timeout(Duration::from_secs(1)),
            Ok(TrayAction::Quit)
        );

        // The panel restarts: the icon registers with the new watcher.
        watcher.close().await.unwrap();
        wait_until("the icon is hidden", || !tray.shown()).await;
        let (_watcher, mut registered) = start_watcher().await;
        let again = tokio::time::timeout(Duration::from_secs(5), registered.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(again, service);
        wait_until("the icon is shown again", || tray.shown()).await;
    }
}
