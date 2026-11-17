//! Screen capture smoke tests. They need an interactive desktop session,
//! so they are ignored by default (CI runners have none). Run them one at
//! a time (one duplication per output per process):
//!
//! ```sh
//! cargo test -p rr-platform --test capture -- --ignored --nocapture --test-threads=1
//! ```

use std::time::{Duration, Instant};

use rr_platform::capture;

/// Captures until a frame arrives or `limit` passes.
fn first_frame(
    capturer: &mut dyn capture::ScreenCapturer,
    limit: Duration,
) -> Option<(u32, u32, usize)> {
    let started = Instant::now();
    let mut seen = None;
    while seen.is_none() && started.elapsed() < limit {
        capturer
            .capture(Duration::from_millis(100), &mut |frame| {
                let row = frame.width as usize * 4;
                assert!(frame.stride >= row);
                assert!(frame.bgra.len() >= frame.stride * frame.height as usize);
                // Alpha is undefined: only color bytes count.
                let lit = frame
                    .bgra
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .filter(|pixel| pixel[..3] != [0, 0, 0])
                    .count();
                seen = Some((frame.width, frame.height, lit));
            })
            .unwrap();
    }
    println!("  first frame after {:?}: {seen:?}", started.elapsed());
    seen
}

#[test]
#[ignore = "needs an interactive desktop"]
fn lists_monitors_and_captures_each() {
    let _ = capture::set_dpi_aware();
    let monitors = capture::monitors().unwrap();
    assert!(!monitors.is_empty());
    assert_eq!(monitors.iter().filter(|monitor| monitor.primary).count(), 1);
    for monitor in &monitors {
        println!("{monitor:?}");
        let mut capturer = capture::open(monitor.id).unwrap();
        // DWM presents shortly after a duplication starts.
        let (width, height, lit) =
            first_frame(capturer.as_mut(), Duration::from_secs(3)).expect("no frame in 3 s");
        assert_eq!((width, height), (monitor.width, monitor.height));
        assert!(lit > 0, "the first frame is all black");
    }
}

#[test]
#[ignore = "needs an interactive desktop"]
fn static_screen_produces_few_frames() {
    let mut capturer = capture::open(0).unwrap();
    let _ = first_frame(capturer.as_mut(), Duration::from_secs(3));
    let mut frames = 0u32;
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(1) {
        let _ = capturer
            .capture(Duration::from_millis(100), &mut |_| frames += 1)
            .unwrap();
    }
    // Only real screen changes count (a terminal printing test output is
    // one); an idle desktop yields none.
    println!("frames in 1 s: {frames}");
    assert!(frames < 30);
}

#[test]
fn unknown_monitor_is_reported() {
    if let Ok(monitors) = capture::monitors() {
        let missing = u8::try_from(monitors.len()).unwrap();
        assert!(matches!(
            capture::open(missing),
            Err(capture::CaptureError::NoSuchMonitor(_) | capture::CaptureError::Unsupported(_))
        ));
    }
}
