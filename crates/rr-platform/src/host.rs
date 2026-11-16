//! Basic facts about the local machine.

/// The machine's host name, if the OS reports one.
///
/// - Windows: the `COMPUTERNAME` environment variable.
/// - Linux: `/proc/sys/kernel/hostname`, falling back to `/etc/hostname`.
#[must_use]
pub fn hostname() -> Option<String> {
    let raw = os_hostname()?;
    let trimmed = raw.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

#[cfg(windows)]
fn os_hostname() -> Option<String> {
    std::env::var("COMPUTERNAME").ok()
}

#[cfg(target_os = "linux")]
fn os_hostname() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .or_else(|_| std::fs::read_to_string("/etc/hostname"))
        .ok()
}
