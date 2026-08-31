#[cfg_attr(not(any(test, target_os = "linux")), allow(dead_code))]
mod pinentry_protocol;

#[cfg(target_os = "linux")]
mod unix;

#[cfg(target_os = "linux")]
pub use unix::LinuxPinentryPrompt;

#[cfg(test)]
mod tests;
