#[cfg(target_os = "linux")]
mod unix;

#[cfg(target_os = "linux")]
pub use unix::LinuxPinentryPrompt;

#[cfg(test)]
mod tests;
