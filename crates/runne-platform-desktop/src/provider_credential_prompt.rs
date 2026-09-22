#[cfg_attr(not(any(test, target_os = "linux")), allow(dead_code))]
mod pinentry_protocol;

#[cfg(target_os = "linux")]
mod linux_gui;

#[cfg(target_os = "linux")]
pub use linux_gui::LinuxGuiHostCredentialPrompt;

#[cfg(test)]
mod tests;
