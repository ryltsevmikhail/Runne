// Shell completion script generation

#[path = "completion/bash.rs"]
pub mod bash;
#[path = "completion/fish.rs"]
pub mod fish;
#[path = "completion/powershell.rs"]
pub mod powershell;
#[path = "completion/zsh.rs"]
pub mod zsh;

/// Supported shell types for completion generation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
    PowerShell,
}

impl Shell {
    /// Parse shell name from string
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "bash" => Some(Self::Bash),
            "zsh" => Some(Self::Zsh),
            "fish" => Some(Self::Fish),
            "powershell" | "pwsh" => Some(Self::PowerShell),
            _ => None,
        }
    }

    /// Get shell name as string
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Bash => "bash",
            Self::Zsh => "zsh",
            Self::Fish => "fish",
            Self::PowerShell => "powershell",
        }
    }
}

/// Generate completion script for the specified shell
#[must_use]
pub fn generate_completion(shell: Shell) -> String {
    match shell {
        Shell::Bash => bash::generate(),
        Shell::Zsh => zsh::generate(),
        Shell::Fish => fish::generate(),
        Shell::PowerShell => powershell::generate(),
    }
}
