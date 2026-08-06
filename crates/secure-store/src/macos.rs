// macOS Keychain operations stay in a private include part so this platform
// selector remains small and the crash-safe credential lifecycle is audited in
// its dedicated implementation unit.
include!("macos/implementation.inc");
