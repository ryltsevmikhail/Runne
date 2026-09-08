mod helper { pub struct HiddenPending; impl HiddenPending { pub fn capture_current() -> Self { Self } } }
use helper::HiddenPending;
fn production() { let _ = HiddenPending::capture_current(); }
