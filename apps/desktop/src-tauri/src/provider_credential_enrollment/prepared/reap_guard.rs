pub(super) trait ExactWriterReap {
    type Error;

    fn reap_exact(self) -> Result<(), Self::Error>;
}

pub(super) struct RetainedWriterCleanup<H: ExactWriterReap, S: FnMut()> {
    handoff: Option<H>,
    stop: S,
    armed: bool,
}

impl<H: ExactWriterReap, S: FnMut()> RetainedWriterCleanup<H, S> {
    pub(super) const fn new(handoff: H, stop: S) -> Self {
        Self {
            handoff: Some(handoff),
            stop,
            armed: true,
        }
    }

    pub(super) const fn handoff_mut(&mut self) -> Option<&mut H> {
        self.handoff.as_mut()
    }

    pub(super) fn finish(mut self) -> Result<(), H::Error> {
        self.armed = false;
        self.handoff.take().expect("retained handoff").reap_exact()
    }

    pub(super) fn abort(mut self) -> Result<(), H::Error> {
        (self.stop)();
        self.armed = false;
        self.handoff.take().expect("retained handoff").reap_exact()
    }
}

impl<H: ExactWriterReap, S: FnMut()> Drop for RetainedWriterCleanup<H, S> {
    fn drop(&mut self) {
        if self.armed {
            (self.stop)();
            if let Some(handoff) = self.handoff.take() {
                let _ = handoff.reap_exact();
            }
        }
    }
}

impl ExactWriterReap for runne_platform_desktop::CredentialWriterHandoff {
    type Error = runne_platform_desktop::ProtectedBundledRuntimeError;

    fn reap_exact(self) -> Result<(), Self::Error> {
        self.reap_exact_writer()
    }
}
