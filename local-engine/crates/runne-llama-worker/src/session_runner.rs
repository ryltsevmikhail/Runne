//! Convenience entrypoint for one worker session.

use crate::engine::EngineBackend;
use crate::session::{WorkerIdentity, WorkerSessionLoop};
use runne_inference_protocol::{ProtocolError, Session, WorkerFrameV1, WorkerWire};

/// Runs one worker session to completion.
pub fn serve<W: WorkerWire, E: EngineBackend>(
    wire: &mut W,
    session: &mut Session<WorkerFrameV1>,
    identity: WorkerIdentity,
    engine: &mut E,
) -> Result<(), ProtocolError> {
    WorkerSessionLoop::new(wire, identity, engine).run(session)
}
