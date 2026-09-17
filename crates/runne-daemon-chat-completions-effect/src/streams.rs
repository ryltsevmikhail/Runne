use runne_provider::{
    DispatchError, ProviderStreamEvent, ProviderStreamEventKind, ProviderStreamId,
    ProviderStreamItem, StreamCursor, StreamError,
};
use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;

const MAX_STREAMS: usize = 64;
// Keep this equal to the shared decoder's event bound. The response body and
// each normalized frame remain bounded independently by the profile.
const MAX_EVENTS_PER_STREAM: usize = 16_384;

/// Bounded in-memory stream handoff between the effect and runtime poller.
pub struct StreamStore {
    streams: Mutex<BTreeMap<ProviderStreamId, VecDeque<ProviderStreamEvent>>>,
}

impl StreamStore {
    pub(crate) const fn new() -> Self {
        Self {
            streams: Mutex::new(BTreeMap::new()),
        }
    }

    pub(crate) fn reserve(&self, stream: ProviderStreamId) -> Result<(), DispatchError> {
        let mut streams = self
            .streams
            .lock()
            .map_err(|_| DispatchError::MaybeDispatched)?;
        if streams.contains_key(&stream) {
            return Err(DispatchError::AttemptConflict);
        }
        if streams.len() >= MAX_STREAMS {
            return Err(DispatchError::RejectedBeforeEffect(
                runne_provider::ProviderPreEffectRejection::AdapterRejected,
            ));
        }
        streams.insert(stream, VecDeque::new());
        drop(streams);
        Ok(())
    }

    pub(crate) fn publish(
        &self,
        stream: ProviderStreamId,
        events: Vec<ProviderStreamEvent>,
    ) -> Result<(), DispatchError> {
        if events.len() > MAX_EVENTS_PER_STREAM {
            self.remove(stream);
            return Err(DispatchError::MaybeDispatched);
        }
        let mut streams = self
            .streams
            .lock()
            .map_err(|_| DispatchError::MaybeDispatched)?;
        let queue = streams
            .get_mut(&stream)
            .ok_or(DispatchError::StreamNotFound)?;
        queue.extend(events);
        drop(streams);
        Ok(())
    }

    pub(crate) fn remove(&self, stream: ProviderStreamId) {
        if let Ok(mut streams) = self.streams.lock() {
            streams.remove(&stream);
        }
    }

    pub(crate) fn next(
        &self,
        stream: ProviderStreamId,
        cursor: StreamCursor,
    ) -> Result<ProviderStreamItem, StreamError> {
        let (item, remove_after) = {
            let mut streams = self.streams.lock().map_err(|_| StreamError::NotFound)?;
            let events = streams.get_mut(&stream).ok_or(StreamError::NotFound)?;
            let next = events.front().ok_or(StreamError::Closed)?;
            if next.sequence() != cursor.sequence() {
                return Err(StreamError::SequenceGap {
                    expected: cursor.sequence(),
                    actual: next.sequence(),
                });
            }
            let event = events.pop_front().expect("front event exists");
            let remove_after = matches!(
                event.kind(),
                ProviderStreamEventKind::Finished { .. }
                    | ProviderStreamEventKind::ScannerCompleted { .. }
            );
            drop(streams);
            (ProviderStreamItem::from_event(event)?, remove_after)
        };
        if remove_after {
            self.remove(stream);
        }
        Ok(item)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use runne_provider::{ProviderFinishReason, ProviderTerminalDisposition};

    fn event(sequence: u64, kind: ProviderStreamEventKind) -> ProviderStreamEvent {
        ProviderStreamEvent::new(sequence, kind).expect("valid event")
    }

    #[test]
    fn wrong_cursor_retains_event_and_terminal_poll_removes_stream() {
        let store = StreamStore::new();
        let stream = ProviderStreamId::from_bytes([7; 16]);
        store.reserve(stream).unwrap();
        store
            .publish(
                stream,
                vec![
                    event(0, ProviderStreamEventKind::Started),
                    event(
                        1,
                        ProviderStreamEventKind::Finished {
                            disposition: ProviderTerminalDisposition::RemoteIncomplete,
                            reason: ProviderFinishReason::Stop,
                        },
                    ),
                ],
            )
            .unwrap();
        assert!(matches!(
            store.next(stream, StreamCursor::new(9)),
            Err(StreamError::SequenceGap { .. })
        ));
        assert!(store.next(stream, StreamCursor::new(0)).is_ok());
        assert!(store.next(stream, StreamCursor::new(1)).is_ok());
        assert_eq!(
            store.next(stream, StreamCursor::new(2)),
            Err(StreamError::NotFound)
        );
    }

    #[test]
    fn reservation_is_bounded_and_duplicate_safe() {
        let store = StreamStore::new();
        for value in 0..MAX_STREAMS {
            store
                .reserve(ProviderStreamId::from_bytes((value as u128).to_be_bytes()))
                .unwrap();
        }
        assert!(matches!(
            store.reserve(ProviderStreamId::from_bytes([99; 16])),
            Err(DispatchError::RejectedBeforeEffect(_))
        ));
        assert_eq!(
            store.reserve(ProviderStreamId::from_bytes([0; 16])),
            Err(DispatchError::AttemptConflict)
        );
    }

    #[test]
    fn accepts_more_than_two_thousand_small_normalized_chunks() {
        let store = StreamStore::new();
        let stream = ProviderStreamId::from_bytes([8; 16]);
        store.reserve(stream).unwrap();
        let mut events = vec![event(0, ProviderStreamEventKind::Started)];
        events.extend((1..=2_048).map(|sequence| {
            event(
                sequence,
                ProviderStreamEventKind::TextDelta { text: "x".into() },
            )
        }));
        store.publish(stream, events).unwrap();
    }
}
