use std::collections::{BTreeSet, VecDeque};

use serde_json::{Value, json};

use crate::{
    McpClientPort, McpDiscoverySnapshot, McpNormalizedMessage, McpRequestId, McpServerId,
    McpToolDescriptor, McpTransportError,
};

const STABLE_PROTOCOL_VERSION: &str = "2025-11-25";
const MAX_DISCOVERY_PAGES: usize = 1024;
const MAX_CURSOR_BYTES: usize = 128;

/// Exact MCP capabilities accepted by the deterministic conformance adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct McpCapabilities {
    tools: bool,
    notifications: bool,
    cancellation: bool,
}

impl McpCapabilities {
    /// Constructs an exact capability tuple.
    pub const fn new(tools: bool, notifications: bool, cancellation: bool) -> Self {
        Self {
            tools,
            notifications,
            cancellation,
        }
    }
}

/// One deterministic cursor-bound discovery page.
#[derive(Debug, Clone, PartialEq)]
pub struct McpDiscoveryPage {
    cursor: Option<String>,
    tools: Vec<McpToolDescriptor>,
    next_cursor: Option<String>,
}

impl McpDiscoveryPage {
    /// Captures one bounded discovery page.
    pub fn new(
        cursor: Option<String>,
        tools: Vec<McpToolDescriptor>,
        next_cursor: Option<String>,
    ) -> Result<Self, McpAdapterError> {
        if tools.len() > 4096
            || cursor.as_deref().is_some_and(invalid_cursor)
            || next_cursor.as_deref().is_some_and(invalid_cursor)
            || cursor == next_cursor
        {
            return Err(McpAdapterError::InvalidFixture);
        }
        Ok(Self {
            cursor,
            tools,
            next_cursor,
        })
    }
}

/// Protocol-local call disposition; not runtime terminal evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpCallDisposition {
    /// A correlated peer response was received.
    Completed,
}

/// Deterministic MCP adapter rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpAdapterError {
    /// Stable protocol version did not match.
    UnsupportedProtocol,
    /// Required capability tuple did not match.
    CapabilityMismatch,
    /// Adapter was used before initialize.
    NotInitialized,
    /// Pagination cursor was not the exact expected cursor.
    CursorMismatch,
    /// Fixture pages were malformed, duplicated or unbounded.
    InvalidFixture,
    /// Adapter-local connection is closed.
    Closed,
    /// Project-owned transport boundary was unavailable.
    Transport,
}

/// Deterministic fixture adapter implementing the project-owned client port.
pub struct FixtureMcpAdapter {
    server_id: McpServerId,
    protocol_version: String,
    capabilities: McpCapabilities,
    pages: Vec<McpDiscoveryPage>,
    inbox: VecDeque<McpNormalizedMessage>,
    cancelled: BTreeSet<McpRequestId>,
    initialized: bool,
    closed: bool,
}

impl FixtureMcpAdapter {
    /// Creates a bounded, deterministic conformance fixture.
    pub fn new(
        server_id: McpServerId,
        protocol_version: impl Into<String>,
        capabilities: McpCapabilities,
        pages: Vec<McpDiscoveryPage>,
    ) -> Result<Self, McpAdapterError> {
        let protocol_version = protocol_version.into();
        if pages.is_empty()
            || pages.len() > MAX_DISCOVERY_PAGES
            || pages
                .first()
                .and_then(|page| page.cursor.as_ref())
                .is_some()
        {
            return Err(McpAdapterError::InvalidFixture);
        }
        for window in pages.windows(2) {
            if window[0].next_cursor != window[1].cursor {
                return Err(McpAdapterError::InvalidFixture);
            }
        }
        if pages
            .last()
            .and_then(|page| page.next_cursor.as_ref())
            .is_some()
        {
            return Err(McpAdapterError::InvalidFixture);
        }
        Ok(Self {
            server_id,
            protocol_version,
            capabilities,
            pages,
            inbox: VecDeque::new(),
            cancelled: BTreeSet::new(),
            initialized: false,
            closed: false,
        })
    }

    /// Negotiates the exact stable protocol and capability tuple.
    pub fn initialize(
        &mut self,
        protocol_version: &str,
        capabilities: McpCapabilities,
    ) -> Result<(), McpAdapterError> {
        self.ensure_open()?;
        if protocol_version != STABLE_PROTOCOL_VERSION
            || self.protocol_version != STABLE_PROTOCOL_VERSION
        {
            return Err(McpAdapterError::UnsupportedProtocol);
        }
        if capabilities != self.capabilities {
            return Err(McpAdapterError::CapabilityMismatch);
        }
        self.initialized = true;
        Ok(())
    }

    /// Returns one exact page for a caller-owned cursor.
    pub fn discovery_page(
        &self,
        cursor: Option<&str>,
    ) -> Result<McpDiscoveryPage, McpAdapterError> {
        self.ensure_ready()?;
        self.pages
            .iter()
            .find(|page| page.cursor.as_deref() == cursor)
            .cloned()
            .ok_or(McpAdapterError::CursorMismatch)
    }

    /// Follows the deterministic cursor chain into one normalized snapshot.
    pub fn discover_all(&self) -> Result<McpDiscoverySnapshot, McpAdapterError> {
        self.ensure_ready()?;
        let mut cursor = None;
        let mut tools = Vec::new();
        for _ in 0..MAX_DISCOVERY_PAGES {
            let page = self.discovery_page(cursor.as_deref())?;
            tools.extend(page.tools);
            cursor = page.next_cursor;
            if cursor.is_none() {
                return McpDiscoverySnapshot::new(self.server_id.clone(), tools)
                    .map_err(|_| McpAdapterError::InvalidFixture);
            }
        }
        Err(McpAdapterError::InvalidFixture)
    }

    /// Sends one normalized tool call and consumes its correlated response.
    pub fn call(
        &mut self,
        request_id: McpRequestId,
        tool_name: &str,
        input: Value,
    ) -> Result<McpCallDisposition, McpAdapterError> {
        self.ensure_ready()?;
        if !self.capabilities.tools || tool_name.is_empty() {
            return Err(McpAdapterError::CapabilityMismatch);
        }
        let request = McpNormalizedMessage::request(
            Some(request_id.clone()),
            "tools/call".into(),
            json!({"name": tool_name, "arguments": input}),
        );
        self.dispatch(&request)
            .map_err(|_| McpAdapterError::Transport)?;
        let response = self.receive().map_err(|_| McpAdapterError::Transport)?;
        if response.request_id() == Some(&request_id) && response.is_success_response() {
            Ok(McpCallDisposition::Completed)
        } else {
            Err(McpAdapterError::Transport)
        }
    }

    /// Sends one normalized notification.
    pub fn notify(&mut self, method: &str, params: Value) -> Result<(), McpAdapterError> {
        self.ensure_ready()?;
        if !self.capabilities.notifications || method.is_empty() {
            return Err(McpAdapterError::CapabilityMismatch);
        }
        self.dispatch(&McpNormalizedMessage::request(
            None,
            method.to_owned(),
            params,
        ))
        .map_err(|_| McpAdapterError::Transport)
    }

    /// Idempotently records protocol cancellation.
    pub fn cancel(&mut self, request_id: &McpRequestId) -> Result<(), McpAdapterError> {
        self.ensure_ready()?;
        if !self.capabilities.cancellation {
            return Err(McpAdapterError::CapabilityMismatch);
        }
        self.cancelled.insert(request_id.clone());
        Ok(())
    }

    /// Closes only the adapter-local connection disposition.
    pub fn close(&mut self) -> Result<(), McpAdapterError> {
        self.ensure_open()?;
        self.closed = true;
        Ok(())
    }

    fn ensure_open(&self) -> Result<(), McpAdapterError> {
        if self.closed {
            Err(McpAdapterError::Closed)
        } else {
            Ok(())
        }
    }

    fn ensure_ready(&self) -> Result<(), McpAdapterError> {
        self.ensure_open()?;
        if self.initialized {
            Ok(())
        } else {
            Err(McpAdapterError::NotInitialized)
        }
    }
}

impl McpClientPort for FixtureMcpAdapter {
    fn dispatch(&mut self, message: &McpNormalizedMessage) -> Result<(), McpTransportError> {
        self.ensure_ready()
            .map_err(|_| McpTransportError::Unavailable)?;
        if let Some(request_id) = message.request_id().cloned() {
            self.inbox.push_back(McpNormalizedMessage::success(
                request_id,
                json!({"ok": true}),
            ));
        }
        Ok(())
    }

    fn receive(&mut self) -> Result<McpNormalizedMessage, McpTransportError> {
        self.ensure_ready()
            .map_err(|_| McpTransportError::Unavailable)?;
        self.inbox.pop_front().ok_or(McpTransportError::Unavailable)
    }
}

fn invalid_cursor(cursor: &str) -> bool {
    cursor.is_empty()
        || cursor.len() > MAX_CURSOR_BYTES
        || !cursor.bytes().all(|byte| byte.is_ascii_graphic())
}
