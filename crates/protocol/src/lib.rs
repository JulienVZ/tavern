// SPDX-License-Identifier: AGPL-3.0-or-later

//! Wire types shared by the Tavern client and server.
//!
//! This crate performs no I/O and depends on no other Tavern crate. The
//! protocol is specified in `docs/protocol.md`.

#![forbid(unsafe_code)]

pub mod handle;
pub mod rest;

/// Gateway protocol, generated from `proto/tavern/gateway/v1/gateway.proto`.
pub mod gateway {
    /// Major version 1 of the gateway protocol.
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/tavern.gateway.v1.rs"));
    }
}

/// Identity structures, generated from `proto/tavern/identity/v1/identity.proto`.
pub mod identity {
    /// Version 1 of the identity structures.
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/tavern.identity.v1.rs"));
    }
}

/// Major version of the gateway protocol implemented by this crate.
pub const GATEWAY_MAJOR_VERSION: u32 = 1;

/// Minor version of the gateway protocol implemented by this crate.
///
/// Incremented on every additive change within a major version.
pub const GATEWAY_MINOR_VERSION: u32 = 0;

/// WebSocket subprotocol negotiated by the gateway.
pub const GATEWAY_SUBPROTOCOL: &str = "tavern.v1";

/// Largest gateway frame accepted by default, in bytes.
pub const DEFAULT_MAX_FRAME_BYTES: u32 = 1024 * 1024;

/// Largest JSON body accepted by the REST API by default, in bytes.
pub const DEFAULT_MAX_REST_BODY_BYTES: usize = 64 * 1024;

#[cfg(test)]
mod tests {
    use prost::Message;

    use super::gateway::v1::{ClientFrame, Hello, client_frame::Payload};

    #[test]
    fn client_frame_round_trips() {
        let frame = ClientFrame {
            request_id: 7,
            payload: Some(Payload::Hello(Hello {
                session_token: vec![1, 2, 3],
                protocol_minor: super::GATEWAY_MINOR_VERSION,
                client_version: "0.0.1".to_owned(),
                client_platform: "linux".to_owned(),
            })),
        };

        let bytes = frame.encode_to_vec();
        let decoded = ClientFrame::decode(bytes.as_slice()).unwrap();

        assert_eq!(decoded, frame);
    }

    #[test]
    fn unknown_payload_decodes_as_none() {
        // Field 999 (length-delimited, empty) is not a known `payload` member.
        let bytes = [0x08, 0x01, 0xba, 0x3e, 0x00];
        let decoded = ClientFrame::decode(bytes.as_slice()).unwrap();

        assert_eq!(decoded.request_id, 1);
        assert!(decoded.payload.is_none());
    }
}
