//! Untrusted desktop-offer claims framed for the inherited activation channel.

use super::{
    BootstrapControlReply, DesktopOffer, MAX_QUALIFICATION_BOOTSTRAP_CONTROL_BYTES,
    QualificationBootstrapControlError as Error,
};

/// Encodes only a desktop offer before the unchanged protected V2 launch frame.
/// This framing grants no profile, credential, or bootstrap authority.
///
/// # Errors
///
/// Rejects a control message that cannot be encoded within the protocol bound.
pub fn encode_qualification_bootstrap_prelude(offer: DesktopOffer) -> Result<Vec<u8>, Error> {
    let payload = BootstrapControlReply::DesktopOffer(offer).encode()?;
    let length = u32::try_from(payload.len()).map_err(|_| Error::InvalidMessage)?;
    let mut frame = Vec::with_capacity(payload.len() + 4);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Decodes a bounded, exact desktop-offer prelude, retaining only untrusted claims.
/// The daemon must independently authenticate the peer and obtain the root ACK
/// before selecting a qualification profile. A recognized prelude never permits
/// fallback to ordinary launch after a subsequent frame or admission failure.
///
/// # Errors
///
/// Rejects malformed, oversized, noncanonical, or non-desktop-offer frames.
pub fn decode_qualification_bootstrap_prelude(frame: &[u8]) -> Result<DesktopOffer, Error> {
    let length = frame
        .get(..4)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map(u32::from_be_bytes)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(Error::InvalidMessage)?;
    if !(1..=MAX_QUALIFICATION_BOOTSTRAP_CONTROL_BYTES).contains(&length)
        || frame.len() != length + 4
    {
        return Err(Error::InvalidMessage);
    }
    match BootstrapControlReply::decode(&frame[4..])? {
        BootstrapControlReply::DesktopOffer(offer) => Ok(offer),
        _ => Err(Error::InvalidMessage),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RootPrepared, RunBinding};

    fn binding() -> RunBinding {
        RunBinding::new(
            "run-1", [1; 20], [2; 32], [3; 32], [4; 32], [5; 32], [6; 32],
        )
        .unwrap()
    }

    fn offer() -> DesktopOffer {
        DesktopOffer::new([7; 32], [8; 32], binding(), 100, 200).unwrap()
    }

    #[test]
    fn prelude_roundtrip_is_exact_and_remains_only_a_claim() {
        let frame = encode_qualification_bootstrap_prelude(offer()).unwrap();
        let decoded = decode_qualification_bootstrap_prelude(&frame).unwrap();
        assert_eq!(decoded.desktop_challenge(), [7; 32]);
        assert_eq!(decoded.offer_id(), [8; 32]);
        assert_eq!(decoded.binding().profile_sha256(), [6; 32]);
        assert_eq!(
            encode_qualification_bootstrap_prelude(decoded).unwrap(),
            frame
        );
    }

    #[test]
    fn prelude_rejects_other_roles_and_frame_boundaries() {
        let payload = BootstrapControlReply::RootPrepared(
            RootPrepared::new([8; 32], binding(), 100, 200).unwrap(),
        )
        .encode()
        .unwrap();
        let mut wrong_role = u32::try_from(payload.len()).unwrap().to_be_bytes().to_vec();
        wrong_role.extend(payload);
        assert!(decode_qualification_bootstrap_prelude(&wrong_role).is_err());
        let frame = encode_qualification_bootstrap_prelude(offer()).unwrap();
        for length in [0, 1, 3, 4, frame.len() - 1] {
            assert!(decode_qualification_bootstrap_prelude(&frame[..length]).is_err());
        }
        let mut trailing = frame.clone();
        trailing.push(0);
        assert!(decode_qualification_bootstrap_prelude(&trailing).is_err());
        let mut oversized = frame;
        oversized[..4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode_qualification_bootstrap_prelude(&oversized).is_err());
    }
}
