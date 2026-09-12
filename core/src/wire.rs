//! Execute instruction wire encoding for the reconstructable intent fields.
//!
//! A legacy Solana transaction is capped at 1232 bytes. Putting the full
//! [`AuthorizationIntent`] on the wire alongside a Falcon signature and the
//! Ed25519 precompile overflows that budget. The program therefore reconstructs
//! every field that is already known from trusted context, and the instruction
//! carries only what cannot be derived:
//!
//! ```text
//! expiry_slot: u64 LE     (8)
//! action_tag:  u8         (1)
//! action_body: [u8; 40]   (40)
//! ─────────────────────────
//! total                   49
//! ```
//!
//! The Falcon signature (666 bytes) is appended by Milestone 5's `Execute`
//! instruction; this module owns only the intent fragment so Milestone 4 can
//! prove reconstruction without implementing authorization.
//!
//! Derived (never on the wire): `version`, `chain_domain`, `program_id`,
//! `account`, `nonce`.

use crate::canonical::{ACTION_BODY_LEN, INTENT_VERSION};
use crate::error::DualKeyError;
use crate::intent::{
    Action, AuthorizationIntent, ACTION_TAG_ROTATE_ED25519, ACTION_TAG_ROTATE_FALCON,
    ACTION_TAG_TRANSFER_SOL,
};

/// Wire length of the reconstructable intent fragment (no discriminator, no sig).
pub const EXECUTE_INTENT_WIRE_LEN: usize = 8 + 1 + ACTION_BODY_LEN;

const _: () = assert!(EXECUTE_INTENT_WIRE_LEN == 49);

/// Bytes saved by reconstructing rather than transmitting the full intent.
///
/// `version(1) + chain_domain(32) + program_id(32) + account(32) + nonce(8) = 105`.
pub const EXECUTE_INTENT_DERIVED_LEN: usize = 1 + 32 + 32 + 32 + 8;

const _: () = assert!(EXECUTE_INTENT_DERIVED_LEN == 105);

/// Offsets within the 49-byte intent wire fragment.
pub mod wire_offsets {
    pub const EXPIRY_SLOT: usize = 0;
    pub const ACTION_TAG: usize = 8;
    pub const ACTION_BODY: usize = 9;
}

/// The subset of an [`AuthorizationIntent`] that travels on the wire.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecuteIntentWire {
    pub expiry_slot: u64,
    pub action: Action,
}

impl ExecuteIntentWire {
    /// Encode into the fixed 49-byte wire fragment.
    pub fn encode(self) -> [u8; EXECUTE_INTENT_WIRE_LEN] {
        let mut out = [0u8; EXECUTE_INTENT_WIRE_LEN];
        out[wire_offsets::EXPIRY_SLOT..wire_offsets::EXPIRY_SLOT + 8]
            .copy_from_slice(&self.expiry_slot.to_le_bytes());
        out[wire_offsets::ACTION_TAG] = self.action.tag();
        match self.action {
            Action::TransferSol {
                recipient,
                lamports,
            } => {
                let body = wire_offsets::ACTION_BODY;
                out[body..body + 32].copy_from_slice(&recipient);
                out[body + 32..body + 40].copy_from_slice(&lamports.to_le_bytes());
            }
            Action::RotateEd25519Key { new_pubkey } => {
                let body = wire_offsets::ACTION_BODY;
                out[body..body + 32].copy_from_slice(&new_pubkey);
            }
            Action::RotateFalconKey { new_pubkey_hash } => {
                let body = wire_offsets::ACTION_BODY;
                out[body..body + 32].copy_from_slice(&new_pubkey_hash);
            }
        }
        out
    }

    /// Decode a fixed 49-byte wire fragment.
    ///
    /// Unknown action tags yield [`DualKeyError::UnsupportedAction`]. Malformed
    /// length yields [`DualKeyError::MalformedInstructionData`].
    pub fn decode(bytes: &[u8]) -> Result<Self, DualKeyError> {
        if bytes.len() != EXECUTE_INTENT_WIRE_LEN {
            return Err(DualKeyError::MalformedInstructionData);
        }
        let expiry_slot = u64::from_le_bytes(
            bytes[wire_offsets::EXPIRY_SLOT..wire_offsets::EXPIRY_SLOT + 8]
                .try_into()
                .map_err(|_| DualKeyError::MalformedInstructionData)?,
        );
        let action = Action::from_wire(
            bytes[wire_offsets::ACTION_TAG],
            &bytes[wire_offsets::ACTION_BODY..wire_offsets::ACTION_BODY + ACTION_BODY_LEN],
        )?;
        Ok(Self {
            expiry_slot,
            action,
        })
    }

    /// Pull the wire fragment out of a fully-populated signing intent.
    pub fn from_intent(intent: &AuthorizationIntent) -> Self {
        Self {
            expiry_slot: intent.expiry_slot,
            action: intent.action,
        }
    }
}

impl Action {
    /// Decode an action from its wire tag and 40-byte body.
    pub fn from_wire(tag: u8, body: &[u8]) -> Result<Self, DualKeyError> {
        if body.len() != ACTION_BODY_LEN {
            return Err(DualKeyError::MalformedInstructionData);
        }
        match tag {
            ACTION_TAG_TRANSFER_SOL => {
                let recipient: [u8; 32] = body[..32]
                    .try_into()
                    .map_err(|_| DualKeyError::MalformedInstructionData)?;
                let lamports = u64::from_le_bytes(
                    body[32..40]
                        .try_into()
                        .map_err(|_| DualKeyError::MalformedInstructionData)?,
                );
                Ok(Self::TransferSol {
                    recipient,
                    lamports,
                })
            }
            ACTION_TAG_ROTATE_ED25519 => {
                let new_pubkey: [u8; 32] = body[..32]
                    .try_into()
                    .map_err(|_| DualKeyError::MalformedInstructionData)?;
                Ok(Self::RotateEd25519Key { new_pubkey })
            }
            ACTION_TAG_ROTATE_FALCON => {
                let new_pubkey_hash: [u8; 32] = body[..32]
                    .try_into()
                    .map_err(|_| DualKeyError::MalformedInstructionData)?;
                Ok(Self::RotateFalconKey { new_pubkey_hash })
            }
            _ => Err(DualKeyError::UnsupportedAction),
        }
    }
}

/// Trusted context the program supplies when reconstructing an intent.
///
/// None of these values are taken from instruction data: a caller who could
/// choose them on the wire could forge digests for a different vault, program,
/// network, or nonce.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IntentContext {
    pub chain_domain: [u8; 32],
    pub program_id: [u8; 32],
    pub account: [u8; 32],
    pub nonce: u64,
}

/// Reconstruct a full [`AuthorizationIntent`] from trusted context + wire fields.
///
/// This is the on-chain reconstruction rule. The client builds the same struct
/// with all fields populated before signing; the program rebuilds it here and
/// must obtain an identical preimage, or signature verification fails.
pub fn reconstruct_intent(ctx: &IntentContext, wire: &ExecuteIntentWire) -> AuthorizationIntent {
    AuthorizationIntent {
        version: INTENT_VERSION,
        chain_domain: ctx.chain_domain,
        program_id: ctx.program_id,
        account: ctx.account,
        nonce: ctx.nonce,
        expiry_slot: wire.expiry_slot,
        action: wire.action,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{canonical_preimage, test_vector_intent};
    use crate::chain_domain::CHAIN_DOMAIN_LOCALNET;

    #[test]
    fn wire_roundtrip_preserves_fields() {
        let intent = test_vector_intent();
        let wire = ExecuteIntentWire::from_intent(&intent);
        let encoded = wire.encode();
        assert_eq!(encoded.len(), EXECUTE_INTENT_WIRE_LEN);
        let decoded = ExecuteIntentWire::decode(&encoded).unwrap();
        assert_eq!(decoded, wire);
    }

    #[test]
    fn reconstruction_matches_full_intent_preimage() {
        let intent = test_vector_intent();
        let wire = ExecuteIntentWire::from_intent(&intent);
        let ctx = IntentContext {
            chain_domain: intent.chain_domain,
            program_id: intent.program_id,
            account: intent.account,
            nonce: intent.nonce,
        };
        let rebuilt = reconstruct_intent(&ctx, &wire);
        assert_eq!(rebuilt, intent);
        assert_eq!(canonical_preimage(&rebuilt), canonical_preimage(&intent));
    }

    #[test]
    fn wrong_context_changes_the_preimage() {
        let intent = test_vector_intent();
        let wire = ExecuteIntentWire::from_intent(&intent);
        let mut ctx = IntentContext {
            chain_domain: intent.chain_domain,
            program_id: intent.program_id,
            account: intent.account,
            nonce: intent.nonce,
        };
        let original = canonical_preimage(&reconstruct_intent(&ctx, &wire));

        ctx.nonce = intent.nonce + 1;
        assert_ne!(
            canonical_preimage(&reconstruct_intent(&ctx, &wire)),
            original
        );

        ctx.nonce = intent.nonce;
        ctx.account[0] ^= 1;
        assert_ne!(
            canonical_preimage(&reconstruct_intent(&ctx, &wire)),
            original
        );

        ctx.account = intent.account;
        ctx.program_id[0] ^= 1;
        assert_ne!(
            canonical_preimage(&reconstruct_intent(&ctx, &wire)),
            original
        );

        ctx.program_id = intent.program_id;
        ctx.chain_domain = CHAIN_DOMAIN_LOCALNET;
        assert_ne!(
            canonical_preimage(&reconstruct_intent(&ctx, &wire)),
            original
        );
    }

    #[test]
    fn unknown_action_tag_is_rejected() {
        let mut bytes = ExecuteIntentWire::from_intent(&test_vector_intent()).encode();
        bytes[wire_offsets::ACTION_TAG] = 99;
        assert_eq!(
            ExecuteIntentWire::decode(&bytes).unwrap_err(),
            DualKeyError::UnsupportedAction
        );
    }

    #[test]
    fn wrong_wire_length_is_rejected() {
        assert_eq!(
            ExecuteIntentWire::decode(&[0u8; 48]).unwrap_err(),
            DualKeyError::MalformedInstructionData
        );
        assert_eq!(
            ExecuteIntentWire::decode(&[0u8; 50]).unwrap_err(),
            DualKeyError::MalformedInstructionData
        );
    }

    #[test]
    fn reconstruction_saves_105_bytes_on_the_wire() {
        assert_eq!(EXECUTE_INTENT_DERIVED_LEN, 105);
        assert_eq!(
            EXECUTE_INTENT_WIRE_LEN + EXECUTE_INTENT_DERIVED_LEN,
            8 + 1 + ACTION_BODY_LEN + 1 + 32 + 32 + 32 + 8
        );
    }
}
