//! DualKey instruction discriminators.
//!
//! Instruction bodies and full decoding land in later milestones.

/// Instruction discriminators (first byte of instruction data).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DualKeyInstruction {
    /// Initialize a HybridAccount PDA (Milestone 3).
    Initialize = 0,
    /// Execute an authorized intent (Milestone 5–7).
    Execute = 1,
    /// Rotate Ed25519 owner key (Milestone 9).
    RotateEd25519Key = 2,
    /// Rotate Falcon public key (Milestone 9).
    RotateFalconKey = 3,
    /// Change authorization policy (Milestone 10).
    ChangePolicy = 4,
}

impl DualKeyInstruction {
    /// Parse the discriminator byte.
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Initialize),
            1 => Some(Self::Execute),
            2 => Some(Self::RotateEd25519Key),
            3 => Some(Self::RotateFalconKey),
            4 => Some(Self::ChangePolicy),
            _ => None,
        }
    }

    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}
