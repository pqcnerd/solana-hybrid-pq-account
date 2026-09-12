//! Falcon-512 interoperability between PQClean (signing) and the on-chain
//! verifier (`solana-falcon512`).
//!
//! # Observed encodings
//!
//! | Item | PQClean / `pqcrypto-falcon` | `solana-falcon512` |
//! |------|-----------------------------|--------------------|
//! | Public key | 897 bytes fixed | 897 bytes fixed (`FALCON_512_PUBKEY_LEN`) |
//! | Secret key | 1281 bytes fixed | n/a (verify only) |
//! | Signature buffer | `CRYPTO_BYTES = 752` | `FALCON_512_SIGNATURE_LEN = 666` |
//! | Signature on the wire | **variable length**, `as_bytes()` returns `&buf[..len]` | exactly 666 bytes |
//!
//! `pqcrypto_falcon::falcon512::DetachedSignature` stores a 752-byte array
//! plus a used-length field, and `as_bytes()` yields only the used prefix.
//! PQClean's `CRYPTO_BYTES` (752) is a conservative upper bound for its
//! combined `crypto_sign` API, not the compressed signature width.
//!
//! `solana-falcon512` requires exactly 666 bytes and **validates that all
//! trailing bytes beyond the Golomb-Rice-encoded `s2` are zero**
//! (`codec::decompress_signature` rejects any non-zero padding). This matches
//! the standard Falcon compressed encoding: header `0x39`, 40-byte nonce, then
//! up to 625 bytes of `s2`, zero-padded.
//!
//! # The only adaptation performed
//!
//! Right-zero-pad the variable-length PQClean signature into a 666-byte
//! buffer. No re-encoding, no byte reordering, no header rewriting. The
//! signature bytes are passed through byte-for-byte.
//!
//! If a signature ever exceeds 666 bytes it is **rejected**, never truncated.
//! Falcon signing is randomized (fresh 40-byte nonce per signature), so the
//! caller can simply sign again.

use dualkey_core::{FALCON_SIGNATURE_LEN, FALCON_WIRE_PUBKEY_LEN};
use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, VerificationError};
use solana_falcon512::{
    Falcon512PreparedPubkey, Falcon512Pubkey, Falcon512Signature, FALCON_512_PREPARED_PUBKEY_LEN,
    FALCON_512_PUBKEY_LEN, FALCON_512_SIGNATURE_LEN,
};

use crate::error::{ClientError, Result};

// The two crates must agree on the wire lengths, or the padding adaptation
// below is invalid. Checked at compile time.
const _: () = assert!(FALCON_512_SIGNATURE_LEN == FALCON_SIGNATURE_LEN);
const _: () = assert!(FALCON_512_PUBKEY_LEN == FALCON_WIRE_PUBKEY_LEN);
const _: () = assert!(
    FALCON_512_PREPARED_PUBKEY_LEN == dualkey_core::PREPARED_FALCON_PUBKEY_LEN,
    "prepared pubkey length must match the reserved account region"
);

/// Falcon-512 compressed signature header byte (`0x39`), per the Falcon spec
/// and enforced by `solana-falcon512`. Padded (`0x49`) is rejected on-chain.
pub const FALCON_COMPRESSED_HEADER: u8 = 0x39;

/// PQClean `CRYPTO_BYTES` for falcon-512 clean — the signing buffer size, not
/// the wire signature width.
pub const PQCLEAN_SIGNATURE_BUFFER_LEN: usize = 752;

/// A PQClean signature adapted to the on-chain 666-byte wire buffer.
#[derive(Clone)]
pub struct WireSignature {
    bytes: [u8; FALCON_SIGNATURE_LEN],
    encoded_len: usize,
}

impl core::fmt::Debug for WireSignature {
    /// Signatures are public data, but printing 666 bytes is never useful.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WireSignature")
            .field("header", &format_args!("0x{:02x}", self.bytes[0]))
            .field("encoded_len", &self.encoded_len)
            .field("padding_len", &self.padding_len())
            .finish()
    }
}

impl WireSignature {
    /// Adapt a variable-length PQClean detached signature to the 666-byte
    /// on-chain wire buffer by right-zero-padding.
    ///
    /// Rejects signatures longer than 666 bytes rather than truncating.
    pub fn from_pqclean(sig: &falcon512::DetachedSignature) -> Result<Self> {
        Self::from_encoded_bytes(sig.as_bytes())
    }

    /// Adapt raw compressed signature bytes of any length `<= 666`.
    pub fn from_encoded_bytes(encoded: &[u8]) -> Result<Self> {
        if encoded.len() > FALCON_SIGNATURE_LEN {
            return Err(ClientError::FalconSignatureTooLong {
                actual: encoded.len(),
                max: FALCON_SIGNATURE_LEN,
            });
        }
        let mut bytes = [0u8; FALCON_SIGNATURE_LEN];
        bytes[..encoded.len()].copy_from_slice(encoded);
        Ok(Self {
            bytes,
            encoded_len: encoded.len(),
        })
    }

    /// Reconstruct from an already-padded 666-byte buffer.
    ///
    /// `encoded_len` is recovered by stripping trailing zeros, which is exactly
    /// what both verifiers treat as padding. This is sound for valid PQClean
    /// signatures because the final byte of a `comp_encode` output always
    /// carries the last coefficient's unary terminator bit and is therefore
    /// never zero (pinned by `last_byte_of_compressed_signature_is_never_zero`).
    ///
    /// The recovered length is only used for reporting and for
    /// [`WireSignature::to_pqclean`]. Verification never depends on it: both
    /// [`verify_pqclean_wire`] and the `solana-falcon512` paths operate on all
    /// 666 bytes.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != FALCON_SIGNATURE_LEN {
            return Err(ClientError::FalconKey(
                "wire signature must be exactly 666 bytes",
            ));
        }
        let mut buf = [0u8; FALCON_SIGNATURE_LEN];
        buf.copy_from_slice(bytes);
        let encoded_len = buf.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
        Ok(Self {
            bytes: buf,
            encoded_len,
        })
    }

    /// The 666-byte, zero-padded buffer accepted on-chain.
    pub fn as_wire_bytes(&self) -> &[u8; FALCON_SIGNATURE_LEN] {
        &self.bytes
    }

    /// The used prefix, byte-for-byte identical to PQClean's `as_bytes()`.
    pub fn encoded_bytes(&self) -> &[u8] {
        &self.bytes[..self.encoded_len]
    }

    /// Length of the PQClean-encoded portion before zero padding.
    pub fn encoded_len(&self) -> usize {
        self.encoded_len
    }

    /// Number of trailing zero-padding bytes added to reach 666.
    pub fn padding_len(&self) -> usize {
        FALCON_SIGNATURE_LEN - self.encoded_len
    }

    /// Header byte of the compressed encoding.
    pub fn header(&self) -> u8 {
        self.bytes[0]
    }

    /// Rebuild a PQClean detached signature from the used prefix.
    ///
    /// Round-trips: `from_pqclean(s).to_pqclean() == s` for valid inputs.
    pub fn to_pqclean(&self) -> Result<falcon512::DetachedSignature> {
        falcon512::DetachedSignature::from_bytes(self.encoded_bytes())
            .map_err(|_| ClientError::FalconKey("PQClean rejected the signature encoding"))
    }
}

/// Verify with PQClean (the reference signer's own verifier).
pub fn verify_pqclean(
    signature: &falcon512::DetachedSignature,
    message: &[u8],
    public_key: &falcon512::PublicKey,
) -> bool {
    matches!(
        falcon512::verify_detached_signature(signature, message, public_key),
        Ok(())
    )
}

/// Verify the **666-byte padded wire form** with PQClean, so PQClean and the
/// on-chain verifier are checked against byte-for-byte identical input.
///
/// PQClean's `do_verify` accepts a `sigbuflen` of 625 (`666 - 40 - 1`, the
/// padded-format size) provided every byte past the compressed encoding is
/// zero, so no length recovery is needed:
///
/// ```c
/// if (v != sigbuflen) {
///     if (sigbuflen == FALCONPADDED512_CRYPTO_BYTES - NONCELEN - 1) {  // 625
///         while (v < sigbuflen) { if (sigbuf[v++] != 0) return -1; }
///     } else { return -1; }
/// }
/// ```
///
/// Prefer this over reconstructing a variable-length signature: it removes any
/// dependence on stripping trailing zeros to recover the encoded length.
pub fn verify_pqclean_wire(
    wire_signature: &WireSignature,
    message: &[u8],
    pubkey_wire: &[u8],
) -> bool {
    let Ok(public_key) = falcon512::PublicKey::from_bytes(pubkey_wire) else {
        return false;
    };
    let Ok(signature) = falcon512::DetachedSignature::from_bytes(wire_signature.as_wire_bytes())
    else {
        return false;
    };
    verify_pqclean(&signature, message, &public_key)
}

/// Map a PQClean verification result to an explicit error, for diagnostics.
pub fn verify_pqclean_detailed(
    signature: &falcon512::DetachedSignature,
    message: &[u8],
    public_key: &falcon512::PublicKey,
) -> std::result::Result<(), VerificationError> {
    falcon512::verify_detached_signature(signature, message, public_key)
}

/// Verify with the on-chain verifier using a raw 897-byte wire public key.
///
/// Never panics: malformed input returns `false`.
pub fn verify_solana_raw(
    wire_signature: &WireSignature,
    message: &[u8],
    pubkey_wire: &[u8],
) -> bool {
    let Ok(pubkey) = Falcon512Pubkey::try_from_slice(pubkey_wire) else {
        return false;
    };
    let Ok(signature) = Falcon512Signature::try_from_slice(wire_signature.as_wire_bytes()) else {
        return false;
    };
    signature.verify(message, pubkey)
}

/// A prepared (NTT-form) Falcon public key with guaranteed alignment.
///
/// # Why the alignment matters
///
/// `Falcon512PreparedPubkey` is `[u16; 512]` underneath, so
/// `Falcon512PreparedPubkey::try_from_slice` **rejects any slice that is not
/// at least 2-byte aligned**. A bare `[u8; 1024]` local has alignment 1, so
/// roughly half of all stack placements land on an odd address and
/// verification fails nondeterministically even though the bytes are correct.
///
/// On-chain this cannot happen: Solana account data is 8-byte aligned by ABI
/// and the DualKey layout places the prepared key at offset 96 (8-byte
/// aligned). This wrapper reproduces that guarantee off-chain.
#[repr(align(8))]
#[derive(Clone)]
pub struct PreparedPubkey([u8; FALCON_512_PREPARED_PUBKEY_LEN]);

impl PreparedPubkey {
    /// Wrap 1024 prepared bytes, e.g. read back from a file or account.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; FALCON_512_PREPARED_PUBKEY_LEN] = bytes.try_into().map_err(|_| {
            ClientError::FalconKey("prepared public key must be exactly 1024 bytes")
        })?;
        Ok(Self(arr))
    }

    /// The 1024 bytes written into DualKey account data.
    pub fn as_bytes(&self) -> &[u8; FALCON_512_PREPARED_PUBKEY_LEN] {
        &self.0
    }

    /// Borrow as the verifier's type. Alignment is guaranteed by `repr(align)`.
    fn as_verifier(&self) -> &Falcon512PreparedPubkey {
        // Infallible: length is exact and the buffer is 8-byte aligned.
        Falcon512PreparedPubkey::try_from_slice(&self.0)
            .expect("PreparedPubkey guarantees length and alignment")
    }
}

impl core::fmt::Debug for PreparedPubkey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PreparedPubkey")
            .field("len", &self.0.len())
            .finish()
    }
}

/// Verify with the on-chain verifier using the prepared (NTT-form) public key,
/// exactly as the program will do from account data.
///
/// Never panics: malformed input returns `false`.
pub fn verify_solana_prepared(
    wire_signature: &WireSignature,
    message: &[u8],
    prepared: &PreparedPubkey,
) -> bool {
    let Ok(signature) = Falcon512Signature::try_from_slice(wire_signature.as_wire_bytes()) else {
        return false;
    };
    signature.verify_with_prepared(message, prepared.as_verifier())
}

/// Convert a 897-byte wire public key into the 1024-byte prepared form that
/// the DualKey account stores.
///
/// This is the same `try_prepare_pubkey` path the program uses at
/// initialization, so the client can precompute account data.
pub fn prepare_pubkey(pubkey_wire: &[u8]) -> Result<PreparedPubkey> {
    let pubkey = Falcon512Pubkey::try_from_slice(pubkey_wire)
        .map_err(|_| ClientError::FalconKey("malformed 897-byte wire public key"))?;
    let prepared = pubkey
        .try_prepare_pubkey()
        .map_err(|_| ClientError::FalconKey("public key failed NTT preparation"))?;
    Ok(PreparedPubkey(*prepared.as_bytes()))
}

/// Sign `message` with Falcon-512 and adapt the result to the on-chain wire
/// format in one step.
pub fn sign_to_wire(
    message: &[u8],
    secret_key: &falcon512::SecretKey,
) -> Result<(falcon512::DetachedSignature, WireSignature)> {
    let sig = falcon512::detached_sign(message, secret_key);
    let wire = WireSignature::from_pqclean(&sig)?;
    Ok((sig, wire))
}

/// Sign, retrying if the randomized signature exceeds the 666-byte buffer.
///
/// Falcon signing samples a fresh nonce each call, so retrying yields a
/// different (and possibly shorter) encoding. Returns the number of attempts.
pub fn sign_to_wire_with_retry(
    message: &[u8],
    secret_key: &falcon512::SecretKey,
    max_attempts: usize,
) -> Result<(falcon512::DetachedSignature, WireSignature, usize)> {
    let mut last_err = None;
    for attempt in 1..=max_attempts.max(1) {
        match sign_to_wire(message, secret_key) {
            Ok((sig, wire)) => return Ok((sig, wire, attempt)),
            Err(e @ ClientError::FalconSignatureTooLong { .. }) => last_err = Some(e),
            Err(other) => return Err(other),
        }
    }
    Err(last_err.unwrap_or(ClientError::FalconKey("Falcon signing failed")))
}

/// Observed byte lengths, for reporting and tests.
pub mod lengths {
    use pqcrypto_falcon::falcon512;

    /// PQClean public key length (897).
    pub fn pqclean_public_key() -> usize {
        falcon512::public_key_bytes()
    }

    /// PQClean secret key length (1281).
    pub fn pqclean_secret_key() -> usize {
        falcon512::secret_key_bytes()
    }

    /// PQClean signature buffer length / `CRYPTO_BYTES` (752).
    pub fn pqclean_signature_buffer() -> usize {
        falcon512::signature_bytes()
    }

    /// On-chain wire signature length (666).
    pub const fn solana_wire_signature() -> usize {
        solana_falcon512::FALCON_512_SIGNATURE_LEN
    }

    /// On-chain wire public key length (897).
    pub const fn solana_wire_public_key() -> usize {
        solana_falcon512::FALCON_512_PUBKEY_LEN
    }

    /// On-chain prepared public key length (1024).
    pub const fn solana_prepared_public_key() -> usize {
        solana_falcon512::FALCON_512_PREPARED_PUBKEY_LEN
    }
}
