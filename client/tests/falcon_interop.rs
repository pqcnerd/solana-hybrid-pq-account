//! MILESTONE 1 GATE: PQClean Falcon-512 signatures must verify under the
//! on-chain verifier (`solana-falcon512`) with no invented conversion.
//!
//! The only adaptation permitted is right-zero-padding a variable-length
//! PQClean signature into the 666-byte wire buffer.

use dualkey_client::falcon_interop::{
    self, lengths, WireSignature, FALCON_COMPRESSED_HEADER, PQCLEAN_SIGNATURE_BUFFER_LEN,
};
use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};

const MESSAGE: &[u8] = b"dualkey milestone 1 falcon interoperability gate";

#[test]
fn observed_key_and_signature_lengths() {
    assert_eq!(lengths::pqclean_public_key(), 897, "PQClean public key");
    assert_eq!(lengths::pqclean_secret_key(), 1281, "PQClean secret key");
    assert_eq!(
        lengths::pqclean_signature_buffer(),
        PQCLEAN_SIGNATURE_BUFFER_LEN,
        "PQClean CRYPTO_BYTES is the signing buffer, not the wire width"
    );
    assert_eq!(lengths::solana_wire_signature(), 666);
    assert_eq!(lengths::solana_wire_public_key(), 897);
    assert_eq!(lengths::solana_prepared_public_key(), 1024);

    // Public key widths agree byte-for-byte; signature widths do NOT.
    assert_eq!(
        lengths::pqclean_public_key(),
        lengths::solana_wire_public_key()
    );
    assert_ne!(
        lengths::pqclean_signature_buffer(),
        lengths::solana_wire_signature()
    );
}

#[test]
fn pqclean_signatures_are_variable_length_and_fit_the_wire_buffer() {
    let (_pk, sk) = falcon512::keypair();

    let mut min = usize::MAX;
    let mut max = 0usize;
    let mut over = 0usize;

    for i in 0..200 {
        let msg = format!("{}-{i}", String::from_utf8_lossy(MESSAGE));
        let sig = falcon512::detached_sign(msg.as_bytes(), &sk);
        let len = sig.as_bytes().len();
        min = min.min(len);
        max = max.max(len);
        if len > 666 {
            over += 1;
        }
        // Header byte is the compressed-format marker in every case.
        assert_eq!(
            sig.as_bytes()[0],
            FALCON_COMPRESSED_HEADER,
            "PQClean falcon512 must emit compressed header 0x39"
        );
    }

    println!("PQClean signature length over 200 signings: min={min} max={max} over_666={over}");

    assert!(
        min < max,
        "Falcon signing is randomized; lengths should vary"
    );
    assert!(
        max <= 666,
        "observed a {max}-byte signature, exceeding the 666-byte on-chain buffer"
    );
    assert_eq!(over, 0, "no signature may exceed the 666-byte wire buffer");
}

/// The gate: a real PQClean signature verifies under the on-chain verifier,
/// via both the raw and prepared public-key paths.
#[test]
fn pqclean_signature_verifies_under_solana_verifier() {
    let (pk, sk) = falcon512::keypair();
    let (pq_sig, wire) = falcon_interop::sign_to_wire(MESSAGE, &sk).expect("sign");

    // 1. PQClean verifies its own signature.
    assert!(
        falcon_interop::verify_pqclean(&pq_sig, MESSAGE, &pk),
        "PQClean must verify its own signature"
    );

    // 2. The used prefix is byte-for-byte identical to PQClean's output.
    assert_eq!(
        wire.encoded_bytes(),
        pq_sig.as_bytes(),
        "adaptation must not alter signature bytes"
    );

    // 3. Padding accounting is exact.
    assert_eq!(wire.encoded_len() + wire.padding_len(), 666);
    assert!(
        wire.as_wire_bytes()[wire.encoded_len()..]
            .iter()
            .all(|&b| b == 0),
        "trailing bytes must be zero padding"
    );

    // 4. The on-chain verifier accepts it, raw pubkey path.
    assert!(
        falcon_interop::verify_solana_raw(&wire, MESSAGE, pk.as_bytes()),
        "solana-falcon512 must verify a PQClean signature (raw pubkey path)"
    );

    // 5. The on-chain verifier accepts it, prepared pubkey path (what the
    //    program will actually run from account data).
    let prepared = falcon_interop::prepare_pubkey(pk.as_bytes()).expect("prepare pubkey");
    assert!(
        falcon_interop::verify_solana_prepared(&wire, MESSAGE, &prepared),
        "solana-falcon512 must verify via the prepared pubkey path"
    );

    println!(
        "GATE PASS: encoded_len={} padding={} header=0x{:02x}",
        wire.encoded_len(),
        wire.padding_len(),
        wire.header()
    );
}

/// Repeat the gate across many fresh keypairs and signatures so a rare
/// length or encoding variant cannot slip through.
#[test]
fn cross_implementation_verification_holds_across_many_signatures() {
    for round in 0..25 {
        let (pk, sk) = falcon512::keypair();
        let prepared = falcon_interop::prepare_pubkey(pk.as_bytes()).expect("prepare");
        let msg = format!("round-{round}");

        let (pq_sig, wire) = falcon_interop::sign_to_wire(msg.as_bytes(), &sk).expect("sign");

        assert!(
            falcon_interop::verify_pqclean(&pq_sig, msg.as_bytes(), &pk),
            "round {round}: PQClean verify failed"
        );
        assert!(
            falcon_interop::verify_solana_raw(&wire, msg.as_bytes(), pk.as_bytes()),
            "round {round}: solana raw verify failed (len={})",
            wire.encoded_len()
        );
        assert!(
            falcon_interop::verify_solana_prepared(&wire, msg.as_bytes(), &prepared),
            "round {round}: solana prepared verify failed (len={})",
            wire.encoded_len()
        );
    }
}

/// Soak test characterising the compressed-signature length distribution.
///
/// The margin between the observed maximum and the 666-byte on-chain buffer is
/// the reason `sign_to_wire_with_retry` exists. Run with:
/// `cargo test -p dualkey-client --release -- --ignored --nocapture`
#[test]
#[ignore = "soak test; run explicitly"]
fn signature_length_distribution_soak() {
    const KEYPAIRS: usize = 20;
    const SIGS_PER_KEY: usize = 500;

    let mut histogram = std::collections::BTreeMap::<usize, usize>::new();
    let mut over = 0usize;
    let mut total = 0usize;

    for k in 0..KEYPAIRS {
        let (pk, sk) = falcon512::keypair();
        let prepared = falcon_interop::prepare_pubkey(pk.as_bytes()).expect("prepare");

        for s in 0..SIGS_PER_KEY {
            let msg = format!("soak-{k}-{s}");
            let sig = falcon512::detached_sign(msg.as_bytes(), &sk);
            let len = sig.as_bytes().len();
            *histogram.entry(len).or_default() += 1;
            total += 1;

            if len > 666 {
                over += 1;
                continue;
            }

            // Everything that fits must verify on-chain.
            let wire = WireSignature::from_encoded_bytes(sig.as_bytes()).expect("pad");
            assert!(
                falcon_interop::verify_solana_prepared(&wire, msg.as_bytes(), &prepared),
                "soak {k}/{s}: len={len} failed prepared verification"
            );
        }
    }

    let min = *histogram.keys().next().unwrap();
    let max = *histogram.keys().next_back().unwrap();
    println!("--- Falcon-512 compressed signature length distribution ---");
    println!("samples={total} min={min} max={max} over_666={over}");
    println!("margin below 666-byte buffer: {} bytes", 666 - max);
    for (len, count) in &histogram {
        let pct = (*count as f64) * 100.0 / (total as f64);
        println!("  {len:>4} bytes : {count:>6}  ({pct:5.2}%)");
    }

    assert_eq!(
        over, 0,
        "{over}/{total} signatures exceeded the 666-byte buffer"
    );
}

#[test]
fn wire_signature_round_trips_through_pqclean_and_wire_forms() {
    let (pk, sk) = falcon512::keypair();
    let (pq_sig, wire) = falcon_interop::sign_to_wire(MESSAGE, &sk).expect("sign");

    // wire -> pqclean -> verify
    let rebuilt = wire.to_pqclean().expect("rebuild pqclean signature");
    assert_eq!(rebuilt.as_bytes(), pq_sig.as_bytes());
    assert!(falcon_interop::verify_pqclean(&rebuilt, MESSAGE, &pk));

    // wire bytes -> WireSignature -> verify
    let reloaded = WireSignature::from_wire_bytes(wire.as_wire_bytes()).expect("reload");
    assert_eq!(reloaded.as_wire_bytes(), wire.as_wire_bytes());
    assert_eq!(reloaded.encoded_len(), wire.encoded_len());
    assert!(falcon_interop::verify_solana_raw(
        &reloaded,
        MESSAGE,
        pk.as_bytes()
    ));
}

#[test]
fn prepared_pubkey_matches_reserved_account_region() {
    let (pk, _sk) = falcon512::keypair();
    let prepared = falcon_interop::prepare_pubkey(pk.as_bytes()).expect("prepare");
    assert_eq!(
        prepared.as_bytes().len(),
        dualkey_core::PREPARED_FALCON_PUBKEY_LEN
    );
    assert_eq!(prepared.as_bytes().len(), 1024);
}

/// Regression test for a real bug found in Milestone 1.
///
/// `Falcon512PreparedPubkey` is `[u16; 512]` underneath, so the verifier
/// rejects any prepared-key slice that is not at least 2-byte aligned. Holding
/// the prepared key in a bare `[u8; 1024]` gave alignment 1, so verification
/// failed nondeterministically depending on stack placement. `PreparedPubkey`
/// is `#[repr(align(8))]`, mirroring Solana's 8-byte-aligned account data.
#[test]
fn prepared_pubkey_is_always_sufficiently_aligned() {
    let (pk, sk) = falcon512::keypair();

    // Many independent allocations, including deliberately odd-sized
    // interleaved buffers to shift stack/heap offsets around.
    for i in 0..64usize {
        let _shifter = vec![0u8; i * 7 + 1];
        let prepared = falcon_interop::prepare_pubkey(pk.as_bytes()).expect("prepare");
        let addr = prepared.as_bytes().as_ptr() as usize;
        assert_eq!(
            addr % 2,
            0,
            "iteration {i}: prepared pubkey must be at least 2-byte aligned (addr={addr:#x})"
        );
        assert_eq!(addr % 8, 0, "iteration {i}: expected 8-byte alignment");

        let msg = format!("alignment-{i}");
        let (_pq, wire) = falcon_interop::sign_to_wire(msg.as_bytes(), &sk).expect("sign");
        assert!(
            falcon_interop::verify_solana_prepared(&wire, msg.as_bytes(), &prepared),
            "iteration {i}: prepared verification must succeed regardless of placement"
        );
    }
}

/// The prepared form must survive a byte round trip through storage, since the
/// program will read it back out of account data.
#[test]
fn prepared_pubkey_round_trips_through_bytes() {
    use dualkey_client::falcon_interop::PreparedPubkey;

    let (pk, sk) = falcon512::keypair();
    let prepared = falcon_interop::prepare_pubkey(pk.as_bytes()).expect("prepare");

    let stored = prepared.as_bytes().to_vec();
    let reloaded = PreparedPubkey::from_slice(&stored).expect("reload");
    assert_eq!(reloaded.as_bytes(), prepared.as_bytes());

    let (_pq, wire) = falcon_interop::sign_to_wire(MESSAGE, &sk).expect("sign");
    assert!(falcon_interop::verify_solana_prepared(
        &wire, MESSAGE, &reloaded
    ));

    // Wrong lengths are rejected.
    assert!(PreparedPubkey::from_slice(&stored[..1023]).is_err());
    assert!(PreparedPubkey::from_slice(&[0u8; 897]).is_err());
}

#[test]
fn oversized_signature_is_rejected_not_truncated() {
    let too_long = vec![0x39u8; 667];
    let err = WireSignature::from_encoded_bytes(&too_long).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("667") && msg.contains("666"),
        "error must report observed and max lengths: {msg}"
    );
}

#[test]
fn padded_format_signature_is_rejected_by_solana_verifier() {
    // Header 0x49 is the padded Falcon format, which the on-chain verifier
    // explicitly rejects. Confirms we are not accidentally relying on it.
    let (pk, sk) = falcon512::keypair();
    let (_pq_sig, wire) = falcon_interop::sign_to_wire(MESSAGE, &sk).expect("sign");
    let mut bytes = *wire.as_wire_bytes();
    bytes[0] = 0x49;
    let mutated = WireSignature::from_wire_bytes(&bytes).expect("reload");
    assert!(
        !falcon_interop::verify_solana_raw(&mutated, MESSAGE, pk.as_bytes()),
        "padded header 0x49 must be rejected"
    );
}
