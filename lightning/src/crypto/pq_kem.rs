// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Post-quantum key-encapsulation primitives used to add hybrid quantum resistance to LDK's
//! Shor-vulnerable ECDH. We use ML-KEM (FIPS 203) at the ML-KEM-768 parameter set, the standard
//! hybrid choice (as in TLS and Signal). The classical secp256k1 ECDH is left untouched; each
//! ML-KEM shared secret is mixed in alongside it, into the Noise chaining key on the BOLT 8
//! transport.

use fips203::ml_kem_768::{CipherText, DecapsKey, EncapsKey, CT_LEN, DK_LEN, EK_LEN, KG};
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
use fips203::SSK_LEN;

use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::{Hash, HashEngine};

/// The length, in bytes, of a serialized ML-KEM-768 encapsulation (public) key.
pub const PQ_KEM_EK_LEN: usize = EK_LEN;
/// The length, in bytes, of a serialized ML-KEM-768 decapsulation (secret) key.
pub const PQ_KEM_DK_LEN: usize = DK_LEN;
/// The length, in bytes, of an ML-KEM-768 ciphertext.
pub const PQ_KEM_CT_LEN: usize = CT_LEN;
/// The length, in bytes, of an ML-KEM shared secret.
pub const PQ_KEM_SS_LEN: usize = SSK_LEN;

/// Expands a 32-byte seed into the `(d, z)` pair ML-KEM key generation consumes, deriving the two
/// halves under distinct domain-separation tags so they are independent.
fn expand_seed(seed: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
	let derive = |tag: &[u8]| {
		let mut engine = Sha256::engine();
		engine.input(tag);
		engine.input(seed);
		Sha256::from_engine(engine).to_byte_array()
	};
	(derive(b"LDK-PQ-KEM-d"), derive(b"LDK-PQ-KEM-z"))
}

/// Deterministically derives an ML-KEM-768 keypair from a 32-byte seed, returning the serialized
/// encapsulation (public) key and decapsulation (secret) key. Used both for the node's static KEM
/// identity (seeded from the node's entropy, so it is recoverable from the same backup) and for the
/// per-connection ephemeral keypair (seeded from fresh entropy).
pub(crate) fn keypair_from_seed(seed: &[u8; 32]) -> ([u8; PQ_KEM_EK_LEN], [u8; PQ_KEM_DK_LEN]) {
	let (d, z) = expand_seed(seed);
	let (ek, dk) = KG::keygen_from_seed(d, z);
	(ek.into_bytes(), dk.into_bytes())
}

/// Encapsulates to the serialized encapsulation key `ek_bytes`, returning the shared secret and the
/// ciphertext, or `None` if `ek_bytes` is not a well-formed ML-KEM-768 key. `seed` supplies the
/// encapsulation randomness: callers pass fresh entropy in production and a fixed seed in tests for
/// reproducibility.
pub(crate) fn encapsulate(
	ek_bytes: &[u8; PQ_KEM_EK_LEN], seed: &[u8; 32],
) -> Option<([u8; PQ_KEM_SS_LEN], [u8; PQ_KEM_CT_LEN])> {
	let ek = EncapsKey::try_from_bytes(*ek_bytes).ok()?;
	let (ssk, ct) = ek.encaps_from_seed(seed);
	Some((ssk.into_bytes(), ct.into_bytes()))
}

/// Decapsulates the ciphertext `ct_bytes` with the serialized decapsulation key `dk_bytes`,
/// returning the shared secret, or `None` if either input is malformed.
pub(crate) fn decapsulate(
	dk_bytes: &[u8; PQ_KEM_DK_LEN], ct_bytes: &[u8; PQ_KEM_CT_LEN],
) -> Option<[u8; PQ_KEM_SS_LEN]> {
	let dk = DecapsKey::try_from_bytes(*dk_bytes).ok()?;
	let ct = CipherText::try_from_bytes(*ct_bytes).ok()?;
	let ssk = dk.try_decaps(&ct).ok()?;
	Some(ssk.into_bytes())
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn keygen_is_deterministic() {
		let (ek_a, dk_a) = keypair_from_seed(&[7u8; 32]);
		let (ek_b, dk_b) = keypair_from_seed(&[7u8; 32]);
		assert_eq!(ek_a, ek_b);
		assert_eq!(dk_a, dk_b);
		let (ek_c, _) = keypair_from_seed(&[8u8; 32]);
		assert_ne!(ek_a, ek_c);
	}

	#[test]
	fn encaps_decaps_round_trip() {
		let (ek, dk) = keypair_from_seed(&[1u8; 32]);
		let (ss_enc, ct) = encapsulate(&ek, &[2u8; 32]).unwrap();
		let ss_dec = decapsulate(&dk, &ct).unwrap();
		assert_eq!(ss_enc, ss_dec);
	}

	#[test]
	fn encaps_is_deterministic_from_seed() {
		let (ek, _) = keypair_from_seed(&[1u8; 32]);
		let a = encapsulate(&ek, &[5u8; 32]).unwrap();
		let b = encapsulate(&ek, &[5u8; 32]).unwrap();
		assert_eq!(a, b);
		// Fresh randomness must produce a different ciphertext (and so a different shared secret).
		let c = encapsulate(&ek, &[6u8; 32]).unwrap();
		assert_ne!(a.1, c.1);
	}

	#[test]
	fn wrong_key_yields_different_secret() {
		// ML-KEM decapsulation is failure-resistant: decapsulating with a mismatched key returns an
		// unrelated secret rather than erroring, so we assert the recovered secret differs.
		let (ek, _) = keypair_from_seed(&[1u8; 32]);
		let (_, dk_other) = keypair_from_seed(&[2u8; 32]);
		let (ss_enc, ct) = encapsulate(&ek, &[3u8; 32]).unwrap();
		let ss_dec = decapsulate(&dk_other, &ct).unwrap();
		assert_ne!(ss_enc, ss_dec);
	}

	#[test]
	fn malformed_decaps_key_is_rejected() {
		let (ek, _) = keypair_from_seed(&[1u8; 32]);
		let (_, ct) = encapsulate(&ek, &[3u8; 32]).unwrap();
		assert!(decapsulate(&[0u8; PQ_KEM_DK_LEN], &ct).is_none());
	}
}
