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
//! ML-KEM shared secret is mixed in alongside it.

use fips203::ml_kem_768::{DK_LEN, EK_LEN, KG};
use fips203::traits::{KeyGen, SerDes};

use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::{Hash, HashEngine};

/// The length, in bytes, of a serialized ML-KEM-768 encapsulation (public) key.
pub const PQ_KEM_EK_LEN: usize = EK_LEN;
/// The length, in bytes, of a serialized ML-KEM-768 decapsulation (secret) key.
pub const PQ_KEM_DK_LEN: usize = DK_LEN;

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
/// encapsulation (public) key and decapsulation (secret) key. Used for the node's static KEM
/// identity, seeded from the node's entropy so it is recoverable from the same backup.
pub(crate) fn keypair_from_seed(seed: &[u8; 32]) -> ([u8; PQ_KEM_EK_LEN], [u8; PQ_KEM_DK_LEN]) {
	let (d, z) = expand_seed(seed);
	let (ek, dk) = KG::keygen_from_seed(d, z);
	(ek.into_bytes(), dk.into_bytes())
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
}
