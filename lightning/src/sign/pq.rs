// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Post-quantum signing primitives used to add hybrid quantum resistance to
//! Shor-vulnerable signatures. We use ML-DSA (FIPS 204) at the ML-DSA-44
//! parameter set, which is the smallest standardized set and keeps the gossip
//! size overhead as low as possible. The classical secp256k1 signatures are left
//! untouched; the ML-DSA signature is added alongside them.

use fips204::ml_dsa_44::{self, PrivateKey, PublicKey, PK_LEN, SIG_LEN};
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};

use crate::prelude::*;

/// The length, in bytes, of a serialized ML-DSA-44 public key.
pub const PQ_PUBLIC_KEY_LEN: usize = PK_LEN;
/// The length, in bytes, of an ML-DSA-44 signature.
pub const PQ_SIGNATURE_LEN: usize = SIG_LEN;

/// An ML-DSA-44 secret key, used to produce post-quantum signatures over gossip messages and
/// BOLT 11 invoices.
pub struct PqSecretKey(PrivateKey);

/// Deterministically derives an ML-DSA-44 keypair from a 32-byte seed, returning the secret
/// key and the serialized public key. Used for the node's ML-DSA identity, seeded from the
/// node's entropy so it is recoverable from the same backup as the node's secret key.
pub(crate) fn keypair_from_seed(seed: &[u8; 32]) -> (PqSecretKey, [u8; PQ_PUBLIC_KEY_LEN]) {
	let (pk, sk) = ml_dsa_44::KG::keygen_from_seed(seed);
	(PqSecretKey(sk), pk.into_bytes())
}

/// Domain-separation context for BOLT 11 invoice signatures. ML-DSA (FIPS 204) takes a context
/// string that is bound into the signature; using a distinct context per surface means a signature
/// produced for one surface can never verify on another, preventing cross-protocol replay.
pub const PQ_CONTEXT_BOLT11: &[u8] = b"LDK-PQ-BOLT11-invoice";
/// Domain-separation context for BOLT 7 gossip signatures (node_announcement, channel_update).
pub const PQ_CONTEXT_GOSSIP: &[u8] = b"LDK-PQ-BOLT7-gossip";

/// Signs the message `msg` with `sk` under domain-separation `context`, returning the ML-DSA-44
/// signature. We sign the full message rather than a pre-hash so the only hash binding the message
/// is ML-DSA's internal SHAKE-256, which keeps the collision strength at the scheme's level rather
/// than that of a 256-bit pre-hash. We use the FIPS 204 deterministic variant (all-zero
/// per-signature randomness) so signatures are reproducible across runs.
pub(crate) fn sign(sk: &PqSecretKey, msg: &[u8], context: &[u8]) -> [u8; PQ_SIGNATURE_LEN] {
	// The only error conditions are a context longer than 255 bytes (ours are short constants) and
	// an RNG failure (the deterministic seed RNG cannot fail), so signing here is infallible.
	sk.0.try_sign_with_seed(&[0u8; 32], msg, context).expect("ML-DSA signing cannot fail with a short context")
}

/// Verifies the ML-DSA-44 signature `sig` over the message `msg` under domain-separation `context`
/// against the serialized public key `pk`. Returns `false` on any decoding or verification failure
/// rather than erroring, so callers can treat it as a total predicate.
pub fn verify(
	pk: &[u8; PQ_PUBLIC_KEY_LEN], msg: &[u8], sig: &[u8; PQ_SIGNATURE_LEN], context: &[u8],
) -> bool {
	match PublicKey::try_from_bytes(*pk) {
		Ok(pk) => pk.verify(msg, sig, context),
		Err(_) => false,
	}
}

// We carry the post-quantum public key and signature as odd-typed TLV records appended to the tail
// of a gossip message's `excess_data`. Odd types are ignored by nodes which do not understand them,
// so vanilla nodes treat these as opaque excess data and still verify the classical signature. A
// node_announcement may also carry the node's static ML-KEM (FIPS 203) encapsulation key, which
// post-quantum peers discover and pin via the network graph so they can later encapsulate to the
// node. That record is written between the public key and the signature, keeping the records
// ascending in type and, like the public key, covered by both the ML-DSA and the classical
// signatures.
const PQ_PUBLIC_KEY_RECORD_TYPE: u64 = 27;
const PQ_KEM_KEY_RECORD_TYPE: u64 = 29;
const PQ_SIGNATURE_RECORD_TYPE: u64 = 31;

/// The post-quantum records parsed out of a gossip message's `excess_data`.
pub(crate) struct PqRecords {
	/// The ML-DSA public key carried by a node_announcement, if present.
	pub pubkey: Option<[u8; PQ_PUBLIC_KEY_LEN]>,
	/// The ML-KEM-768 encapsulation key carried by a node_announcement, if present.
	pub kem_key: Option<[u8; crate::crypto::pq_kem::PQ_KEM_EK_LEN]>,
	/// The ML-DSA signature, if present.
	pub signature: Option<[u8; PQ_SIGNATURE_LEN]>,
	/// The number of bytes the signature record occupies. Because the signature record is always
	/// appended last, callers strip this many bytes from the end of `excess_data` to recover the
	/// exact bytes that were signed. Zero if no signature record is present.
	pub signature_record_len: usize,
}

/// Appends a BigSize-encoded value to `out`.
fn write_bigsize(out: &mut Vec<u8>, val: u64) {
	if val < 0xfd {
		out.push(val as u8);
	} else if val <= 0xffff {
		out.push(0xfd);
		out.extend_from_slice(&(val as u16).to_be_bytes());
	} else if val <= 0xffff_ffff {
		out.push(0xfe);
		out.extend_from_slice(&(val as u32).to_be_bytes());
	} else {
		out.push(0xff);
		out.extend_from_slice(&val.to_be_bytes());
	}
}

/// Reads a BigSize value from `data` starting at `*pos`, advancing `*pos`. Returns `None` on a short
/// read.
fn read_bigsize(data: &[u8], pos: &mut usize) -> Option<u64> {
	let first = *data.get(*pos)?;
	*pos += 1;
	match first {
		0xff => {
			let b = data.get(*pos..*pos + 8)?;
			*pos += 8;
			Some(u64::from_be_bytes(b.try_into().ok()?))
		},
		0xfe => {
			let b = data.get(*pos..*pos + 4)?;
			*pos += 4;
			Some(u32::from_be_bytes(b.try_into().ok()?) as u64)
		},
		0xfd => {
			let b = data.get(*pos..*pos + 2)?;
			*pos += 2;
			Some(u16::from_be_bytes(b.try_into().ok()?) as u64)
		},
		v => Some(v as u64),
	}
}

/// Appends the ML-DSA public key record to a gossip message's `excess_data`.
pub(crate) fn append_public_key_record(excess_data: &mut Vec<u8>, pubkey: &[u8; PQ_PUBLIC_KEY_LEN]) {
	write_bigsize(excess_data, PQ_PUBLIC_KEY_RECORD_TYPE);
	write_bigsize(excess_data, PQ_PUBLIC_KEY_LEN as u64);
	excess_data.extend_from_slice(pubkey);
}

/// Appends the ML-KEM-768 encapsulation key record to a node_announcement's `excess_data`. This
/// must be written after the public key record and before the signature record, so the signature
/// commits to it.
pub(crate) fn append_kem_key_record(
	excess_data: &mut Vec<u8>, kem_key: &[u8; crate::crypto::pq_kem::PQ_KEM_EK_LEN],
) {
	write_bigsize(excess_data, PQ_KEM_KEY_RECORD_TYPE);
	write_bigsize(excess_data, crate::crypto::pq_kem::PQ_KEM_EK_LEN as u64);
	excess_data.extend_from_slice(kem_key);
}

/// Appends the ML-DSA signature record to a gossip message's `excess_data`. This must be the last
/// thing written, as the signature covers everything before it.
pub(crate) fn append_signature_record(excess_data: &mut Vec<u8>, signature: &[u8; PQ_SIGNATURE_LEN]) {
	write_bigsize(excess_data, PQ_SIGNATURE_RECORD_TYPE);
	write_bigsize(excess_data, PQ_SIGNATURE_LEN as u64);
	excess_data.extend_from_slice(signature);
}

/// Parses the post-quantum public key and signature records out of a gossip message's `excess_data`.
/// Records with an unexpected type or length are left untouched (treated as ordinary excess data).
pub(crate) fn parse_records(excess_data: &[u8]) -> PqRecords {
	let mut records =
		PqRecords { pubkey: None, kem_key: None, signature: None, signature_record_len: 0 };
	let mut pos = 0;
	while pos < excess_data.len() {
		let record_start = pos;
		let typ = match read_bigsize(excess_data, &mut pos) {
			Some(t) => t,
			None => break,
		};
		let len = match read_bigsize(excess_data, &mut pos) {
			Some(l) => l as usize,
			None => break,
		};
		if excess_data.len() < pos + len {
			break;
		}
		let value = &excess_data[pos..pos + len];
		pos += len;
		if typ == PQ_PUBLIC_KEY_RECORD_TYPE && len == PQ_PUBLIC_KEY_LEN {
			let mut pk = [0u8; PQ_PUBLIC_KEY_LEN];
			pk.copy_from_slice(value);
			records.pubkey = Some(pk);
		} else if typ == PQ_KEM_KEY_RECORD_TYPE && len == crate::crypto::pq_kem::PQ_KEM_EK_LEN {
			let mut kem = [0u8; crate::crypto::pq_kem::PQ_KEM_EK_LEN];
			kem.copy_from_slice(value);
			records.kem_key = Some(kem);
		} else if typ == PQ_SIGNATURE_RECORD_TYPE && len == PQ_SIGNATURE_LEN {
			let mut sig = [0u8; PQ_SIGNATURE_LEN];
			sig.copy_from_slice(value);
			records.signature = Some(sig);
			records.signature_record_len = pos - record_start;
		}
	}
	records
}

#[cfg(test)]
mod tests {
	use super::*;

	const CTX: &[u8] = b"test-context";

	#[test]
	fn keygen_and_signing_are_deterministic() {
		let (sk_a, pk_a) = keypair_from_seed(&[7u8; 32]);
		let (sk_b, pk_b) = keypair_from_seed(&[7u8; 32]);
		assert_eq!(pk_a, pk_b);
		let msg = [42u8; 32];
		assert_eq!(sign(&sk_a, &msg, CTX), sign(&sk_b, &msg, CTX));
	}

	#[test]
	fn sign_and_verify_round_trip() {
		let (sk, pk) = keypair_from_seed(&[1u8; 32]);
		let msg = [9u8; 32];
		let sig = sign(&sk, &msg, CTX);
		assert!(verify(&pk, &msg, &sig, CTX));
	}

	#[test]
	fn wrong_key_is_rejected() {
		let (sk, _) = keypair_from_seed(&[1u8; 32]);
		let (_, pk2) = keypair_from_seed(&[2u8; 32]);
		let msg = [9u8; 32];
		let sig = sign(&sk, &msg, CTX);
		assert!(!verify(&pk2, &msg, &sig, CTX));
	}

	#[test]
	fn tampered_signature_or_message_is_rejected() {
		let (sk, pk) = keypair_from_seed(&[1u8; 32]);
		let msg = [9u8; 32];
		let mut sig = sign(&sk, &msg, CTX);
		assert!(verify(&pk, &msg, &sig, CTX));

		sig[0] ^= 0x01;
		assert!(!verify(&pk, &msg, &sig, CTX));

		let good_sig = sign(&sk, &msg, CTX);
		let mut bad_msg = msg;
		bad_msg[0] ^= 0x01;
		assert!(!verify(&pk, &bad_msg, &good_sig, CTX));
	}

	#[test]
	fn context_domain_separation_is_enforced() {
		// A signature produced under one context must not verify under a different context.
		let (sk, pk) = keypair_from_seed(&[3u8; 32]);
		let msg = [5u8; 32];
		let sig = sign(&sk, &msg, PQ_CONTEXT_GOSSIP);
		assert!(verify(&pk, &msg, &sig, PQ_CONTEXT_GOSSIP));
		assert!(!verify(&pk, &msg, &sig, PQ_CONTEXT_BOLT11));
	}

	#[test]
	fn malformed_public_key_does_not_panic() {
		let (sk, _) = keypair_from_seed(&[1u8; 32]);
		let msg = [9u8; 32];
		let sig = sign(&sk, &msg, CTX);
		// An all-zero public key must be rejected (not panic).
		assert!(!verify(&[0u8; PQ_PUBLIC_KEY_LEN], &msg, &sig, CTX));
	}

	#[test]
	fn records_round_trip_with_kem_key() {
		// The three node_announcement records (public key, KEM key, signature) must parse back out
		// in any combination, and the signature record length must let a verifier strip exactly the
		// trailing signature record.
		let pubkey = [1u8; PQ_PUBLIC_KEY_LEN];
		let kem_key = [2u8; crate::crypto::pq_kem::PQ_KEM_EK_LEN];
		let signature = [3u8; PQ_SIGNATURE_LEN];

		let mut excess = Vec::new();
		append_public_key_record(&mut excess, &pubkey);
		append_kem_key_record(&mut excess, &kem_key);
		let signed_len = excess.len();
		append_signature_record(&mut excess, &signature);

		let records = parse_records(&excess);
		assert_eq!(records.pubkey, Some(pubkey));
		assert_eq!(records.kem_key, Some(kem_key));
		assert_eq!(records.signature, Some(signature));
		assert_eq!(excess.len() - records.signature_record_len, signed_len);

		// A node_announcement may carry the ML-DSA pair without a KEM key (an ML-DSA-only node).
		let mut excess = Vec::new();
		append_public_key_record(&mut excess, &pubkey);
		append_signature_record(&mut excess, &signature);
		let records = parse_records(&excess);
		assert_eq!(records.pubkey, Some(pubkey));
		assert_eq!(records.kem_key, None);
		assert_eq!(records.signature, Some(signature));
	}
}
