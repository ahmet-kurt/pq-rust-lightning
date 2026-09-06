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
//! untouched; the post-quantum signature is added alongside them.
//! The larger ML-DSA-65 and ML-DSA-87 sets, and FN-DSA (Falcon) at degree 512 or 1024, can be
//! selected with cargo features for evaluation.

use crate::prelude::*;

// The signature scheme and its parameter set are selected at build time. ML-DSA-44 is the default;
// the `pq-ml-dsa-65` and `pq-ml-dsa-87` features swap in the larger ML-DSA sets and the
// `pq-fn-dsa-512` and `pq-fn-dsa-1024` features swap in FN-DSA, so the other NIST security
// categories and the other lattice signature scheme can be evaluated with the same code. Both
// backends expose the same key type, functions and length constants, and the rest of the crate
// only uses those.
const _: () = assert!(
	cfg!(feature = "pq-ml-dsa-65") as u8
		+ cfg!(feature = "pq-ml-dsa-87") as u8
		+ cfg!(feature = "pq-fn-dsa-512") as u8
		+ cfg!(feature = "pq-fn-dsa-1024") as u8
		<= 1,
	"at most one of the pq-ml-dsa-65, pq-ml-dsa-87, pq-fn-dsa-512 and pq-fn-dsa-1024 features may be enabled"
);

#[cfg(not(any(feature = "pq-fn-dsa-512", feature = "pq-fn-dsa-1024")))]
use self::ml_dsa_backend as backend;
#[cfg(any(feature = "pq-fn-dsa-512", feature = "pq-fn-dsa-1024"))]
use self::fn_dsa_backend as backend;

pub use backend::verify;
pub use backend::{PqSecretKey, PQ_PUBLIC_KEY_LEN, PQ_SIGNATURE_LEN, PQ_SIG_SCHEME};
pub(crate) use backend::{keypair_from_seed, sign};

/// Domain-separation context for BOLT 11 invoice signatures. ML-DSA (FIPS 204) and FN-DSA take a
/// context string that is bound into the signature; using a distinct context per surface means a
/// signature produced for one surface can never verify on another, preventing cross-protocol
/// replay.
pub const PQ_CONTEXT_BOLT11: &[u8] = b"LDK-PQ-BOLT11-invoice";
/// Domain-separation context for BOLT 7 gossip signatures (node_announcement, channel_update).
pub const PQ_CONTEXT_GOSSIP: &[u8] = b"LDK-PQ-BOLT7-gossip";
/// Domain-separation context for BOLT 12 `invoice` signatures.
pub const PQ_CONTEXT_BOLT12: &[u8] = b"LDK-PQ-BOLT12-invoice";
/// Domain-separation context for BOLT 12 `static_invoice` signatures (async payments). Distinct from
/// the `invoice` context so a signature for one cannot verify as the other even though both are
/// anchored to the same per-offer ML-DSA key.
pub const PQ_CONTEXT_BOLT12_STATIC: &[u8] = b"LDK-PQ-BOLT12-static-invoice";

/// The ML-DSA (FIPS 204) backend.
#[cfg(not(any(feature = "pq-fn-dsa-512", feature = "pq-fn-dsa-1024")))]
mod ml_dsa_backend {
	#[cfg(not(any(feature = "pq-ml-dsa-65", feature = "pq-ml-dsa-87")))]
	use fips204::ml_dsa_44::{self as ml_dsa, PrivateKey, PublicKey, PK_LEN, SIG_LEN};
	#[cfg(feature = "pq-ml-dsa-65")]
	use fips204::ml_dsa_65::{self as ml_dsa, PrivateKey, PublicKey, PK_LEN, SIG_LEN};
	#[cfg(feature = "pq-ml-dsa-87")]
	use fips204::ml_dsa_87::{self as ml_dsa, PrivateKey, PublicKey, PK_LEN, SIG_LEN};
	use fips204::traits::{KeyGen, SerDes, Signer, Verifier};

	/// The length, in bytes, of a serialized public key of the selected ML-DSA set.
	pub const PQ_PUBLIC_KEY_LEN: usize = PK_LEN;
	/// The length, in bytes, of a signature of the selected ML-DSA set.
	pub const PQ_SIGNATURE_LEN: usize = SIG_LEN;
	/// The name of the selected ML-DSA parameter set, for logs and measurement reports.
	#[cfg(not(any(feature = "pq-ml-dsa-65", feature = "pq-ml-dsa-87")))]
	pub const PQ_SIG_SCHEME: &str = "ML-DSA-44";
	#[cfg(feature = "pq-ml-dsa-65")]
	/// The name of the selected ML-DSA parameter set, for logs and measurement reports.
	pub const PQ_SIG_SCHEME: &str = "ML-DSA-65";
	#[cfg(feature = "pq-ml-dsa-87")]
	/// The name of the selected ML-DSA parameter set, for logs and measurement reports.
	pub const PQ_SIG_SCHEME: &str = "ML-DSA-87";

	/// An ML-DSA secret key, used to produce post-quantum signatures over gossip messages and
	/// BOLT 11 and BOLT 12 invoices.
	pub struct PqSecretKey(PrivateKey);

	/// Deterministically derives an ML-DSA keypair from a 32-byte seed, returning the secret key
	/// and the serialized public key. Used both for the node's post-quantum identity (seeded from
	/// the node's entropy, so it is recoverable from the same backup as the node's secret key) and
	/// for per-offer keys (seeded from an HMAC of the node's offer key and the offer's nonce).
	pub(crate) fn keypair_from_seed(seed: &[u8; 32]) -> (PqSecretKey, [u8; PQ_PUBLIC_KEY_LEN]) {
		let (pk, sk) = ml_dsa::KG::keygen_from_seed(seed);
		(PqSecretKey(sk), pk.into_bytes())
	}

	/// Signs the message `msg` with `sk` under domain-separation `context`, returning the ML-DSA
	/// signature. We sign the full message rather than a pre-hash so the only hash binding the
	/// message is ML-DSA's internal SHAKE-256, which keeps the collision strength at the scheme's
	/// level rather than that of a 256-bit pre-hash. We use the FIPS 204 deterministic variant
	/// (all-zero per-signature randomness) so signatures are reproducible across runs.
	pub(crate) fn sign(sk: &PqSecretKey, msg: &[u8], context: &[u8]) -> [u8; PQ_SIGNATURE_LEN] {
		// The only error conditions are a context longer than 255 bytes (ours are short constants)
		// and an RNG failure (the deterministic seed RNG cannot fail), so signing here is
		// infallible.
		sk.0.try_sign_with_seed(&[0u8; 32], msg, context)
			.expect("ML-DSA signing cannot fail with a short context")
	}

	/// Verifies the ML-DSA signature `sig` over the message `msg` under domain-separation
	/// `context` against the serialized public key `pk`. Returns `false` on any decoding or
	/// verification failure rather than erroring, so callers can treat it as a total predicate.
	pub fn verify(
		pk: &[u8; PQ_PUBLIC_KEY_LEN], msg: &[u8], sig: &[u8; PQ_SIGNATURE_LEN], context: &[u8],
	) -> bool {
		match PublicKey::try_from_bytes(*pk) {
			Ok(pk) => pk.verify(msg, sig, context),
			Err(_) => false,
		}
	}
}

/// The FN-DSA (Falcon) backend. FN-DSA is the third lattice signature scheme NIST selected for
/// standardization, with keys and signatures far smaller than ML-DSA's at the cost of a slow key
/// generation and floating-point arithmetic in signing. NIST has not published FIPS 206 yet, so
/// the `fn-dsa` crate implements the expected draft and its encodings may still change.
#[cfg(any(feature = "pq-fn-dsa-512", feature = "pq-fn-dsa-1024"))]
mod fn_dsa_backend {
	use fn_dsa::{
		sign_key_size, signature_size, vrfy_key_size, CryptoRng, DomainContext, KeyPairGenerator,
		RngCore, RngError, SigningKey, VerifyingKey, HASH_ID_RAW, SHAKE256,
	};
	#[cfg(feature = "pq-fn-dsa-512")]
	use fn_dsa::{
		KeyPairGenerator512 as KeyPairGen, SigningKey512 as SignKey, VerifyingKey512 as VrfyKey,
		FN_DSA_LOGN_512 as LOGN,
	};
	#[cfg(feature = "pq-fn-dsa-1024")]
	use fn_dsa::{
		KeyPairGenerator1024 as KeyPairGen, SigningKey1024 as SignKey,
		VerifyingKey1024 as VrfyKey, FN_DSA_LOGN_1024 as LOGN,
	};

	/// The length, in bytes, of a serialized public (verifying) key of the selected FN-DSA degree.
	pub const PQ_PUBLIC_KEY_LEN: usize = vrfy_key_size(LOGN);
	/// The length, in bytes, of a signature of the selected FN-DSA degree.
	pub const PQ_SIGNATURE_LEN: usize = signature_size(LOGN);
	/// The length, in bytes, of a serialized signing key of the selected FN-DSA degree.
	const PQ_SIGNING_KEY_LEN: usize = sign_key_size(LOGN);
	/// The name of the selected FN-DSA degree, for logs and measurement reports.
	#[cfg(feature = "pq-fn-dsa-512")]
	pub const PQ_SIG_SCHEME: &str = "FN-DSA-512";
	#[cfg(feature = "pq-fn-dsa-1024")]
	/// The name of the selected FN-DSA degree, for logs and measurement reports.
	pub const PQ_SIG_SCHEME: &str = "FN-DSA-1024";

	/// An FN-DSA signing key in its encoded form, used to produce post-quantum signatures over
	/// gossip messages and BOLT 11 and BOLT 12 invoices. It is decoded on every signature, which
	/// costs a small fraction of the signature itself and keeps signing free of shared mutable
	/// state.
	pub struct PqSecretKey([u8; PQ_SIGNING_KEY_LEN]);

	/// A SHAKE256 stream standing in for the random source that FN-DSA key generation and signing
	/// draw from, so both are deterministic in their seed.
	struct SeedRng(SHAKE256);

	impl SeedRng {
		fn new(parts: &[&[u8]]) -> Self {
			let mut shake = SHAKE256::new();
			for part in parts {
				shake.inject(part);
			}
			shake.flip();
			SeedRng(shake)
		}
	}

	impl CryptoRng for SeedRng {}

	impl RngCore for SeedRng {
		fn next_u32(&mut self) -> u32 {
			let mut bytes = [0u8; 4];
			self.fill_bytes(&mut bytes);
			u32::from_le_bytes(bytes)
		}
		fn next_u64(&mut self) -> u64 {
			let mut bytes = [0u8; 8];
			self.fill_bytes(&mut bytes);
			u64::from_le_bytes(bytes)
		}
		fn fill_bytes(&mut self, dest: &mut [u8]) {
			self.0.extract(dest);
		}
		fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
			self.fill_bytes(dest);
			Ok(())
		}
	}

	/// Deterministically derives an FN-DSA keypair from a 32-byte seed, returning the encoded
	/// signing key and the encoded verifying key. Used for the same node and per-offer keys as
	/// the ML-DSA backend.
	pub(crate) fn keypair_from_seed(seed: &[u8; 32]) -> (PqSecretKey, [u8; PQ_PUBLIC_KEY_LEN]) {
		let mut rng = SeedRng::new(&[&seed[..]]);
		let mut generator = KeyPairGen::default();
		let mut sign_key = [0u8; PQ_SIGNING_KEY_LEN];
		let mut vrfy_key = [0u8; PQ_PUBLIC_KEY_LEN];
		generator.keygen(LOGN, &mut rng, &mut sign_key, &mut vrfy_key);
		(PqSecretKey(sign_key), vrfy_key)
	}

	/// Signs the message `msg` with `sk` under domain-separation `context`, returning the FN-DSA
	/// signature. The message is signed directly rather than pre-hashed, as in the ML-DSA backend.
	/// FN-DSA signing is randomized, so the salt and the Gaussian sampler draw from a stream bound
	/// to the key, the context and the message, which keeps signatures reproducible across runs as
	/// the deterministic ML-DSA variant does.
	pub(crate) fn sign(sk: &PqSecretKey, msg: &[u8], context: &[u8]) -> [u8; PQ_SIGNATURE_LEN] {
		let mut key = SignKey::decode(&sk.0).expect("a signing key produced by keygen decodes");
		let mut rng = SeedRng::new(&[&sk.0[..], context, msg]);
		let mut sig = [0u8; PQ_SIGNATURE_LEN];
		// The only error condition is an invalid signing key, which keygen never produces.
		key.sign(&mut rng, &DomainContext(context), &HASH_ID_RAW, msg, &mut sig)
			.expect("FN-DSA signing cannot fail with a valid key");
		sig
	}

	/// Verifies the FN-DSA signature `sig` over the message `msg` under domain-separation
	/// `context` against the serialized verifying key `pk`. Returns `false` on any decoding or
	/// verification failure rather than erroring, so callers can treat it as a total predicate.
	pub fn verify(
		pk: &[u8; PQ_PUBLIC_KEY_LEN], msg: &[u8], sig: &[u8; PQ_SIGNATURE_LEN], context: &[u8],
	) -> bool {
		match VrfyKey::decode(pk) {
			Some(vk) => vk.verify(sig, &DomainContext(context), &HASH_ID_RAW, msg),
			None => false,
		}
	}
}

// We carry the post-quantum public key and signature as odd-typed TLV records appended to the tail
// of a gossip message's `excess_data`. Odd types are ignored by nodes which do not understand them,
// so vanilla nodes treat these as opaque excess data and still verify the classical signature. A
// node_announcement may also carry the node's static ML-KEM (FIPS 203) encapsulation key, which
// post-quantum senders discover and pin via the network graph so they can encapsulate to the node
// when building blinded paths and payment onions through it. That record is written between the
// public key and the signature, keeping the records ascending in type
// and, like the public key, covered by both the ML-DSA and the classical signatures.
const PQ_PUBLIC_KEY_RECORD_TYPE: u64 = 27;
const PQ_KEM_KEY_RECORD_TYPE: u64 = 29;
const PQ_SIGNATURE_RECORD_TYPE: u64 = 31;

/// The number of bytes the three post-quantum records add to a node_announcement. Each record is its
/// one-byte type, its three-byte BigSize length (every value is at least 253 bytes long) and its
/// value. The gossip relay budget is sized from this.
pub(crate) const PQ_NODE_ANNOUNCEMENT_RECORDS_LEN: usize =
	3 * 4 + PQ_PUBLIC_KEY_LEN + crate::crypto::pq_kem::PQ_KEM_EK_LEN + PQ_SIGNATURE_LEN;

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

#[cfg(test)]
mod timing_tests {
	use super::*;
	use crate::crypto::pq_kem;

	use bitcoin::secp256k1::{
		ecdh, Keypair, Message, PublicKey as SecpPublicKey, Secp256k1, SecretKey,
	};

	use core::hint::black_box;
	use std::time::Instant;

	const ITERS: usize = 1000;
	const MSG_LEN: usize = 300;

	fn seed(i: usize) -> [u8; 32] {
		let mut seed = [0x5au8; 32];
		seed[..8].copy_from_slice(&(i as u64).to_le_bytes());
		seed
	}

	fn message(i: usize) -> Vec<u8> {
		let mut msg = vec![0x33u8; MSG_LEN];
		msg[..8].copy_from_slice(&(i as u64).to_le_bytes());
		msg
	}

	/// Runs `op` once per prepared input, after a short untimed warmup, and returns the per-call
	/// wall times in microseconds.
	fn time_each<T, F: FnMut(usize) -> T>(mut op: F) -> Vec<f64> {
		for _ in 0..10 {
			black_box(op(0));
		}
		let mut samples = Vec::with_capacity(ITERS);
		for i in 0..ITERS {
			let start = Instant::now();
			black_box(op(i));
			samples.push(start.elapsed().as_secs_f64() * 1_000_000.0);
		}
		samples
	}

	fn report(name: &str, samples: &[f64]) {
		let mean = samples.iter().sum::<f64>() / samples.len() as f64;
		let var = samples.iter().map(|s| (s - mean) * (s - mean)).sum::<f64>()
			/ (samples.len() - 1) as f64;
		println!("{: <24} mean {: >9.2} us   std {: >8.2} us", name, mean, var.sqrt());
	}

	/// Measures the post-quantum primitives through the same entry points the production code
	/// calls, next to the classical secp256k1 operations used on the same surfaces, so the
	/// per-operation computational overhead can be reported. Ignored by default; run manually in
	/// release mode with
	/// `cargo test -p lightning --lib --features post-quantum --release -- timing_tests --ignored --nocapture`.
	#[test]
	#[ignore]
	fn measure_primitive_timings() {
		println!("{} iterations per operation, {} byte messages", ITERS, MSG_LEN);

		let seeds: Vec<[u8; 32]> = (0..ITERS).map(seed).collect();
		let msgs: Vec<Vec<u8>> = (0..ITERS).map(message).collect();

		report(
			&format!("{} keygen", PQ_SIG_SCHEME),
			&time_each(|i| keypair_from_seed(&seeds[i])),
		);
		let dsa_keys: Vec<_> = seeds.iter().map(keypair_from_seed).collect();
		report(
			&format!("{} sign", PQ_SIG_SCHEME),
			&time_each(|i| sign(&dsa_keys[i].0, &msgs[i], PQ_CONTEXT_GOSSIP)),
		);
		let sigs: Vec<_> =
			(0..ITERS).map(|i| sign(&dsa_keys[i].0, &msgs[i], PQ_CONTEXT_GOSSIP)).collect();
		report(
			&format!("{} verify", PQ_SIG_SCHEME),
			&time_each(|i| verify(&dsa_keys[i].1, &msgs[i], &sigs[i], PQ_CONTEXT_GOSSIP)),
		);

		report(
			&format!("{} keygen", pq_kem::PQ_KEM_SCHEME),
			&time_each(|i| pq_kem::keypair_from_seed(&seeds[i])),
		);
		let kem_keys: Vec<_> = seeds.iter().map(|s| pq_kem::keypair_from_seed(s)).collect();
		report(
			&format!("{} encapsulate", pq_kem::PQ_KEM_SCHEME),
			&time_each(|i| pq_kem::encapsulate(&kem_keys[i].0, &seeds[i]).unwrap()),
		);
		let cts: Vec<_> =
			(0..ITERS).map(|i| pq_kem::encapsulate(&kem_keys[i].0, &seeds[i]).unwrap().1).collect();
		report(
			&format!("{} decapsulate", pq_kem::PQ_KEM_SCHEME),
			&time_each(|i| pq_kem::decapsulate(&kem_keys[i].1, &cts[i]).unwrap()),
		);

		let secp = Secp256k1::new();
		report(
			"secp256k1 keygen",
			&time_each(|i| {
				let sk = SecretKey::from_slice(&seeds[i]).unwrap();
				SecpPublicKey::from_secret_key(&secp, &sk)
			}),
		);
		let sks: Vec<_> = seeds.iter().map(|s| SecretKey::from_slice(s).unwrap()).collect();
		let pks: Vec<_> = sks.iter().map(|sk| SecpPublicKey::from_secret_key(&secp, sk)).collect();
		let digests: Vec<_> = (0..ITERS).map(|i| Message::from_digest(seed(i))).collect();
		report("ECDSA sign", &time_each(|i| secp.sign_ecdsa(&digests[i], &sks[i])));
		let ecdsa_sigs: Vec<_> = (0..ITERS).map(|i| secp.sign_ecdsa(&digests[i], &sks[i])).collect();
		report(
			"ECDSA verify",
			&time_each(|i| secp.verify_ecdsa(&digests[i], &ecdsa_sigs[i], &pks[i]).unwrap()),
		);
		let keypairs: Vec<_> = sks.iter().map(|sk| Keypair::from_secret_key(&secp, sk)).collect();
		report(
			"Schnorr sign",
			&time_each(|i| secp.sign_schnorr_no_aux_rand(&digests[i], &keypairs[i])),
		);
		let schnorr_sigs: Vec<_> =
			(0..ITERS).map(|i| secp.sign_schnorr_no_aux_rand(&digests[i], &keypairs[i])).collect();
		let xonly: Vec<_> = keypairs.iter().map(|kp| kp.x_only_public_key().0).collect();
		report(
			"Schnorr verify",
			&time_each(|i| secp.verify_schnorr(&schnorr_sigs[i], &digests[i], &xonly[i]).unwrap()),
		);
		report("ECDH", &time_each(|i| ecdh::SharedSecret::new(&pks[(i + 1) % ITERS], &sks[i])));

		let kem_secrets: Vec<_> =
			(0..ITERS).map(|i| pq_kem::decapsulate(&kem_keys[i].1, &cts[i]).unwrap()).collect();
		let classical_secrets: Vec<_> =
			(0..ITERS).map(|i| ecdh::SharedSecret::new(&pks[(i + 1) % ITERS], &sks[i])).collect();
		report(
			"hybrid secret fold",
			&time_each(|i| {
				pq_kem::mix_payment_onion_secret(classical_secrets[i].as_ref(), &kem_secrets[i])
			}),
		);
	}
}

#[cfg(test)]
mod size_tests {
	use super::*;
	use crate::crypto::pq_kem;
	use crate::ln::msgs;
	use crate::ln::onion_utils::{PQ_BLINDED_PATH_MAX_HOPS, PQ_PAYMENT_TRAIL_LEN};
	use crate::ln::types::ChannelId;
	use crate::types::payment::PaymentHash;
	use crate::util::ser::Writeable;

	use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
	use lightning_invoice::pq::{append_chunks, TAG_PQ_PUBLIC_KEY, TAG_PQ_SIGNATURE};
	use lightning_invoice::RawTaggedField;

	/// The number of chunked BOLT 11 fields `data` occupies under `tag`, and the base32 characters
	/// they add to the encoded invoice (the three-character field header of each chunk included).
	fn bolt11_fields(tag: u8, data: &[u8]) -> (usize, usize) {
		let mut fields = Vec::new();
		append_chunks(&mut fields, tag, data);
		let chars = fields
			.iter()
			.map(|field| match field {
				RawTaggedField::UnknownSemantics(values) => values.len(),
				RawTaggedField::KnownSemantics(_) => 0,
			})
			.sum();
		(fields.len(), chars)
	}

	/// Reports the wire sizes of the post-quantum additions at the selected parameter sets, produced
	/// with the encoders the production code uses, one `PQ-SIZE name value` line each. Ignored by
	/// default; run with
	/// `cargo test -p lightning --lib --features post-quantum --release -- size_tests --ignored --nocapture`.
	#[test]
	#[ignore]
	fn report_pq_sizes() {
		let report = |name: &str, value: usize| println!("PQ-SIZE {} {}", name, value);
		println!("PQ-SCHEME sig {}", PQ_SIG_SCHEME);
		println!("PQ-SCHEME kem {}", pq_kem::PQ_KEM_SCHEME);
		report("pq_public_key", PQ_PUBLIC_KEY_LEN);
		report("pq_signature", PQ_SIGNATURE_LEN);
		report("ml_kem_encaps_key", pq_kem::PQ_KEM_EK_LEN);
		report("ml_kem_ciphertext", pq_kem::PQ_KEM_CT_LEN);

		// BOLT 7: the three node_announcement records and the channel_update record with their TLV
		// framing, and the relay budget the build derives from them.
		let mut excess = Vec::new();
		append_public_key_record(&mut excess, &[0u8; PQ_PUBLIC_KEY_LEN]);
		append_kem_key_record(&mut excess, &[0u8; pq_kem::PQ_KEM_EK_LEN]);
		append_signature_record(&mut excess, &[0u8; PQ_SIGNATURE_LEN]);
		assert_eq!(excess.len(), PQ_NODE_ANNOUNCEMENT_RECORDS_LEN);
		report("node_announcement_records", excess.len());
		let mut excess = Vec::new();
		append_signature_record(&mut excess, &[0u8; PQ_SIGNATURE_LEN]);
		report("channel_update_record", excess.len());
		report("relay_budget", crate::routing::gossip::MAX_EXCESS_BYTES_FOR_RELAY);

		// BOLT 8: the ML-KEM material each hybrid act carries beyond the 50-byte classical act, as
		// `PeerChannelEncryptor` lays the acts out.
		report("act_one_pq", pq_kem::PQ_KEM_CT_LEN + pq_kem::PQ_KEM_EK_LEN);
		report("act_two_pq", pq_kem::PQ_KEM_CT_LEN);

		// BOLT 4: the two ciphertext lists of update_add_htlc, measured as the growth of the encoded
		// message so their TLV framing is included.
		let secp_ctx = Secp256k1::new();
		let mut msg = msgs::UpdateAddHTLC {
			channel_id: ChannelId::from_bytes([2; 32]),
			htlc_id: 42,
			amount_msat: 1000,
			payment_hash: PaymentHash([1; 32]),
			cltv_expiry: 500000,
			skimmed_fee_msat: None,
			onion_routing_packet: msgs::OnionPacket {
				version: 0,
				public_key: Ok(PublicKey::from_secret_key(
					&secp_ctx,
					&SecretKey::from_slice(&[42; 32]).unwrap(),
				)),
				hop_data: [1; 20 * 65],
				hmac: [2; 32],
			},
			blinding_point: None,
			hold_htlc: None,
			accountable: None,
			pq_onion_trail: None,
			pq_blinded_ct: None,
		};
		let classical = msg.encode().len();
		msg.pq_onion_trail = Some(vec![0u8; PQ_PAYMENT_TRAIL_LEN]);
		report("update_add_htlc_trail", msg.encode().len() - classical);
		msg.pq_onion_trail = None;
		msg.pq_blinded_ct = Some(vec![0u8; PQ_BLINDED_PATH_MAX_HOPS * pq_kem::PQ_KEM_CT_LEN]);
		report("update_add_htlc_blinded", msg.encode().len() - classical);

		// BOLT 12: the invoice signature record.
		let mut record = Vec::new();
		crate::offers::pq::append_invoice_pq_signature(&mut record, &[0u8; PQ_SIGNATURE_LEN]);
		report("bolt12_invoice_signature_record", record.len());

		// BOLT 11: the chunked signature and public key fields.
		let (fields, chars) = bolt11_fields(TAG_PQ_SIGNATURE, &[0u8; PQ_SIGNATURE_LEN]);
		report("bolt11_signature_fields", fields);
		report("bolt11_signature_chars", chars);
		let (fields, chars) = bolt11_fields(TAG_PQ_PUBLIC_KEY, &[0u8; PQ_PUBLIC_KEY_LEN]);
		report("bolt11_public_key_fields", fields);
		report("bolt11_public_key_chars", chars);
	}
}
