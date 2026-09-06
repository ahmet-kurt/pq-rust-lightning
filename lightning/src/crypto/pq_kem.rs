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
//! transport and into the per-hop secrets for BOLT 4 payment onions and blinded paths.
//! The ML-KEM-512 and ML-KEM-1024 sets can be selected with cargo features for evaluation.

// The parameter set is selected at build time. ML-KEM-768 is the default; the `pq-ml-kem-512` and
// `pq-ml-kem-1024` features swap in the other sets so the other NIST security categories can be
// evaluated with the same code.
#[cfg(all(feature = "pq-ml-kem-512", feature = "pq-ml-kem-1024"))]
compile_error!("at most one of the pq-ml-kem-512 and pq-ml-kem-1024 features may be enabled");
#[cfg(not(any(feature = "pq-ml-kem-512", feature = "pq-ml-kem-1024")))]
use fips203::ml_kem_768::{CipherText, DecapsKey, EncapsKey, CT_LEN, DK_LEN, EK_LEN, KG};
#[cfg(feature = "pq-ml-kem-512")]
use fips203::ml_kem_512::{CipherText, DecapsKey, EncapsKey, CT_LEN, DK_LEN, EK_LEN, KG};
#[cfg(feature = "pq-ml-kem-1024")]
use fips203::ml_kem_1024::{CipherText, DecapsKey, EncapsKey, CT_LEN, DK_LEN, EK_LEN, KG};
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
use fips203::SSK_LEN;

use chacha20_poly1305::chacha20::{ChaCha20, Key, Nonce};

use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::{Hash, HashEngine};

/// The length, in bytes, of a serialized encapsulation (public) key of the selected ML-KEM set.
pub const PQ_KEM_EK_LEN: usize = EK_LEN;
/// The length, in bytes, of a serialized decapsulation (secret) key of the selected ML-KEM set.
pub const PQ_KEM_DK_LEN: usize = DK_LEN;
/// The length, in bytes, of a ciphertext of the selected ML-KEM set.
pub const PQ_KEM_CT_LEN: usize = CT_LEN;
/// The length, in bytes, of an ML-KEM shared secret.
pub const PQ_KEM_SS_LEN: usize = SSK_LEN;
/// The name of the selected ML-KEM parameter set, for logs and measurement reports.
#[cfg(not(any(feature = "pq-ml-kem-512", feature = "pq-ml-kem-1024")))]
pub const PQ_KEM_SCHEME: &str = "ML-KEM-768";
#[cfg(feature = "pq-ml-kem-512")]
/// The name of the selected ML-KEM parameter set, for logs and measurement reports.
pub const PQ_KEM_SCHEME: &str = "ML-KEM-512";
#[cfg(feature = "pq-ml-kem-1024")]
/// The name of the selected ML-KEM parameter set, for logs and measurement reports.
pub const PQ_KEM_SCHEME: &str = "ML-KEM-1024";

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

/// The parameters of the selected ML-KEM set (FIPS 203, Table 2) that shape a ciphertext: the
/// modulus, the polynomial degree, the rank and the compression widths of the two ciphertext
/// components.
const MLKEM_Q: u32 = 3329;
const MLKEM_N: usize = 256;
#[cfg(not(any(feature = "pq-ml-kem-512", feature = "pq-ml-kem-1024")))]
const MLKEM_K: usize = 3;
#[cfg(feature = "pq-ml-kem-512")]
const MLKEM_K: usize = 2;
#[cfg(feature = "pq-ml-kem-1024")]
const MLKEM_K: usize = 4;
#[cfg(not(feature = "pq-ml-kem-1024"))]
const MLKEM_DU: u32 = 10;
#[cfg(feature = "pq-ml-kem-1024")]
const MLKEM_DU: u32 = 11;
#[cfg(not(feature = "pq-ml-kem-1024"))]
const MLKEM_DV: u32 = 4;
#[cfg(feature = "pq-ml-kem-1024")]
const MLKEM_DV: u32 = 5;
// A ciphertext is `k` polynomials compressed to `d_u` bits each followed by one compressed to `d_v`
// bits, so the parameters must reproduce the ciphertext length of the selected set.
const _: () = assert!(32 * (MLKEM_K * MLKEM_DU as usize + MLKEM_DV as usize) == PQ_KEM_CT_LEN);
/// The length, in bytes, of the `c1` component of a ciphertext, which precedes `c2`.
#[cfg(test)]
const MLKEM_C1_LEN: usize = MLKEM_K * MLKEM_N * (MLKEM_DU as usize) / 8;

/// FIPS 203 `Compress_d`, rounding `x * 2^d / q` to the nearest integer modulo `2^d`.
fn mlkem_compress(x: u32, d: u32) -> u32 {
	(((x << (d + 1)) + MLKEM_Q) / (2 * MLKEM_Q)) & ((1 << d) - 1)
}

/// Derives a dummy ML-KEM ciphertext from `seed` for padding a per-hop ciphertext list to its
/// fixed length. A real ciphertext is the compression of a pseudorandom pair of polynomials, so the
/// dummy is built the same way from uniformly random coefficients modulo `q`, compressed and
/// byte-encoded exactly as FIPS 203 encodes `c1` and `c2`. Uniformly random bytes would not do.
/// `Compress_10` maps the 3329 residues onto 1024 values, so 257 of the 10-bit values of a real
/// ciphertext are a third more likely than the other 767, and a hop counting them could tell the
/// padding from the real entries and learn the route length. No hop ever decapsulates a dummy.
pub(crate) fn dummy_ciphertext_from_seed(seed: &[u8; 32]) -> [u8; PQ_KEM_CT_LEN] {
	// Coefficients come from rejection sampling 12-bit draws of a ChaCha20 keystream, as FIPS 203
	// samples its public matrix. The 2048 draws of one buffer yield the `(k + 1) * 256` coefficients
	// needed except with negligible probability, and the stream is simply extended if they do not.
	let mut stream = ChaCha20::new(Key::new(*seed), Nonce::new([0; 12]), 0);
	let mut buf = [0u8; 4096];
	stream.apply_keystream(&mut buf);
	let mut pos = 0;
	let mut coeffs = [0u32; (MLKEM_K + 1) * MLKEM_N];
	let mut filled = 0;
	while filled < coeffs.len() {
		if pos + 2 > buf.len() {
			buf = [0u8; 4096];
			stream.apply_keystream(&mut buf);
			pos = 0;
		}
		let draw = (u16::from_le_bytes([buf[pos], buf[pos + 1]]) & 0x0fff) as u32;
		pos += 2;
		if draw < MLKEM_Q {
			coeffs[filled] = draw;
			filled += 1;
		}
	}
	// `ByteEncode_d` packs each compressed coefficient least significant bit first. The `k`
	// polynomials of `c1` use `d_u` bits each and the single polynomial of `c2` uses `d_v` bits.
	let mut ct = [0u8; PQ_KEM_CT_LEN];
	let mut out = 0;
	let mut acc = 0u32;
	let mut nbits = 0;
	for (i, &c) in coeffs.iter().enumerate() {
		let d = if i < MLKEM_K * MLKEM_N { MLKEM_DU } else { MLKEM_DV };
		acc |= mlkem_compress(c, d) << nbits;
		nbits += d;
		while nbits >= 8 {
			ct[out] = (acc & 0xff) as u8;
			out += 1;
			acc >>= 8;
			nbits -= 8;
		}
	}
	debug_assert_eq!(out, PQ_KEM_CT_LEN);
	ct
}

/// Test-only: the number of preimages under `Compress_du` of every compressed value, and the largest
/// such number. `Compress_10` maps the 3329 residues onto 1024 values, so 257 of them have four
/// preimages and the rest three; `Compress_11` maps them onto 2048 values, so 1281 have two and the
/// rest one.
#[cfg(test)]
fn compress_preimages() -> ([u8; 1 << MLKEM_DU], u8) {
	let mut preimages = [0u8; 1 << MLKEM_DU];
	for x in 0..MLKEM_Q {
		preimages[mlkem_compress(x, MLKEM_DU) as usize] += 1;
	}
	let max_preimages = *preimages.iter().max().unwrap();
	(preimages, max_preimages)
}

/// Test-only: the number of `c1` coefficients of `ct` whose compressed value has the larger number
/// of preimages under `Compress_du`. A real ML-KEM-768 ciphertext scores about 237 of 768 and
/// uniformly random bytes about 193, which is the counting test a hop could run on an entry of a
/// ciphertext list to tell padding from real ciphertexts.
#[cfg(test)]
pub(crate) fn max_preimage_count(ct: &[u8; PQ_KEM_CT_LEN]) -> usize {
	let (preimages, max_preimages) = compress_preimages();
	let mut count = 0;
	let mut acc = 0u32;
	let mut nbits = 0;
	for &byte in &ct[..MLKEM_C1_LEN] {
		acc |= (byte as u32) << nbits;
		nbits += 8;
		while nbits >= MLKEM_DU {
			if preimages[(acc & ((1 << MLKEM_DU) - 1)) as usize] == max_preimages {
				count += 1;
			}
			acc >>= MLKEM_DU;
			nbits -= MLKEM_DU;
		}
	}
	count
}

/// Test-only: the `max_preimage_count` a real ciphertext and uniformly random bytes are expected to
/// score, and the standard deviation of a real score, from the parameters of the selected set.
#[cfg(test)]
pub(crate) fn expected_max_preimage_counts() -> (f64, f64, f64) {
	let (preimages, max_preimages) = compress_preimages();
	let heavy = preimages.iter().filter(|&&p| p == max_preimages).count() as f64;
	let coeffs = (MLKEM_K * MLKEM_N) as f64;
	let p_real = heavy * max_preimages as f64 / MLKEM_Q as f64;
	let p_random = heavy / (1u64 << MLKEM_DU) as f64;
	(coeffs * p_real, coeffs * p_random, (coeffs * p_real * (1.0 - p_real)).sqrt())
}

/// Domain-separation tag for folding an ML-KEM shared secret into a blinded-path per-hop secret.
const PQ_BLINDED_PATH_MIX_TAG: &[u8] = b"LDK-PQ-blinded-path-hybrid-ss";

/// Mixes a classical per-hop ECDH secret with the per-hop ML-KEM shared secret into a single 32-byte
/// hybrid secret. The hybrid secret replaces the classical per-hop secret everywhere a blinded path
/// (onion-message or payment) derives keys from it (the encrypted recipient data key, the blinded
/// node id, and the next blinding point), so a quantum attacker who recovers the classical secret
/// by breaking the per-hop ECDH still cannot derive the hop's keys. This is a concatenation KDF:
/// SHA-256 over both secrets is indistinguishable from random as long as either input is, which
/// holds because the ML-KEM secret is quantum-resistant.
pub(crate) fn mix_blinded_path_secret(
	classical_ss: &[u8], kem_ss: &[u8; PQ_KEM_SS_LEN],
) -> [u8; 32] {
	let mut engine = Sha256::engine();
	engine.input(PQ_BLINDED_PATH_MIX_TAG);
	engine.input(classical_ss);
	engine.input(kem_ss);
	Sha256::from_engine(engine).to_byte_array()
}

/// Domain-separation tag for folding an ML-KEM shared secret into a payment-onion per-hop secret.
const PQ_PAYMENT_ONION_MIX_TAG: &[u8] = b"LDK-PQ-payment-onion-hybrid-ss";

/// Mixes a classical per-hop ECDH secret with the per-hop ML-KEM shared secret into a single 32-byte
/// hybrid secret for the BOLT 4 payment Sphinx onion. The hybrid secret replaces the classical per-hop
/// secret when deriving the onion `rho`/`mu` keys, so a quantum attacker who recovers the classical
/// secret by breaking the per-hop ECDH still cannot derive the hop's onion keys, and so cannot peel the
/// route or the per-hop payload. Like [`mix_blinded_path_secret`] this is a concatenation KDF: SHA-256
/// over both secrets is indistinguishable from random as long as either input is, which holds because
/// the ML-KEM secret is quantum-resistant. A distinct tag keeps it separate from the blinded-path mix.
pub(crate) fn mix_payment_onion_secret(
	classical_ss: &[u8], kem_ss: &[u8; PQ_KEM_SS_LEN],
) -> [u8; 32] {
	let mut engine = Sha256::engine();
	engine.input(PQ_PAYMENT_ONION_MIX_TAG);
	engine.input(classical_ss);
	engine.input(kem_ss);
	Sha256::from_engine(engine).to_byte_array()
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

	#[test]
	fn dummy_ciphertexts_match_the_real_distribution() {
		// Adversarial: a hop that counts the over-represented compressed coefficients of a list entry
		// must not be able to tell a dummy from a real ciphertext. Real ciphertexts and dummies must
		// score alike and both must score well above uniformly random bytes.
		let seed = |i: usize| {
			let mut seed = [0x5au8; 32];
			seed[..8].copy_from_slice(&(i as u64).to_le_bytes());
			seed
		};
		let (ek, _) = keypair_from_seed(&[1u8; 32]);
		let n = 64;
		let real: usize =
			(0..n).map(|i| max_preimage_count(&encapsulate(&ek, &seed(i)).unwrap().1)).sum();
		let dummy: usize =
			(0..n).map(|i| max_preimage_count(&dummy_ciphertext_from_seed(&seed(i)))).sum();
		let random: usize = (0..n)
			.map(|i| {
				let mut bytes = [0u8; PQ_KEM_CT_LEN];
				ChaCha20::new(Key::new(seed(i)), Nonce::new([0; 12]), 0)
					.apply_keystream(&mut bytes);
				max_preimage_count(&bytes)
			})
			.sum();
		// The expected scores follow from the parameters. A coefficient of a real ciphertext lands on a
		// value with the larger number of preimages with probability (values * preimages) / q, and a
		// uniformly random one with probability values / 2^d_u. For ML-KEM-768 that is about 237 and
		// 193 of 768 per entry, so over 64 entries the sums sit near 15180 and 12340 with a standard
		// deviation near 100. The margins below are several standard deviations wide at every set.
		let (expect_real, expect_random, _) = expected_max_preimage_counts();
		let (expect_real, expect_random) = (n as f64 * expect_real, n as f64 * expect_random);
		let gap = expect_real - expect_random;
		assert!((real as f64 - expect_real).abs() < gap / 3.0, "real {} expected {}", real, expect_real);
		assert!((real as f64 - dummy as f64).abs() < gap / 3.0, "real {} dummy {}", real, dummy);
		assert!(dummy as f64 > random as f64 + gap / 2.0, "dummy {} random {}", dummy, random);
		// Padding is deterministic in its seed and distinct across seeds.
		assert_eq!(dummy_ciphertext_from_seed(&seed(0)), dummy_ciphertext_from_seed(&seed(0)));
		assert_ne!(dummy_ciphertext_from_seed(&seed(0)), dummy_ciphertext_from_seed(&seed(1)));
	}
}
