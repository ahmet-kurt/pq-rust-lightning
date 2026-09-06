// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use crate::prelude::*;

use crate::ln::msgs;
use crate::ln::msgs::{ErrorAction, LightningError};
use crate::ln::wire;
use crate::ln::wire::Type;
use crate::sign::{NodeSigner, Recipient};
use crate::util::ser::Writeable;

use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::{Hash, HashEngine};

use bitcoin::hex::DisplayHex;

use bitcoin::secp256k1;
use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use chacha20_poly1305::{ChaCha20Poly1305, Key, Nonce};

use crate::crypto::utils::hkdf_extract_expand_twice;
use crate::util::ser::VecWriter;

#[cfg(feature = "post-quantum")]
use crate::crypto::pq_kem::{PQ_KEM_CT_LEN, PQ_KEM_DK_LEN, PQ_KEM_EK_LEN};

/// Maximum Lightning message data length according to
/// [BOLT-8](https://github.com/lightning/bolts/blob/v1.0/08-transport.md#lightning-message-specification)
/// and [BOLT-1](https://github.com/lightning/bolts/blob/master/01-messaging.md#lightning-message-format):
pub const LN_MAX_MSG_LEN: usize = ::core::u16::MAX as usize; // Must be equal to 65535

/// The (rough) size buffer to pre-allocate when encoding a message. Messages should reliably be
/// smaller than this size by at least 32 bytes or so.
pub const MSG_BUF_ALLOC_SIZE: usize = 2048;

// Sha256("Noise_XK_secp256k1_ChaChaPoly_SHA256")
const NOISE_CK: [u8; 32] = [
	0x26, 0x40, 0xf5, 0x2e, 0xeb, 0xcd, 0x9e, 0x88, 0x29, 0x58, 0x95, 0x1c, 0x79, 0x42, 0x50, 0xee,
	0xdb, 0x28, 0x00, 0x2c, 0x05, 0xd7, 0xdc, 0x2e, 0xa0, 0xf1, 0x95, 0x40, 0x60, 0x42, 0xca, 0xf1,
];
// Sha256(NOISE_CK || "lightning")
const NOISE_H: [u8; 32] = [
	0xd1, 0xfb, 0xf6, 0xde, 0xe4, 0xf6, 0x86, 0xf1, 0x32, 0xfd, 0x70, 0x2c, 0x4a, 0xbf, 0x8f, 0xba,
	0x4b, 0xb4, 0x20, 0xd8, 0x9d, 0x2a, 0x04, 0x8a, 0x3c, 0x4f, 0x4c, 0x09, 0x2e, 0x37, 0xb6, 0x76,
];

enum NoiseSecretKey<'a, 'b, NS: NodeSigner> {
	InMemory(&'a SecretKey),
	NodeSigner(&'b NS),
}

pub enum NextNoiseStep {
	ActOne,
	ActTwo,
	ActThree,
	NoiseComplete,
}

#[derive(PartialEq)]
enum NoiseStep {
	PreActOne,
	PostActOne,
	PostActTwo,
	// When done swap noise_state for NoiseState::Finished
}

struct BidirectionalNoiseState {
	h: [u8; 32],
	ck: [u8; 32],
}
enum DirectionalNoiseState {
	Outbound {
		ie: SecretKey,
	},
	Inbound {
		ie: Option<PublicKey>,     // filled in if state >= PostActOne
		re: Option<SecretKey>,     // filled in if state >= PostActTwo
		temp_k2: Option<[u8; 32]>, // filled in if state >= PostActTwo
	},
}
enum NoiseState {
	InProgress {
		state: NoiseStep,
		directional_state: DirectionalNoiseState,
		bidirectional_state: BidirectionalNoiseState,
	},
	Finished {
		sk: [u8; 32],
		sn: u64,
		sck: [u8; 32],
		rk: [u8; 32],
		rn: u64,
		rck: [u8; 32],
	},
}

// Per-connection state for the hybrid post-quantum (ML-KEM) BOLT 8 handshake. This rides alongside
// the classical Noise state; the classical handshake is left byte-for-byte unchanged and this is
// only populated for connections established on a post-quantum endpoint.
#[cfg(feature = "post-quantum")]
enum PqHandshakeState {
	Outbound {
		// The responder's pinned static ML-KEM encapsulation key, supplied out of band (e.g. from
		// the gossip pin). We encapsulate to it in act one to authenticate the responder.
		rs_kem_ek: [u8; PQ_KEM_EK_LEN],
		// Per-connection randomness seed; expanded into the static-encapsulation and ephemeral-keygen
		// sub-seeds. Fresh per connection in production (forward secrecy), fixed in tests.
		pq_seed: [u8; 32],
		// Our ephemeral ML-KEM decapsulation key, generated in act one and used to recover the
		// forward-secret shared secret from the responder's ciphertext in act two.
		eph_dk: Option<[u8; PQ_KEM_DK_LEN]>,
	},
	Inbound {
		// Per-connection randomness seed for the ephemeral encapsulation we send in act two.
		pq_seed: [u8; 32],
	},
}

pub struct PeerChannelEncryptor {
	their_node_id: Option<PublicKey>, // filled in for outbound, or inbound after noise_state is Finished

	noise_state: NoiseState,

	#[cfg(feature = "post-quantum")]
	pq: Option<PqHandshakeState>,
}

impl PeerChannelEncryptor {
	pub fn new_outbound(
		their_node_id: PublicKey, ephemeral_key: SecretKey,
	) -> PeerChannelEncryptor {
		let mut sha = Sha256::engine();
		sha.input(&NOISE_H);
		sha.input(&their_node_id.serialize()[..]);
		let h = Sha256::from_engine(sha).to_byte_array();

		PeerChannelEncryptor {
			their_node_id: Some(their_node_id),
			noise_state: NoiseState::InProgress {
				state: NoiseStep::PreActOne,
				directional_state: DirectionalNoiseState::Outbound { ie: ephemeral_key },
				bidirectional_state: BidirectionalNoiseState { h, ck: NOISE_CK },
			},
			#[cfg(feature = "post-quantum")]
			pq: None,
		}
	}

	/// Builds an outbound encryptor for a hybrid post-quantum handshake. `responder_kem_key` is the
	/// responder's pinned static ML-KEM encapsulation key (supplied out of band, e.g. the gossip
	/// pin) and `pq_seed` is fresh per-connection randomness.
	#[cfg(feature = "post-quantum")]
	pub fn new_outbound_pq(
		their_node_id: PublicKey, ephemeral_key: SecretKey,
		responder_kem_key: [u8; PQ_KEM_EK_LEN], pq_seed: [u8; 32],
	) -> PeerChannelEncryptor {
		let mut res = PeerChannelEncryptor::new_outbound(their_node_id, ephemeral_key);
		res.pq =
			Some(PqHandshakeState::Outbound { rs_kem_ek: responder_kem_key, pq_seed, eph_dk: None });
		res
	}

	pub fn new_inbound<NS: NodeSigner>(node_signer: &NS) -> PeerChannelEncryptor {
		let mut sha = Sha256::engine();
		sha.input(&NOISE_H);
		let our_node_id = node_signer.get_node_id(Recipient::Node).unwrap();
		sha.input(&our_node_id.serialize()[..]);
		let h = Sha256::from_engine(sha).to_byte_array();

		PeerChannelEncryptor {
			their_node_id: None,
			noise_state: NoiseState::InProgress {
				state: NoiseStep::PreActOne,
				directional_state: DirectionalNoiseState::Inbound {
					ie: None,
					re: None,
					temp_k2: None,
				},
				bidirectional_state: BidirectionalNoiseState { h, ck: NOISE_CK },
			},
			#[cfg(feature = "post-quantum")]
			pq: None,
		}
	}

	/// Builds an inbound encryptor for a hybrid post-quantum handshake (a connection accepted on a
	/// post-quantum endpoint). `pq_seed` is fresh per-connection randomness.
	#[cfg(feature = "post-quantum")]
	pub fn new_inbound_pq<NS: NodeSigner>(
		node_signer: &NS, pq_seed: [u8; 32],
	) -> PeerChannelEncryptor {
		let mut res = PeerChannelEncryptor::new_inbound(node_signer);
		res.pq = Some(PqHandshakeState::Inbound { pq_seed });
		res
	}

	#[inline]
	fn encrypt_with_ad(res: &mut [u8], n: u64, key: &[u8; 32], h: &[u8], plaintext: &[u8]) {
		let mut nonce = [0; 12];
		nonce[4..].copy_from_slice(&n.to_le_bytes()[..]);
		res[0..plaintext.len()].copy_from_slice(plaintext);

		let chacha = ChaCha20Poly1305::new(Key::new(*key), Nonce::new(nonce));
		let tag = chacha.encrypt(&mut res[0..plaintext.len()], Some(h));

		res[plaintext.len()..].copy_from_slice(&tag);
	}

	#[inline]
	/// Encrypts the message in res[offset..] in-place and pushes a 16-byte tag onto the end of
	/// res.
	fn encrypt_in_place_with_ad(
		res: &mut Vec<u8>, offset: usize, n: u64, key: &[u8; 32], h: &[u8],
	) {
		let mut nonce = [0; 12];
		nonce[4..].copy_from_slice(&n.to_le_bytes()[..]);

		let chacha = ChaCha20Poly1305::new(Key::new(*key), Nonce::new(nonce));
		let tag = chacha.encrypt(&mut res[offset..], Some(h));
		res.extend_from_slice(&tag);
	}

	fn decrypt_in_place_with_ad(
		inout: &mut [u8], n: u64, key: &[u8; 32], h: &[u8],
	) -> Result<(), LightningError> {
		let mut nonce = [0; 12];
		nonce[4..].copy_from_slice(&n.to_le_bytes()[..]);

		let chacha = ChaCha20Poly1305::new(Key::new(*key), Nonce::new(nonce));
		let (inout, tag) = inout.split_at_mut(inout.len() - 16);
		let mut decrypt_tag = [0; 16];
		decrypt_tag.copy_from_slice(tag);
		if chacha.decrypt(inout, decrypt_tag, Some(h)).is_err() {
			return Err(LightningError {
				err: "Bad MAC".to_owned(),
				action: msgs::ErrorAction::DisconnectPeer { msg: None },
			});
		}
		Ok(())
	}

	#[inline]
	fn decrypt_with_ad(
		res: &mut [u8], n: u64, key: &[u8; 32], h: &[u8], cyphertext: &[u8],
	) -> Result<(), LightningError> {
		let mut nonce = [0; 12];
		nonce[4..].copy_from_slice(&n.to_le_bytes()[..]);

		let (data, hmac) = cyphertext.split_at(cyphertext.len() - 16);
		let mut tag = [0; 16];
		tag.copy_from_slice(hmac);
		res.copy_from_slice(data);

		let mac_check =
			ChaCha20Poly1305::new(Key::new(*key), Nonce::new(nonce)).decrypt(res, tag, Some(h));
		mac_check.map_err(|_| LightningError {
			err: "Bad MAC".to_owned(),
			action: msgs::ErrorAction::DisconnectPeer { msg: None },
		})
	}

	#[inline]
	fn hkdf(state: &mut BidirectionalNoiseState, ss: SharedSecret) -> [u8; 32] {
		let (t1, t2) = hkdf_extract_expand_twice(&state.ck, ss.as_ref());
		state.ck = t1;
		t2
	}

	// Mixes opaque handshake bytes (an ML-KEM ciphertext or ephemeral public key) into the
	// transcript hash, exactly as the classical acts mix the ephemeral pubkeys and AEAD tags.
	#[cfg(feature = "post-quantum")]
	#[inline]
	fn mix_hash(state: &mut BidirectionalNoiseState, data: &[u8]) {
		let mut sha = Sha256::engine();
		sha.input(&state.h);
		sha.input(data);
		state.h = Sha256::from_engine(sha).to_byte_array();
	}

	// Folds an ML-KEM shared secret into the chaining key, exactly as `hkdf` folds an ECDH shared
	// secret. We advance the chaining key only; the next classical act derives its AEAD key from it.
	#[cfg(feature = "post-quantum")]
	#[inline]
	fn mix_kem_secret(state: &mut BidirectionalNoiseState, ss: &[u8; 32]) {
		let (t1, _) = hkdf_extract_expand_twice(&state.ck, ss);
		state.ck = t1;
	}

	#[inline]
	fn outbound_noise_act<T: secp256k1::Signing>(
		secp_ctx: &Secp256k1<T>, state: &mut BidirectionalNoiseState, our_key: &SecretKey,
		their_key: &PublicKey,
	) -> ([u8; 50], [u8; 32]) {
		let our_pub = PublicKey::from_secret_key(secp_ctx, &our_key);

		let mut sha = Sha256::engine();
		sha.input(&state.h);
		sha.input(&our_pub.serialize()[..]);
		state.h = Sha256::from_engine(sha).to_byte_array();

		let ss = SharedSecret::new(&their_key, &our_key);
		let temp_k = PeerChannelEncryptor::hkdf(state, ss);

		let mut res = [0; 50];
		res[1..34].copy_from_slice(&our_pub.serialize()[..]);
		PeerChannelEncryptor::encrypt_with_ad(&mut res[34..], 0, &temp_k, &state.h, &[0; 0]);

		let mut sha = Sha256::engine();
		sha.input(&state.h);
		sha.input(&res[34..]);
		state.h = Sha256::from_engine(sha).to_byte_array();

		(res, temp_k)
	}

	#[inline]
	fn inbound_noise_act<'a, 'b, NS: NodeSigner>(
		state: &mut BidirectionalNoiseState, act: &[u8], secret_key: NoiseSecretKey<'a, 'b, NS>,
	) -> Result<(PublicKey, [u8; 32]), LightningError> {
		assert_eq!(act.len(), 50);

		if act[0] != 0 {
			return Err(LightningError {
				err: format!("Unknown handshake version number {}", act[0]),
				action: msgs::ErrorAction::DisconnectPeer { msg: None },
			});
		}

		let their_pub = match PublicKey::from_slice(&act[1..34]) {
			Err(_) => {
				return Err(LightningError {
					err: format!("Invalid public key {}", &act[1..34].as_hex()),
					action: msgs::ErrorAction::DisconnectPeer { msg: None },
				})
			},
			Ok(key) => key,
		};

		let mut sha = Sha256::engine();
		sha.input(&state.h);
		sha.input(&their_pub.serialize()[..]);
		state.h = Sha256::from_engine(sha).to_byte_array();

		let ss = match secret_key {
			NoiseSecretKey::InMemory(secret_key) => SharedSecret::new(&their_pub, secret_key),
			NoiseSecretKey::NodeSigner(node_signer) => {
				node_signer.ecdh(Recipient::Node, &their_pub, None).map_err(|_| LightningError {
					err: "Failed to derive shared secret".to_owned(),
					action: msgs::ErrorAction::DisconnectPeer { msg: None },
				})?
			},
		};
		let temp_k = PeerChannelEncryptor::hkdf(state, ss);

		let mut dec = [0; 0];
		PeerChannelEncryptor::decrypt_with_ad(&mut dec, 0, &temp_k, &state.h, &act[34..])?;

		let mut sha = Sha256::engine();
		sha.input(&state.h);
		sha.input(&act[34..]);
		state.h = Sha256::from_engine(sha).to_byte_array();

		Ok((their_pub, temp_k))
	}

	pub fn get_act_one<C: secp256k1::Signing>(&mut self, secp_ctx: &Secp256k1<C>) -> [u8; 50] {
		match self.noise_state {
			NoiseState::InProgress {
				ref mut state,
				ref directional_state,
				ref mut bidirectional_state,
			} => match directional_state {
				&DirectionalNoiseState::Outbound { ref ie } => {
					if *state != NoiseStep::PreActOne {
						panic!("Requested act at wrong step");
					}

					let (res, _) = PeerChannelEncryptor::outbound_noise_act(
						secp_ctx,
						bidirectional_state,
						&ie,
						&self.their_node_id.unwrap(),
					);
					*state = NoiseStep::PostActOne;
					res
				},
				_ => panic!("Wrong direction for act"),
			},
			_ => panic!("Cannot get act one after noise handshake completes"),
		}
	}

	pub fn process_act_one_with_keys<C: secp256k1::Signing, NS: NodeSigner>(
		&mut self, act_one: &[u8], node_signer: &NS, our_ephemeral: SecretKey,
		secp_ctx: &Secp256k1<C>,
	) -> Result<[u8; 50], LightningError> {
		assert_eq!(act_one.len(), 50);

		match self.noise_state {
			NoiseState::InProgress {
				ref mut state,
				ref mut directional_state,
				ref mut bidirectional_state,
			} => match directional_state {
				&mut DirectionalNoiseState::Inbound { ref mut ie, ref mut re, ref mut temp_k2 } => {
					if *state != NoiseStep::PreActOne {
						panic!("Requested act at wrong step");
					}

					let (their_pub, _) = PeerChannelEncryptor::inbound_noise_act(
						bidirectional_state,
						act_one,
						NoiseSecretKey::NodeSigner(node_signer),
					)?;
					ie.get_or_insert(their_pub);

					re.get_or_insert(our_ephemeral);

					let (res, temp_k) = PeerChannelEncryptor::outbound_noise_act(
						secp_ctx,
						bidirectional_state,
						&re.unwrap(),
						&ie.unwrap(),
					);
					*temp_k2 = Some(temp_k);
					*state = NoiseStep::PostActTwo;
					Ok(res)
				},
				_ => panic!("Wrong direction for act"),
			},
			_ => panic!("Cannot get act one after noise handshake completes"),
		}
	}

	pub fn process_act_two<NS: NodeSigner>(
		&mut self, act_two: &[u8], node_signer: &NS,
	) -> Result<([u8; 66], PublicKey), LightningError> {
		assert_eq!(act_two.len(), 50);

		let final_hkdf;
		let ck;
		let res: [u8; 66] = match self.noise_state {
			NoiseState::InProgress {
				ref state,
				ref directional_state,
				ref mut bidirectional_state,
			} => match directional_state {
				&DirectionalNoiseState::Outbound { ref ie } => {
					if *state != NoiseStep::PostActOne {
						panic!("Requested act at wrong step");
					}

					let (re, temp_k2) = PeerChannelEncryptor::inbound_noise_act(
						bidirectional_state,
						act_two,
						NoiseSecretKey::<NS>::InMemory(&ie),
					)?;

					let mut res = [0; 66];
					let our_node_id =
						node_signer.get_node_id(Recipient::Node).map_err(|_| LightningError {
							err: "Failed to encrypt message".to_owned(),
							action: msgs::ErrorAction::DisconnectPeer { msg: None },
						})?;

					PeerChannelEncryptor::encrypt_with_ad(
						&mut res[1..50],
						1,
						&temp_k2,
						&bidirectional_state.h,
						&our_node_id.serialize()[..],
					);

					let mut sha = Sha256::engine();
					sha.input(&bidirectional_state.h);
					sha.input(&res[1..50]);
					bidirectional_state.h = Sha256::from_engine(sha).to_byte_array();

					let ss = node_signer.ecdh(Recipient::Node, &re, None).map_err(|_| {
						LightningError {
							err: "Failed to derive shared secret".to_owned(),
							action: msgs::ErrorAction::DisconnectPeer { msg: None },
						}
					})?;
					let temp_k = PeerChannelEncryptor::hkdf(bidirectional_state, ss);

					PeerChannelEncryptor::encrypt_with_ad(
						&mut res[50..],
						0,
						&temp_k,
						&bidirectional_state.h,
						&[0; 0],
					);
					final_hkdf = hkdf_extract_expand_twice(&bidirectional_state.ck, &[0; 0]);
					ck = bidirectional_state.ck.clone();
					res
				},
				_ => panic!("Wrong direction for act"),
			},
			_ => panic!("Cannot get act one after noise handshake completes"),
		};

		let (sk, rk) = final_hkdf;
		self.noise_state = NoiseState::Finished { sk, sn: 0, sck: ck.clone(), rk, rn: 0, rck: ck };

		Ok((res, self.their_node_id.unwrap().clone()))
	}

	pub fn process_act_three(&mut self, act_three: &[u8]) -> Result<PublicKey, LightningError> {
		assert_eq!(act_three.len(), 66);

		let final_hkdf;
		let ck;
		match self.noise_state {
			NoiseState::InProgress {
				ref state,
				ref directional_state,
				ref mut bidirectional_state,
			} => match directional_state {
				&DirectionalNoiseState::Inbound { ie: _, ref re, ref temp_k2 } => {
					if *state != NoiseStep::PostActTwo {
						panic!("Requested act at wrong step");
					}
					if act_three[0] != 0 {
						return Err(LightningError {
							err: format!("Unknown handshake version number {}", act_three[0]),
							action: msgs::ErrorAction::DisconnectPeer { msg: None },
						});
					}

					let mut their_node_id = [0; 33];
					PeerChannelEncryptor::decrypt_with_ad(
						&mut their_node_id,
						1,
						&temp_k2.unwrap(),
						&bidirectional_state.h,
						&act_three[1..50],
					)?;
					self.their_node_id = Some(match PublicKey::from_slice(&their_node_id) {
						Ok(key) => key,
						Err(_) => {
							return Err(LightningError {
								err: format!("Bad node_id from peer, {}", &their_node_id.as_hex()),
								action: msgs::ErrorAction::DisconnectPeer { msg: None },
							})
						},
					});

					let mut sha = Sha256::engine();
					sha.input(&bidirectional_state.h);
					sha.input(&act_three[1..50]);
					bidirectional_state.h = Sha256::from_engine(sha).to_byte_array();

					let ss = SharedSecret::new(&self.their_node_id.unwrap(), &re.unwrap());
					let temp_k = PeerChannelEncryptor::hkdf(bidirectional_state, ss);

					PeerChannelEncryptor::decrypt_with_ad(
						&mut [0; 0],
						0,
						&temp_k,
						&bidirectional_state.h,
						&act_three[50..],
					)?;
					final_hkdf = hkdf_extract_expand_twice(&bidirectional_state.ck, &[0; 0]);
					ck = bidirectional_state.ck.clone();
				},
				_ => panic!("Wrong direction for act"),
			},
			_ => panic!("Cannot get act one after noise handshake completes"),
		}

		let (rk, sk) = final_hkdf;
		self.noise_state = NoiseState::Finished { sk, sn: 0, sck: ck.clone(), rk, rn: 0, rck: ck };

		Ok(self.their_node_id.unwrap().clone())
	}

	/// Returns whether this encryptor is performing a hybrid post-quantum handshake.
	#[cfg(feature = "post-quantum")]
	pub fn is_post_quantum(&self) -> bool {
		self.pq.is_some()
	}

	// Derives a 32-byte sub-seed from the per-connection seed under a domain-separation tag, so the
	// static-encapsulation, ephemeral-keygen, and ephemeral-encapsulation randomness are independent.
	#[cfg(feature = "post-quantum")]
	fn pq_subseed(seed: &[u8; 32], tag: &[u8]) -> [u8; 32] {
		let mut sha = Sha256::engine();
		sha.input(tag);
		sha.input(seed);
		Sha256::from_engine(sha).to_byte_array()
	}

	/// Builds the post-quantum act one: the classical 50-byte act one, followed by an ML-KEM
	/// ciphertext encapsulated to the responder's pinned static key (authentication) and our fresh
	/// ephemeral ML-KEM public key (forward secrecy). Both are bound into the transcript hash; the
	/// static shared secret is folded into the chaining key now, the ephemeral one in act two.
	#[cfg(feature = "post-quantum")]
	pub fn get_act_one_pq<C: secp256k1::Signing>(&mut self, secp_ctx: &Secp256k1<C>) -> Vec<u8> {
		let (rs_kem_ek, pq_seed) = match &self.pq {
			Some(PqHandshakeState::Outbound { rs_kem_ek, pq_seed, .. }) => (*rs_kem_ek, *pq_seed),
			_ => panic!("get_act_one_pq on a non-post-quantum-outbound encryptor"),
		};

		let (classical, ct_s, eph_ek, eph_dk) = match self.noise_state {
			NoiseState::InProgress {
				ref mut state,
				ref directional_state,
				ref mut bidirectional_state,
			} => match directional_state {
				&DirectionalNoiseState::Outbound { ref ie } => {
					if *state != NoiseStep::PreActOne {
						panic!("Requested act at wrong step");
					}

					let (classical, _) = PeerChannelEncryptor::outbound_noise_act(
						secp_ctx,
						bidirectional_state,
						&ie,
						&self.their_node_id.unwrap(),
					);
					*state = NoiseStep::PostActOne;

					// Encapsulate to the responder's pinned static ML-KEM key (responder
					// authentication): only the holder of the matching secret can recover this.
					let encaps_seed =
						PeerChannelEncryptor::pq_subseed(&pq_seed, b"LDK-PQ-XK-static-encaps");
					let (ss_s, ct_s) = crate::crypto::pq_kem::encapsulate(&rs_kem_ek, &encaps_seed)
						.expect("pinned responder ML-KEM key must be well-formed");
					PeerChannelEncryptor::mix_hash(bidirectional_state, &ct_s);
					PeerChannelEncryptor::mix_kem_secret(bidirectional_state, &ss_s);

					// Attach a fresh ephemeral ML-KEM public key (forward secrecy); the responder
					// encapsulates to it in act two.
					let eph_seed = PeerChannelEncryptor::pq_subseed(&pq_seed, b"LDK-PQ-XK-ephemeral");
					let (eph_ek, eph_dk) = crate::crypto::pq_kem::keypair_from_seed(&eph_seed);
					PeerChannelEncryptor::mix_hash(bidirectional_state, &eph_ek);

					(classical, ct_s, eph_ek, eph_dk)
				},
				_ => panic!("Wrong direction for act"),
			},
			_ => panic!("Cannot get act one after noise handshake completes"),
		};

		if let Some(PqHandshakeState::Outbound { eph_dk: slot, .. }) = &mut self.pq {
			*slot = Some(eph_dk);
		}

		let mut res = Vec::with_capacity(50 + PQ_KEM_CT_LEN + PQ_KEM_EK_LEN);
		res.extend_from_slice(&classical);
		res.extend_from_slice(&ct_s);
		res.extend_from_slice(&eph_ek);
		res
	}

	/// Processes the post-quantum act one and returns the post-quantum act two. Decapsulates the
	/// static ciphertext with our node's ML-KEM key (proving we are the pinned responder) and
	/// encapsulates to the initiator's ephemeral key (forward secrecy).
	#[cfg(feature = "post-quantum")]
	pub fn process_act_one_with_keys_pq<C: secp256k1::Signing, NS: NodeSigner>(
		&mut self, act_one: &[u8], node_signer: &NS, our_ephemeral: SecretKey,
		secp_ctx: &Secp256k1<C>,
	) -> Result<Vec<u8>, LightningError> {
		assert_eq!(act_one.len(), 50 + PQ_KEM_CT_LEN + PQ_KEM_EK_LEN);

		let pq_seed = match &self.pq {
			Some(PqHandshakeState::Inbound { pq_seed }) => *pq_seed,
			_ => panic!("process_act_one_with_keys_pq on a non-post-quantum-inbound encryptor"),
		};

		let mut ct_s = [0u8; PQ_KEM_CT_LEN];
		ct_s.copy_from_slice(&act_one[50..50 + PQ_KEM_CT_LEN]);
		let mut eph_ek = [0u8; PQ_KEM_EK_LEN];
		eph_ek.copy_from_slice(&act_one[50 + PQ_KEM_CT_LEN..]);

		match self.noise_state {
			NoiseState::InProgress {
				ref mut state,
				ref mut directional_state,
				ref mut bidirectional_state,
			} => match directional_state {
				&mut DirectionalNoiseState::Inbound { ref mut ie, ref mut re, ref mut temp_k2 } => {
					if *state != NoiseStep::PreActOne {
						panic!("Requested act at wrong step");
					}

					let (their_pub, _) = PeerChannelEncryptor::inbound_noise_act(
						bidirectional_state,
						&act_one[0..50],
						NoiseSecretKey::NodeSigner(node_signer),
					)?;
					ie.get_or_insert(their_pub);

					// Recover the static shared secret by decapsulating with our node's ML-KEM key. If
					// the initiator pinned a key we do not hold, implicit rejection yields a mismatched
					// secret and the initiator rejects our act two; None here means our signer cannot
					// decapsulate at all.
					PeerChannelEncryptor::mix_hash(bidirectional_state, &ct_s);
					let ss_s = node_signer.pq_kem_decapsulate(&ct_s).ok_or(LightningError {
						err: "Failed to decapsulate post-quantum static shared secret".to_owned(),
						action: msgs::ErrorAction::DisconnectPeer { msg: None },
					})?;
					PeerChannelEncryptor::mix_kem_secret(bidirectional_state, &ss_s);
					PeerChannelEncryptor::mix_hash(bidirectional_state, &eph_ek);

					re.get_or_insert(our_ephemeral);
					let (classical, temp_k) = PeerChannelEncryptor::outbound_noise_act(
						secp_ctx,
						bidirectional_state,
						&re.unwrap(),
						&ie.unwrap(),
					);
					*temp_k2 = Some(temp_k);

					// Encapsulate to the initiator's ephemeral key (forward secrecy).
					let encaps_seed =
						PeerChannelEncryptor::pq_subseed(&pq_seed, b"LDK-PQ-XK-ephemeral-encaps");
					let (ss_e, ct_e) = crate::crypto::pq_kem::encapsulate(&eph_ek, &encaps_seed)
						.ok_or(LightningError {
							err: "Invalid post-quantum ephemeral key in act one".to_owned(),
							action: msgs::ErrorAction::DisconnectPeer { msg: None },
						})?;
					PeerChannelEncryptor::mix_hash(bidirectional_state, &ct_e);
					PeerChannelEncryptor::mix_kem_secret(bidirectional_state, &ss_e);

					*state = NoiseStep::PostActTwo;

					let mut res = Vec::with_capacity(50 + PQ_KEM_CT_LEN);
					res.extend_from_slice(&classical);
					res.extend_from_slice(&ct_e);
					Ok(res)
				},
				_ => panic!("Wrong direction for act"),
			},
			_ => panic!("Cannot get act one after noise handshake completes"),
		}
	}

	/// Processes the post-quantum act two and returns the (classical, 66-byte) act three plus the
	/// responder's node id. Decapsulates the responder's ephemeral ciphertext (forward secrecy);
	/// act three itself carries no extra post-quantum data.
	#[cfg(feature = "post-quantum")]
	pub fn process_act_two_pq<NS: NodeSigner>(
		&mut self, act_two: &[u8], node_signer: &NS,
	) -> Result<([u8; 66], PublicKey), LightningError> {
		assert_eq!(act_two.len(), 50 + PQ_KEM_CT_LEN);

		let eph_dk = match &self.pq {
			Some(PqHandshakeState::Outbound { eph_dk: Some(dk), .. }) => *dk,
			_ => panic!("process_act_two_pq before get_act_one_pq, or on a non-PQ encryptor"),
		};

		let mut ct_e = [0u8; PQ_KEM_CT_LEN];
		ct_e.copy_from_slice(&act_two[50..]);

		let final_hkdf;
		let ck;
		let res: [u8; 66] = match self.noise_state {
			NoiseState::InProgress {
				ref state,
				ref directional_state,
				ref mut bidirectional_state,
			} => match directional_state {
				&DirectionalNoiseState::Outbound { ref ie } => {
					if *state != NoiseStep::PostActOne {
						panic!("Requested act at wrong step");
					}

					let (re, temp_k2) = PeerChannelEncryptor::inbound_noise_act(
						bidirectional_state,
						&act_two[0..50],
						NoiseSecretKey::<NS>::InMemory(&ie),
					)?;

					// Recover the forward-secret shared secret from the responder's ciphertext.
					PeerChannelEncryptor::mix_hash(bidirectional_state, &ct_e);
					let ss_e = crate::crypto::pq_kem::decapsulate(&eph_dk, &ct_e).ok_or(
						LightningError {
							err: "Failed to decapsulate post-quantum ephemeral shared secret"
								.to_owned(),
							action: msgs::ErrorAction::DisconnectPeer { msg: None },
						},
					)?;
					PeerChannelEncryptor::mix_kem_secret(bidirectional_state, &ss_e);

					// Build the classical act three (encrypt our static key, then the `se` step).
					let mut res = [0; 66];
					let our_node_id =
						node_signer.get_node_id(Recipient::Node).map_err(|_| LightningError {
							err: "Failed to encrypt message".to_owned(),
							action: msgs::ErrorAction::DisconnectPeer { msg: None },
						})?;

					PeerChannelEncryptor::encrypt_with_ad(
						&mut res[1..50],
						1,
						&temp_k2,
						&bidirectional_state.h,
						&our_node_id.serialize()[..],
					);

					let mut sha = Sha256::engine();
					sha.input(&bidirectional_state.h);
					sha.input(&res[1..50]);
					bidirectional_state.h = Sha256::from_engine(sha).to_byte_array();

					let ss = node_signer.ecdh(Recipient::Node, &re, None).map_err(|_| {
						LightningError {
							err: "Failed to derive shared secret".to_owned(),
							action: msgs::ErrorAction::DisconnectPeer { msg: None },
						}
					})?;
					let temp_k = PeerChannelEncryptor::hkdf(bidirectional_state, ss);

					PeerChannelEncryptor::encrypt_with_ad(
						&mut res[50..],
						0,
						&temp_k,
						&bidirectional_state.h,
						&[0; 0],
					);
					final_hkdf = hkdf_extract_expand_twice(&bidirectional_state.ck, &[0; 0]);
					ck = bidirectional_state.ck.clone();
					res
				},
				_ => panic!("Wrong direction for act"),
			},
			_ => panic!("Cannot get act one after noise handshake completes"),
		};

		let (sk, rk) = final_hkdf;
		self.noise_state = NoiseState::Finished { sk, sn: 0, sck: ck.clone(), rk, rn: 0, rck: ck };

		Ok((res, self.their_node_id.unwrap().clone()))
	}

	/// Builds sendable bytes for a message.
	///
	/// `msgbuf` must begin with 16 + 2 dummy/0 bytes, which will be filled with the encrypted
	/// message length and its MAC. It should then be followed by the message bytes themselves
	/// (including the two byte message type).
	///
	/// For effeciency, the [`Vec::capacity`] should be at least 16 bytes larger than the
	/// [`Vec::len`], to avoid reallocating for the message MAC, which will be appended to the vec.
	fn encrypt_message_with_header_0s(&mut self, msgbuf: &mut Vec<u8>) -> Result<(), ()> {
		let msg_len = msgbuf.len() - 16 - 2;
		if msg_len > LN_MAX_MSG_LEN {
			debug_assert!(false, "Attempted to encrypt message longer than 65535 bytes!");
			return Err(());
		}

		match self.noise_state {
			NoiseState::Finished { ref mut sk, ref mut sn, ref mut sck, rk: _, rn: _, rck: _ } => {
				if *sn >= 1000 {
					let (new_sck, new_sk) = hkdf_extract_expand_twice(sck, sk);
					*sck = new_sck;
					*sk = new_sk;
					*sn = 0;
				}

				Self::encrypt_with_ad(
					&mut msgbuf[0..16 + 2],
					*sn,
					sk,
					&[0; 0],
					&(msg_len as u16).to_be_bytes(),
				);
				*sn += 1;

				Self::encrypt_in_place_with_ad(msgbuf, 16 + 2, *sn, sk, &[0; 0]);
				*sn += 1;
				Ok(())
			},
			_ => {
				debug_assert!(
					false,
					"Tried to encrypt a message prior to noise handshake completion"
				);
				Err(())
			},
		}
	}

	/// Encrypts the given pre-serialized message, returning the encrypted version.
	pub fn encrypt_buffer(&mut self, mut msg: MessageBuf) -> Vec<u8> {
		self.encrypt_message_with_header_0s(&mut msg.0)
			.expect("Length was checked in buf constructor and peer should be live");
		msg.0
	}

	/// Encrypts the given message, returning the encrypted version.
	///
	/// Returns `Err(())` if the length of `message`, once encoded, is greater than 65535 or if the
	/// Noise handshake has not finished.
	pub(crate) fn encrypt_message<T: wire::Type>(
		&mut self, message: wire::Message<T>,
	) -> Result<Vec<u8>, ()> {
		// Allocate a buffer with 2KB, fitting most common messages. Reserve the first 16+2 bytes
		// for the 2-byte message type prefix and its MAC.
		let mut res = VecWriter(Vec::with_capacity(MSG_BUF_ALLOC_SIZE));
		res.0.resize(16 + 2, 0);

		message.type_id().write(&mut res).expect("In-memory messages must never fail to serialize");
		message.write(&mut res).expect("In-memory messages must never fail to serialize");

		self.encrypt_message_with_header_0s(&mut res.0)?;
		Ok(res.0)
	}

	/// Decrypts a message length header from the remote peer.
	/// panics if noise handshake has not yet finished or msg.len() != 18
	pub fn decrypt_length_header(&mut self, msg: &[u8]) -> Result<u16, LightningError> {
		assert_eq!(msg.len(), 16 + 2);

		match self.noise_state {
			NoiseState::Finished { sk: _, sn: _, sck: _, ref mut rk, ref mut rn, ref mut rck } => {
				if *rn >= 1000 {
					let (new_rck, new_rk) = hkdf_extract_expand_twice(rck, rk);
					*rck = new_rck;
					*rk = new_rk;
					*rn = 0;
				}

				let mut res = [0; 2];
				Self::decrypt_with_ad(&mut res, *rn, rk, &[0; 0], msg)?;
				*rn += 1;
				Ok(u16::from_be_bytes(res))
			},
			_ => panic!("Tried to decrypt a message prior to noise handshake completion"),
		}
	}

	/// Decrypts the given message up to msg.len() - 16. Bytes after msg.len() - 16 will be left
	/// undefined (as they contain the Poly1305 tag bytes).
	///
	/// Returns an error if `msg.len() > 65535 + 16`.
	pub fn decrypt_message(&mut self, msg: &mut [u8]) -> Result<(), LightningError> {
		if msg.len() > LN_MAX_MSG_LEN + 16 {
			debug_assert!(false, "Attempted to decrypt message longer than 65535 + 16 bytes!");
			return Err(LightningError {
				err: "Somehow had an oversized message to decrypt".to_owned(),
				action: ErrorAction::DisconnectPeer { msg: None },
			});
		}

		match self.noise_state {
			NoiseState::Finished { sk: _, sn: _, sck: _, ref rk, ref mut rn, rck: _ } => {
				Self::decrypt_in_place_with_ad(&mut msg[..], *rn, rk, &[0; 0])?;
				*rn += 1;
				Ok(())
			},
			_ => panic!("Tried to decrypt a message prior to noise handshake completion"),
		}
	}

	pub fn get_noise_step(&self) -> NextNoiseStep {
		match self.noise_state {
			NoiseState::InProgress { ref state, .. } => match state {
				&NoiseStep::PreActOne => NextNoiseStep::ActOne,
				&NoiseStep::PostActOne => NextNoiseStep::ActTwo,
				&NoiseStep::PostActTwo => NextNoiseStep::ActThree,
			},
			NoiseState::Finished { .. } => NextNoiseStep::NoiseComplete,
		}
	}

	pub fn is_ready_for_encryption(&self) -> bool {
		match self.noise_state {
			NoiseState::InProgress { .. } => false,
			NoiseState::Finished { .. } => true,
		}
	}
}

/// A buffer which stores an encoded message (including the two message-type bytes) with some
/// padding to allow for future encryption/MACing.
pub struct MessageBuf(Vec<u8>);
impl MessageBuf {
	/// The total allocated space for this message
	pub fn capacity(&self) -> usize {
		self.0.capacity()
	}

	/// Creates a new buffer from an encoded message (i.e. the two message-type bytes followed by
	/// the message contents).
	///
	/// Returns `Err(())` if the message is longer than 2^16 - 1.
	pub fn from_encoded(encoded_msg: &[u8]) -> Result<Self, ()> {
		if encoded_msg.len() > LN_MAX_MSG_LEN {
			debug_assert!(false, "Attempted to encrypt message longer than 65535 bytes!");
			return Err(());
		}
		// In addition to the message (continaing the two message type bytes), we also have to add
		// the message length header (and its MAC) and the message MAC.
		let mut res = Vec::with_capacity(encoded_msg.len() + 16 * 2 + 2);
		res.resize(encoded_msg.len() + 16 + 2, 0);
		res[16 + 2..].copy_from_slice(&encoded_msg);
		Ok(Self(res))
	}

	#[cfg(test)]
	pub(crate) fn fetch_encoded_msg_with_type_pfx(&self) -> Vec<u8> {
		self.0.clone().split_off(16 + 2)
	}
}

#[cfg(test)]
mod tests {
	use super::{MessageBuf, LN_MAX_MSG_LEN};

	use bitcoin::hex::FromHex;
	use bitcoin::secp256k1::Secp256k1;
	use bitcoin::secp256k1::{PublicKey, SecretKey};

	use crate::ln::peer_channel_encryptor::{NoiseState, PeerChannelEncryptor};
	use crate::util::test_utils::TestNodeSigner;

	#[cfg(feature = "post-quantum")]
	use crate::crypto::pq_kem::{PQ_KEM_CT_LEN, PQ_KEM_EK_LEN};
	#[cfg(feature = "post-quantum")]
	use crate::sign::{KeysManager, NodeSigner, Recipient};

	fn get_outbound_peer_for_initiator_test_vectors() -> PeerChannelEncryptor {
		let hex = "028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7";
		let their_node_id = PublicKey::from_slice(&<Vec<u8>>::from_hex(hex).unwrap()[..]).unwrap();
		let secp_ctx = Secp256k1::signing_only();

		let hex = "1212121212121212121212121212121212121212121212121212121212121212";
		let mut outbound_peer = PeerChannelEncryptor::new_outbound(
			their_node_id,
			SecretKey::from_slice(&<Vec<u8>>::from_hex(hex).unwrap()[..]).unwrap(),
		);
		let hex = "00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a";
		assert_eq!(outbound_peer.get_act_one(&secp_ctx)[..], <Vec<u8>>::from_hex(hex).unwrap()[..]);
		outbound_peer
	}

	fn get_inbound_peer_for_test_vectors() -> PeerChannelEncryptor {
		// transport-responder successful handshake
		let hex = "2121212121212121212121212121212121212121212121212121212121212121";
		let our_node_id = SecretKey::from_slice(&<Vec<u8>>::from_hex(hex).unwrap()[..]).unwrap();
		let hex = "2222222222222222222222222222222222222222222222222222222222222222";
		let our_ephemeral = SecretKey::from_slice(&<Vec<u8>>::from_hex(hex).unwrap()[..]).unwrap();
		let secp_ctx = Secp256k1::new();
		let node_signer = TestNodeSigner::new(our_node_id);

		let mut inbound_peer = PeerChannelEncryptor::new_inbound(&&node_signer);

		let hex = "00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a";
		let act_one = <Vec<u8>>::from_hex(hex).unwrap().to_vec();
		let hex = "0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae";
		assert_eq!(
			inbound_peer
				.process_act_one_with_keys(
					&act_one[..],
					&&node_signer,
					our_ephemeral.clone(),
					&secp_ctx
				)
				.unwrap()[..],
			<Vec<u8>>::from_hex(hex).unwrap()[..]
		);

		let hex = "00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba";
		let act_three = <Vec<u8>>::from_hex(hex).unwrap().to_vec();
		// test vector doesn't specify the initiator static key, but it's the same as the one
		// from transport-initiator successful handshake
		let hex = "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";
		assert_eq!(
			inbound_peer.process_act_three(&act_three[..]).unwrap().serialize()[..],
			<Vec<u8>>::from_hex(hex).unwrap()[..]
		);

		match inbound_peer.noise_state {
			NoiseState::Finished { sk, sn, sck, rk, rn, rck } => {
				let hex = "bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442";
				assert_eq!(sk, <Vec<u8>>::from_hex(hex).unwrap()[..]);
				assert_eq!(sn, 0);
				let hex = "919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01";
				assert_eq!(sck, <Vec<u8>>::from_hex(hex).unwrap()[..]);
				let hex = "969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9";
				assert_eq!(rk, <Vec<u8>>::from_hex(hex).unwrap()[..]);
				assert_eq!(rn, 0);
				let hex = "919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01";
				assert_eq!(rck, <Vec<u8>>::from_hex(hex).unwrap()[..]);
			},
			_ => panic!(),
		}

		inbound_peer
	}

	#[test]
	fn noise_initiator_test_vectors() {
		let hex = "1111111111111111111111111111111111111111111111111111111111111111";
		let our_node_id = SecretKey::from_slice(&<Vec<u8>>::from_hex(hex).unwrap()[..]).unwrap();
		let node_signer = TestNodeSigner::new(our_node_id);

		{
			// transport-initiator successful handshake
			let mut outbound_peer = get_outbound_peer_for_initiator_test_vectors();

			let hex = "0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae";
			let act_two = <Vec<u8>>::from_hex(hex).unwrap().to_vec();
			let hex = "00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba";
			assert_eq!(
				outbound_peer.process_act_two(&act_two[..], &&node_signer).unwrap().0[..],
				<Vec<u8>>::from_hex(hex).unwrap()[..]
			);

			match outbound_peer.noise_state {
				NoiseState::Finished { sk, sn, sck, rk, rn, rck } => {
					let hex = "969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9";
					assert_eq!(sk, <Vec<u8>>::from_hex(hex).unwrap()[..]);
					assert_eq!(sn, 0);
					let hex = "919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01";
					assert_eq!(sck, <Vec<u8>>::from_hex(hex).unwrap()[..]);
					let hex = "bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442";
					assert_eq!(rk, <Vec<u8>>::from_hex(hex).unwrap()[..]);
					assert_eq!(rn, 0);
					let hex = "919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01";
					assert_eq!(rck, <Vec<u8>>::from_hex(hex).unwrap()[..]);
				},
				_ => panic!(),
			}
		}
		{
			// transport-initiator act2 short read test
			// Can't actually test this cause process_act_two requires you pass the right length!
		}
		{
			// transport-initiator act2 bad version test
			let mut outbound_peer = get_outbound_peer_for_initiator_test_vectors();

			let hex = "0102466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae";
			let act_two = <Vec<u8>>::from_hex(hex).unwrap().to_vec();
			assert!(outbound_peer.process_act_two(&act_two[..], &&node_signer).is_err());
		}

		{
			// transport-initiator act2 bad key serialization test
			let mut outbound_peer = get_outbound_peer_for_initiator_test_vectors();

			let hex = "0004466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae";
			let act_two = <Vec<u8>>::from_hex(hex).unwrap().to_vec();
			assert!(outbound_peer.process_act_two(&act_two[..], &&node_signer).is_err());
		}

		{
			// transport-initiator act2 bad MAC test
			let mut outbound_peer = get_outbound_peer_for_initiator_test_vectors();

			let hex = "0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730af";
			let act_two = <Vec<u8>>::from_hex(hex).unwrap().to_vec();
			assert!(outbound_peer.process_act_two(&act_two[..], &&node_signer).is_err());
		}
	}

	#[test]
	fn noise_responder_test_vectors() {
		let hex = "2121212121212121212121212121212121212121212121212121212121212121";
		let our_node_id = SecretKey::from_slice(&<Vec<u8>>::from_hex(hex).unwrap()[..]).unwrap();
		let hex = "2222222222222222222222222222222222222222222222222222222222222222";
		let our_ephemeral = SecretKey::from_slice(&<Vec<u8>>::from_hex(hex).unwrap()[..]).unwrap();
		let secp_ctx = Secp256k1::new();
		let node_signer = TestNodeSigner::new(our_node_id);

		{
			let _ = get_inbound_peer_for_test_vectors();
		}
		{
			// transport-responder act1 short read test
			// Can't actually test this cause process_act_one requires you pass the right length!
		}
		{
			// transport-responder act1 bad version test
			let mut inbound_peer = PeerChannelEncryptor::new_inbound(&&node_signer);

			let hex = "01036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a";
			let act_one = <Vec<u8>>::from_hex(hex).unwrap().to_vec();
			assert!(inbound_peer
				.process_act_one_with_keys(
					&act_one[..],
					&&node_signer,
					our_ephemeral.clone(),
					&secp_ctx
				)
				.is_err());
		}
		{
			// transport-responder act1 bad key serialization test
			let mut inbound_peer = PeerChannelEncryptor::new_inbound(&&node_signer);

			let hex = "00046360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a";
			let act_one = <Vec<u8>>::from_hex(hex).unwrap().to_vec();
			assert!(inbound_peer
				.process_act_one_with_keys(
					&act_one[..],
					&&node_signer,
					our_ephemeral.clone(),
					&secp_ctx
				)
				.is_err());
		}
		{
			// transport-responder act1 bad MAC test
			let mut inbound_peer = PeerChannelEncryptor::new_inbound(&&node_signer);

			let hex = "00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6b";
			let act_one = <Vec<u8>>::from_hex(hex).unwrap().to_vec();
			assert!(inbound_peer
				.process_act_one_with_keys(
					&act_one[..],
					&&node_signer,
					our_ephemeral.clone(),
					&secp_ctx
				)
				.is_err());
		}
		{
			// transport-responder act3 bad version test
			let mut inbound_peer = PeerChannelEncryptor::new_inbound(&&node_signer);

			let hex = "00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a";
			let act_one = <Vec<u8>>::from_hex(hex).unwrap().to_vec();
			let hex = "0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae";
			assert_eq!(
				inbound_peer
					.process_act_one_with_keys(
						&act_one[..],
						&&node_signer,
						our_ephemeral.clone(),
						&secp_ctx
					)
					.unwrap()[..],
				<Vec<u8>>::from_hex(hex).unwrap()[..]
			);

			let hex = "01b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba";
			let act_three = <Vec<u8>>::from_hex(hex).unwrap().to_vec();
			assert!(inbound_peer.process_act_three(&act_three[..]).is_err());
		}
		{
			// transport-responder act3 short read test
			// Can't actually test this cause process_act_three requires you pass the right length!
		}
		{
			// transport-responder act3 bad MAC for ciphertext test
			let mut inbound_peer = PeerChannelEncryptor::new_inbound(&&node_signer);

			let hex = "00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a";
			let act_one = <Vec<u8>>::from_hex(hex).unwrap().to_vec();
			let hex = "0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae";
			assert_eq!(
				inbound_peer
					.process_act_one_with_keys(
						&act_one[..],
						&&node_signer,
						our_ephemeral.clone(),
						&secp_ctx
					)
					.unwrap()[..],
				<Vec<u8>>::from_hex(hex).unwrap()[..]
			);

			let hex = "00c9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba";
			let act_three = <Vec<u8>>::from_hex(hex).unwrap().to_vec();
			assert!(inbound_peer.process_act_three(&act_three[..]).is_err());
		}
		{
			// transport-responder act3 bad rs test
			let mut inbound_peer = PeerChannelEncryptor::new_inbound(&&node_signer);

			let hex = "00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a";
			let act_one = <Vec<u8>>::from_hex(hex).unwrap().to_vec();
			let hex = "0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae";
			assert_eq!(
				inbound_peer
					.process_act_one_with_keys(
						&act_one[..],
						&&node_signer,
						our_ephemeral.clone(),
						&secp_ctx
					)
					.unwrap()[..],
				<Vec<u8>>::from_hex(hex).unwrap()[..]
			);

			let hex = "00bfe3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa2235536ad09a8ee351870c2bb7f78b754a26c6cef79a98d25139c856d7efd252c2ae73c";
			let act_three = <Vec<u8>>::from_hex(hex).unwrap().to_vec();
			assert!(inbound_peer.process_act_three(&act_three[..]).is_err());
		}
		{
			// transport-responder act3 bad MAC test
			let mut inbound_peer = PeerChannelEncryptor::new_inbound(&&node_signer);

			let hex = "00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a";
			let act_one = <Vec<u8>>::from_hex(hex).unwrap().to_vec();
			let hex = "0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae";
			assert_eq!(
				inbound_peer
					.process_act_one_with_keys(
						&act_one[..],
						&&node_signer,
						our_ephemeral.clone(),
						&secp_ctx
					)
					.unwrap()[..],
				<Vec<u8>>::from_hex(hex).unwrap()[..]
			);

			let hex = "00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139bb";
			let act_three = <Vec<u8>>::from_hex(hex).unwrap().to_vec();
			assert!(inbound_peer.process_act_three(&act_three[..]).is_err());
		}
	}

	#[test]
	fn message_encryption_decryption_test_vectors() {
		// We use the same keys as the initiator and responder test vectors, so we copy those tests
		// here and use them to encrypt.
		let mut outbound_peer = get_outbound_peer_for_initiator_test_vectors();

		{
			let hex = "1111111111111111111111111111111111111111111111111111111111111111";
			let our_node_id =
				SecretKey::from_slice(&<Vec<u8>>::from_hex(hex).unwrap()[..]).unwrap();
			let node_signer = TestNodeSigner::new(our_node_id);

			let hex = "0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae";
			let act_two = <Vec<u8>>::from_hex(hex).unwrap().to_vec();
			let hex = "00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba";
			assert_eq!(
				outbound_peer.process_act_two(&act_two[..], &&node_signer).unwrap().0[..],
				<Vec<u8>>::from_hex(hex).unwrap()[..]
			);

			match outbound_peer.noise_state {
				NoiseState::Finished { sk, sn, sck, rk, rn, rck } => {
					let hex = "969ab31b4d288cedf6218839b27a3e2140827047f2c0f01bf5c04435d43511a9";
					assert_eq!(sk, <Vec<u8>>::from_hex(hex).unwrap()[..]);
					assert_eq!(sn, 0);
					let hex = "919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01";
					assert_eq!(sck, <Vec<u8>>::from_hex(hex).unwrap()[..]);
					let hex = "bb9020b8965f4df047e07f955f3c4b88418984aadc5cdb35096b9ea8fa5c3442";
					assert_eq!(rk, <Vec<u8>>::from_hex(hex).unwrap()[..]);
					assert_eq!(rn, 0);
					let hex = "919219dbb2920afa8db80f9a51787a840bcf111ed8d588caf9ab4be716e42b01";
					assert_eq!(rck, <Vec<u8>>::from_hex(hex).unwrap()[..]);
				},
				_ => panic!(),
			}
		}

		let mut inbound_peer = get_inbound_peer_for_test_vectors();

		for i in 0..1005 {
			let msg = [0x68, 0x65, 0x6c, 0x6c, 0x6f];
			let msgbuf = MessageBuf::from_encoded(&msg).unwrap();
			let mut res = outbound_peer.encrypt_buffer(msgbuf);
			assert_eq!(res.len(), 5 + 2 * 16 + 2);

			let len_header = res[0..2 + 16].to_vec();
			assert_eq!(
				inbound_peer.decrypt_length_header(&len_header[..]).unwrap() as usize,
				msg.len()
			);

			if i == 0 {
				let hex = "cf2b30ddf0cf3f80e7c35a6e6730b59fe802473180f396d88a8fb0db8cbcf25d2f214cf9ea1d95";
				assert_eq!(res, <Vec<u8>>::from_hex(hex).unwrap());
			} else if i == 1 {
				let hex = "72887022101f0b6753e0c7de21657d35a4cb2a1f5cde2650528bbc8f837d0f0d7ad833b1a256a1";
				assert_eq!(res, <Vec<u8>>::from_hex(hex).unwrap());
			} else if i == 500 {
				let hex = "178cb9d7387190fa34db9c2d50027d21793c9bc2d40b1e14dcf30ebeeeb220f48364f7a4c68bf8";
				assert_eq!(res, <Vec<u8>>::from_hex(hex).unwrap());
			} else if i == 501 {
				let hex = "1b186c57d44eb6de4c057c49940d79bb838a145cb528d6e8fd26dbe50a60ca2c104b56b60e45bd";
				assert_eq!(res, <Vec<u8>>::from_hex(hex).unwrap());
			} else if i == 1000 {
				let hex = "4a2f3cc3b5e78ddb83dcb426d9863d9d9a723b0337c89dd0b005d89f8d3c05c52b76b29b740f09";
				assert_eq!(res, <Vec<u8>>::from_hex(hex).unwrap());
			} else if i == 1001 {
				let hex = "2ecd8c8a5629d0d02ab457a0fdd0f7b90a192cd46be5ecb6ca570bfc5e268338b1a16cf4ef2d36";
				assert_eq!(res, <Vec<u8>>::from_hex(hex).unwrap());
			}

			inbound_peer.decrypt_message(&mut res[2 + 16..]).unwrap();
			assert_eq!(res[2 + 16..res.len() - 16], msg[..]);
		}
	}

	#[test]
	fn max_msg_len_limit_value() {
		assert_eq!(LN_MAX_MSG_LEN, 65535);
		assert_eq!(LN_MAX_MSG_LEN, ::core::u16::MAX as usize);
	}

	#[test]
	#[cfg(debug_assertions)]
	#[should_panic(expected = "Attempted to encrypt message longer than 65535 bytes!")]
	fn max_message_len_encryption() {
		let msg = [4u8; LN_MAX_MSG_LEN + 1];
		let _ = MessageBuf::from_encoded(&msg);
	}

	#[test]
	#[cfg(not(debug_assertions))]
	fn max_message_len_encryption() {
		let msg = [4u8; LN_MAX_MSG_LEN + 1];
		assert!(MessageBuf::from_encoded(&msg).is_err());
	}

	#[test]
	#[cfg(debug_assertions)]
	#[should_panic(expected = "Attempted to decrypt message longer than 65535 + 16 bytes!")]
	fn max_message_len_decryption() {
		let mut inbound_peer = get_inbound_peer_for_test_vectors();

		// MSG should not exceed LN_MAX_MSG_LEN + 16
		let mut msg = [4u8; LN_MAX_MSG_LEN + 17];
		let _ = inbound_peer.decrypt_message(&mut msg);
	}

	#[test]
	#[cfg(not(debug_assertions))]
	fn max_message_len_decryption() {
		let mut inbound_peer = get_inbound_peer_for_test_vectors();

		// MSG should not exceed LN_MAX_MSG_LEN + 16
		let mut msg = [4u8; LN_MAX_MSG_LEN + 17];
		assert!(inbound_peer.decrypt_message(&mut msg).is_err());
	}

	// Sets up an initiator/responder keys pair plus the ephemeral keys for a hybrid post-quantum
	// handshake. The responder's static ML-KEM key is taken from its `KeysManager` (the anchor the
	// initiator pins out of band).
	#[cfg(feature = "post-quantum")]
	fn pq_test_setup(
	) -> (KeysManager, KeysManager, PublicKey, [u8; PQ_KEM_EK_LEN], SecretKey, SecretKey) {
		let initiator_ks = KeysManager::new(&[42u8; 32], 0, 0, false);
		let responder_ks = KeysManager::new(&[43u8; 32], 0, 0, false);
		let responder_node_id = responder_ks.get_node_id(Recipient::Node).unwrap();
		let responder_kem = responder_ks.get_pq_kem_node_id().unwrap();
		let initiator_eph = SecretKey::from_slice(&[2u8; 32]).unwrap();
		let responder_eph = SecretKey::from_slice(&[4u8; 32]).unwrap();
		(initiator_ks, responder_ks, responder_node_id, responder_kem, initiator_eph, responder_eph)
	}

	#[cfg(feature = "post-quantum")]
	fn finished_keys(enc: &PeerChannelEncryptor) -> ([u8; 32], [u8; 32]) {
		match enc.noise_state {
			NoiseState::Finished { sk, rk, .. } => (sk, rk),
			_ => panic!("handshake not finished"),
		}
	}

	#[cfg(feature = "post-quantum")]
	#[test]
	fn pq_handshake_completes_and_message_round_trips() {
		let secp = Secp256k1::new();
		let (initiator_ks, responder_ks, responder_node_id, responder_kem, init_eph, resp_eph) =
			pq_test_setup();

		let mut outbound = PeerChannelEncryptor::new_outbound_pq(
			responder_node_id,
			init_eph,
			responder_kem,
			[7u8; 32],
		);
		let mut inbound = PeerChannelEncryptor::new_inbound_pq(&responder_ks, [9u8; 32]);
		assert!(outbound.is_post_quantum());
		assert!(inbound.is_post_quantum());

		let act_one = outbound.get_act_one_pq(&secp);
		assert_eq!(act_one.len(), 50 + PQ_KEM_CT_LEN + PQ_KEM_EK_LEN);
		let act_two = inbound
			.process_act_one_with_keys_pq(&act_one, &responder_ks, resp_eph, &secp)
			.unwrap();
		assert_eq!(act_two.len(), 50 + PQ_KEM_CT_LEN);
		let (act_three, resp_id) = outbound.process_act_two_pq(&act_two, &initiator_ks).unwrap();
		assert_eq!(act_three.len(), 66);
		assert_eq!(resp_id, responder_node_id);
		let init_id = inbound.process_act_three(&act_three).unwrap();
		assert_eq!(init_id, initiator_ks.get_node_id(Recipient::Node).unwrap());

		// Both sides must derive matching, swapped transport keys.
		let (i_sk, i_rk) = finished_keys(&outbound);
		let (r_sk, r_rk) = finished_keys(&inbound);
		assert_eq!(i_sk, r_rk);
		assert_eq!(i_rk, r_sk);

		// A real message must round-trip over the established transport.
		let msg = [0x68, 0x65, 0x6c, 0x6c, 0x6f];
		let mut enc = outbound.encrypt_buffer(MessageBuf::from_encoded(&msg).unwrap());
		let len = inbound.decrypt_length_header(&enc[..2 + 16]).unwrap();
		assert_eq!(len as usize, msg.len());
		inbound.decrypt_message(&mut enc[2 + 16..]).unwrap();
		assert_eq!(enc[2 + 16..enc.len() - 16], msg[..]);
	}

	#[cfg(feature = "post-quantum")]
	#[test]
	fn pq_handshake_is_deterministic() {
		let secp = Secp256k1::new();
		let run = || {
			let (initiator_ks, responder_ks, responder_node_id, responder_kem, init_eph, resp_eph) =
				pq_test_setup();
			let mut outbound = PeerChannelEncryptor::new_outbound_pq(
				responder_node_id,
				init_eph,
				responder_kem,
				[7u8; 32],
			);
			let mut inbound = PeerChannelEncryptor::new_inbound_pq(&responder_ks, [9u8; 32]);
			let a1 = outbound.get_act_one_pq(&secp);
			let a2 = inbound
				.process_act_one_with_keys_pq(&a1, &responder_ks, resp_eph, &secp)
				.unwrap();
			let (a3, _) = outbound.process_act_two_pq(&a2, &initiator_ks).unwrap();
			(a1, a2, a3.to_vec(), finished_keys(&outbound))
		};
		assert_eq!(run(), run());
	}

	#[cfg(feature = "post-quantum")]
	#[test]
	fn pq_responder_auth_rejects_key_substitution() {
		// A quantum man-in-the-middle can forge the classical key but not the pinned ML-KEM key. We
		// model this as the initiator binding to a static KEM key the responder does not hold: the
		// session is bound to that key, so the handshake must fail rather than complete.
		let secp = Secp256k1::new();
		let (initiator_ks, responder_ks, responder_node_id, _real_kem, init_eph, resp_eph) =
			pq_test_setup();
		let wrong_kem = KeysManager::new(&[99u8; 32], 0, 0, false).get_pq_kem_node_id().unwrap();

		let mut outbound =
			PeerChannelEncryptor::new_outbound_pq(responder_node_id, init_eph, wrong_kem, [7u8; 32]);
		let mut inbound = PeerChannelEncryptor::new_inbound_pq(&responder_ks, [9u8; 32]);

		let act_one = outbound.get_act_one_pq(&secp);
		let act_two = inbound
			.process_act_one_with_keys_pq(&act_one, &responder_ks, resp_eph, &secp)
			.unwrap();
		// The responder decapsulated with its real key, diverging the chaining key, so the
		// initiator rejects act two.
		assert!(outbound.process_act_two_pq(&act_two, &initiator_ks).is_err());
	}

	#[cfg(feature = "post-quantum")]
	#[test]
	fn pq_rejects_tampered_static_ciphertext() {
		let secp = Secp256k1::new();
		let (initiator_ks, responder_ks, responder_node_id, responder_kem, init_eph, resp_eph) =
			pq_test_setup();
		let mut outbound = PeerChannelEncryptor::new_outbound_pq(
			responder_node_id,
			init_eph,
			responder_kem,
			[7u8; 32],
		);
		let mut inbound = PeerChannelEncryptor::new_inbound_pq(&responder_ks, [9u8; 32]);

		let mut act_one = outbound.get_act_one_pq(&secp);
		act_one[60] ^= 0x01; // flip a byte inside the static ciphertext (offset 50..50+CT_LEN)
		let act_two = inbound
			.process_act_one_with_keys_pq(&act_one, &responder_ks, resp_eph, &secp)
			.unwrap();
		assert!(outbound.process_act_two_pq(&act_two, &initiator_ks).is_err());
	}

	#[cfg(feature = "post-quantum")]
	#[test]
	fn pq_rejects_tampered_ephemeral_key() {
		let secp = Secp256k1::new();
		let (initiator_ks, responder_ks, responder_node_id, responder_kem, init_eph, resp_eph) =
			pq_test_setup();
		let mut outbound = PeerChannelEncryptor::new_outbound_pq(
			responder_node_id,
			init_eph,
			responder_kem,
			[7u8; 32],
		);
		let mut inbound = PeerChannelEncryptor::new_inbound_pq(&responder_ks, [9u8; 32]);

		let mut act_one = outbound.get_act_one_pq(&secp);
		let last = act_one.len() - 1; // flip a byte inside the ephemeral key (tail of act one)
		act_one[last] ^= 0x01;
		let act_two = inbound
			.process_act_one_with_keys_pq(&act_one, &responder_ks, resp_eph, &secp)
			.unwrap();
		// The ephemeral key is bound into the transcript before the act-two tag, so the initiator
		// rejects act two.
		assert!(outbound.process_act_two_pq(&act_two, &initiator_ks).is_err());
	}

	#[cfg(feature = "post-quantum")]
	#[test]
	fn pq_rejects_tampered_ephemeral_ciphertext() {
		let secp = Secp256k1::new();
		let (initiator_ks, responder_ks, responder_node_id, responder_kem, init_eph, resp_eph) =
			pq_test_setup();
		let mut outbound = PeerChannelEncryptor::new_outbound_pq(
			responder_node_id,
			init_eph,
			responder_kem,
			[7u8; 32],
		);
		let mut inbound = PeerChannelEncryptor::new_inbound_pq(&responder_ks, [9u8; 32]);

		let act_one = outbound.get_act_one_pq(&secp);
		let mut act_two = inbound
			.process_act_one_with_keys_pq(&act_one, &responder_ks, resp_eph, &secp)
			.unwrap();
		act_two[60] ^= 0x01; // flip a byte inside the ephemeral ciphertext (offset 50..50+CT_LEN)
		// The ephemeral ciphertext is folded after the act-two tag, so the initiator cannot detect
		// the tamper locally, but the transport keys diverge and the responder rejects act three.
		let (act_three, _) = outbound.process_act_two_pq(&act_two, &initiator_ks).unwrap();
		assert!(inbound.process_act_three(&act_three).is_err());
	}

	#[cfg(feature = "post-quantum")]
	#[test]
	fn pq_measurements_transport() {
		let secp = Secp256k1::new();
		let (initiator_ks, responder_ks, responder_node_id, responder_kem, init_eph, resp_eph) =
			pq_test_setup();
		let mut outbound = PeerChannelEncryptor::new_outbound_pq(
			responder_node_id,
			init_eph,
			responder_kem,
			[7u8; 32],
		);
		let mut inbound = PeerChannelEncryptor::new_inbound_pq(&responder_ks, [9u8; 32]);
		let act_one = outbound.get_act_one_pq(&secp);
		let act_two = inbound
			.process_act_one_with_keys_pq(&act_one, &responder_ks, resp_eph, &secp)
			.unwrap();
		let (act_three, _) = outbound.process_act_two_pq(&act_two, &initiator_ks).unwrap();
		println!(
			"PQ: BOLT 8 hybrid ({}) handshake sizes: act_one 50 -> {} B, act_two 50 -> {} B, act_three {} B (unchanged)",
			crate::crypto::pq_kem::PQ_KEM_SCHEME,
			act_one.len(),
			act_two.len(),
			act_three.len(),
		);
		println!(
			"PQ: {} wire sizes: encapsulation key {} B, ciphertext {} B",
			crate::crypto::pq_kem::PQ_KEM_SCHEME, PQ_KEM_EK_LEN, PQ_KEM_CT_LEN,
		);

		// ML-KEM operation timings (debug/test profile; use a release benchmark for
		// publication-quality numbers).
		use std::time::Instant;
		let n = 200;
		let start = Instant::now();
		for i in 0..n {
			let _ = crate::crypto::pq_kem::keypair_from_seed(&[i as u8; 32]);
		}
		let keygen_us = start.elapsed().as_micros() as f64 / n as f64;

		let (ek, dk) = crate::crypto::pq_kem::keypair_from_seed(&[1u8; 32]);
		let start = Instant::now();
		for i in 0..n {
			let _ = crate::crypto::pq_kem::encapsulate(&ek, &[i as u8; 32]);
		}
		let encaps_us = start.elapsed().as_micros() as f64 / n as f64;

		let (_, ct) = crate::crypto::pq_kem::encapsulate(&ek, &[5u8; 32]).unwrap();
		let start = Instant::now();
		for _ in 0..n {
			let _ = crate::crypto::pq_kem::decapsulate(&dk, &ct);
		}
		let decaps_us = start.elapsed().as_micros() as f64 / n as f64;
		println!(
			"PQ: {} (test profile, avg/{}): keygen {:.0} us, encaps {:.0} us, decaps {:.0} us",
			crate::crypto::pq_kem::PQ_KEM_SCHEME, n, keygen_us, encaps_us, decaps_us,
		);
	}
}
