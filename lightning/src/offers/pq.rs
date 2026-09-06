// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Post-quantum carrier records and helpers for BOLT 12 (offers).
//!
//! Adds a hybrid ML-DSA (FIPS 204) signature to the BOLT 12 `invoice` alongside the classical
//! Schnorr signature. The issuer commits to a per-offer ML-DSA public key in the `offer` (the
//! out-of-band trust root the payer already holds); the responding `invoice` carries an ML-DSA
//! signature that the payer verifies against that committed key. The offer-side commitment rides
//! inside the offer metadata record and the invoice-side records ride as odd records in the
//! experimental invoice TLV range, written into the unsigned invoice so the classical signature
//! covers them and a vanilla node round-trips them untouched and verifies the classical signature
//! byte-for-byte (interop). The per-offer ML-DSA key is derived from the node's symmetric offer
//! key (not from any published discrete-log key), so it is unlinkable across offers and is not
//! recoverable by a Shor adversary.

use crate::crypto::pq_kem::PQ_KEM_CT_LEN;
use crate::io::Cursor;
use crate::offers::merkle::SIGNATURE_TYPES;
use crate::offers::nonce::Nonce;
use crate::offers::offer::OFFER_METADATA_TYPE;
use crate::sign::pq::{PQ_PUBLIC_KEY_LEN, PQ_SIGNATURE_LEN};
use crate::util::ser::{BigSize, Readable, Writeable};

use bitcoin::hashes::hmac::{Hmac, HmacEngine};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::hashes::{Hash, HashEngine};

use crate::prelude::*;

/// Magic prefix distinguishing a post-quantum offer metadata value from ordinary opaque metadata.
///
/// The offer's post-quantum records (the issuer's ML-DSA public key and the introduction-node
/// ML-KEM ciphertexts of its post-quantum blinded paths) ride inside the offer metadata record
/// rather than as unknown odd records. The metadata record is a typed field that a vanilla payer
/// copies verbatim into the `invoice_request` (and that the responder echoes back into the
/// `invoice`), so both LDK's stateless-verification HMACs and Core Lightning's requirement that
/// the invoice mirror the request byte for byte treat it consistently; an unknown odd record
/// satisfies neither, as an LDK payer derives its keys from typed fields only while echoing raw
/// bytes. A derived-keys offer, the only kind that commits a post-quantum key, never carries its
/// own metadata record, so the field is free. The value is the magic, the ML-DSA public key, then
/// a sequence of `(BigSize path_index, PQ_KEM_CT_LEN-byte ciphertext)` entries, one per
/// post-quantum path, so a payer can pair each ciphertext with the right `BlindedMessagePath`.
pub(super) const PQ_OFFER_METADATA_MAGIC: &[u8; 4] = b"PQO1";

/// Odd TLV record type carrying the ML-DSA signature on a `Bolt12Invoice`. It sits in the
/// experimental invoice TLV range and is written into the unsigned invoice, so the classical
/// merkle root (and thus the classical signature) covers it and every implementation computes the
/// same root; a vanilla node ignores the unknown odd record. The record cannot sit in the
/// signature TLV range (240..=1000, excluded from the root per BOLT 12) because eclair's root
/// computation includes unknown records in that range, which would diverge from the signer's.
pub(super) const INVOICE_PQ_SIGNATURE_TYPE: u64 = 3_000_000_241;

/// Odd TLV record type carrying the per-path ML-KEM ciphertext lists for a `Bolt12Invoice`'s
/// post-quantum blinded payment paths, so a remote payer that scans an offer and receives the invoice
/// can recover the ciphertext list each path needs (the in-memory `BlindedPaymentPath::kem_ct`). Like
/// the ML-DSA signature record it sits in the experimental invoice TLV range, written into the
/// unsigned invoice so the classical signature covers it, and is ignored by vanilla nodes. It is
/// excluded from the ML-DSA signable bytes; tampering fails closed at the affected blinded hop (a
/// wrong ciphertext yields a wrong route-blinding secret) and a stripped record breaks the classical
/// signature and leaves the payer with classical-looking paths, which fail closed at the hops and
/// which a post-quantum-required sender refuses to use (`UserConfig::require_post_quantum_payments`).
/// The value is a sequence of `(BigSize path_index, BigSize len, len-byte ciphertext list)` entries,
/// one per post-quantum payment path.
pub(super) const INVOICE_PQ_KEM_CT_TYPE: u64 = 3_000_000_243;

/// Typed experimental TLV record carrying the introduction-node ML-KEM ciphertexts of a `Refund`'s
/// post-quantum blinded message paths, so a responder that parses the refund from its encoded form
/// can reply with the invoice over the hybrid path. Unlike the invoice records above it cannot be
/// an unknown odd record: the refund's payer metadata HMAC covers every raw record the responder
/// echoes back in the invoice, so only a field present in the refund's typed TLV stream at
/// metadata-derivation time recomputes consistently. Being covered also means a stripped record
/// fails the payer's stateless verification when the invoice echoes the refund back. A vanilla
/// responder ignores the unknown odd field and echoes it verbatim. The value is a sequence of
/// `(BigSize path_index, PQ_KEM_CT_LEN-byte ciphertext)` entries, one per post-quantum path.
pub(super) const REFUND_PQ_KEM_CT_TYPE: u64 = 2_000_000_243;

/// Domain separator (16 bytes, matching the BOLT 12 IV convention) for deriving a node's per-offer
/// ML-DSA seed as `HMAC(offers_base_key, PQ_OFFER_IV || nonce)`. The seed depends only on the
/// node's symmetric offer key, so it is not recoverable by a Shor adversary from any published key.
pub(super) const PQ_OFFER_IV: &[u8; 16] = b"LDK PQ Offer ~~~";

/// Derives a per-offer ML-DSA seed from a pristine offer HMAC engine (keyed by the node's
/// `offers_base_key`) and the offer's `nonce`. The same `(key, nonce)` is available both when
/// building the offer and when signing the responding invoice, so the seed re-derives identically.
pub(super) fn pq_seed_from_offer_hmac(mut hmac: HmacEngine<Sha256>, nonce: &Nonce) -> [u8; 32] {
	hmac.input(PQ_OFFER_IV);
	hmac.input(nonce.as_slice());
	Hmac::from_engine(hmac).to_byte_array()
}

/// Appends a single TLV record (BigSize type, BigSize length, value) to `out`.
fn append_record(out: &mut Vec<u8>, record_type: u64, value: &[u8]) {
	BigSize(record_type).write(out).expect("Vec writes cannot fail");
	BigSize(value.len() as u64).write(out).expect("Vec writes cannot fail");
	out.extend_from_slice(value);
}

/// Returns the value of the first TLV record with type `record_type` in the well-formed TLV stream
/// `bytes`, or `None` if it is absent or the stream is truncated.
fn find_record(bytes: &[u8], record_type: u64) -> Option<Vec<u8>> {
	let mut cursor = Cursor::new(bytes);
	let total = bytes.len() as u64;
	while cursor.position() < total {
		let typ = BigSize::read(&mut cursor).ok()?.0;
		let value_len = BigSize::read(&mut cursor).ok()?.0;
		let start = cursor.position() as usize;
		let end = start.checked_add(value_len as usize)?;
		if end > bytes.len() {
			return None;
		}
		if typ == record_type {
			return Some(bytes[start..end].to_vec());
		}
		cursor.set_position(end as u64);
	}
	None
}

/// Inserts the offer metadata record carrying the issuer's ML-DSA public key and the `(path_index,
/// ciphertext)` pairs of the offer's post-quantum blinded paths into an `offer`'s serialized bytes,
/// at the position that keeps TLV record types in ascending order, returning the record value so
/// the caller can mirror it into the offer's typed contents. Returns `None` and does nothing if a
/// metadata record is already present (an explicit-metadata offer does not commit post-quantum
/// records).
pub(super) fn insert_offer_pq_metadata(
	bytes: &mut Vec<u8>, pubkey: &[u8; PQ_PUBLIC_KEY_LEN], cts: &[(usize, [u8; PQ_KEM_CT_LEN])],
) -> Option<Vec<u8>> {
	if find_record(bytes, OFFER_METADATA_TYPE).is_some() {
		return None;
	}
	let magic_len = PQ_OFFER_METADATA_MAGIC.len();
	let mut value =
		Vec::with_capacity(magic_len + PQ_PUBLIC_KEY_LEN + cts.len() * (PQ_KEM_CT_LEN + 1));
	value.extend_from_slice(PQ_OFFER_METADATA_MAGIC);
	value.extend_from_slice(pubkey);
	for (idx, ct) in cts {
		BigSize(*idx as u64).write(&mut value).expect("Vec writes cannot fail");
		value.extend_from_slice(ct);
	}
	let offset = pq_insert_offset(bytes, OFFER_METADATA_TYPE);
	let mut record = Vec::new();
	append_record(&mut record, OFFER_METADATA_TYPE, &value);
	bytes.splice(offset..offset, record);
	Some(value)
}

/// Returns the payload after the magic prefix of a post-quantum offer metadata record, or `None`
/// if the record is absent, too short to hold a key, or does not carry the magic.
fn find_offer_pq_metadata(bytes: &[u8]) -> Option<Vec<u8>> {
	let value = find_record(bytes, OFFER_METADATA_TYPE)?;
	if is_offer_pq_metadata_value(&value) {
		Some(value[PQ_OFFER_METADATA_MAGIC.len()..].to_vec())
	} else {
		None
	}
}

/// Whether an offer metadata value is a post-quantum carrier (magic prefix and long enough to
/// hold the ML-DSA key).
pub(super) fn is_offer_pq_metadata_value(value: &[u8]) -> bool {
	let magic_len = PQ_OFFER_METADATA_MAGIC.len();
	value.len() >= magic_len + PQ_PUBLIC_KEY_LEN && &value[..magic_len] == PQ_OFFER_METADATA_MAGIC
}

/// Whether a raw TLV record is a post-quantum offer metadata record. The payer strips this record
/// from the invoice_request it builds (and from its key derivation, consistently), since it
/// anchors the post-quantum data to the offer it already holds and async payments must fit the
/// signed invoice_request inside a fixed-size payment onion.
pub(super) fn is_offer_pq_metadata_record(record: &crate::offers::merkle::TlvRecord<'_>) -> bool {
	if record.r#type != OFFER_METADATA_TYPE {
		return false;
	}
	let mut cursor = Cursor::new(record.record_bytes);
	if BigSize::read(&mut cursor).is_err() || BigSize::read(&mut cursor).is_err() {
		return false;
	}
	is_offer_pq_metadata_value(&record.record_bytes[cursor.position() as usize..])
}

/// Parses the `(path_index, ciphertext)` pairs of the offer's post-quantum blinded paths out of an
/// `offer`'s serialized bytes (empty if the metadata record is absent or not post-quantum).
pub(super) fn parse_offer_pq_kem_cts(bytes: &[u8]) -> Vec<(usize, [u8; PQ_KEM_CT_LEN])> {
	let payload = match find_offer_pq_metadata(bytes) {
		Some(payload) => payload,
		None => return Vec::new(),
	};
	let value = &payload[PQ_PUBLIC_KEY_LEN..];
	let mut out = Vec::new();
	let mut cursor = Cursor::new(&value[..]);
	let total = value.len() as u64;
	while cursor.position() < total {
		let idx = match BigSize::read(&mut cursor) {
			Ok(b) => b.0 as usize,
			Err(_) => break,
		};
		let start = cursor.position() as usize;
		let end = match start.checked_add(PQ_KEM_CT_LEN) {
			Some(e) => e,
			None => break,
		};
		if end > value.len() {
			break;
		}
		let mut ct = [0u8; PQ_KEM_CT_LEN];
		ct.copy_from_slice(&value[start..end]);
		out.push((idx, ct));
		cursor.set_position(end as u64);
	}
	out
}

/// Returns the byte offset at which a record of type `record_type` is inserted to keep TLV types
/// ascending: the start of the first record whose type exceeds `record_type`, or the end of the
/// stream.
fn pq_insert_offset(bytes: &[u8], record_type: u64) -> usize {
	let mut cursor = Cursor::new(bytes);
	let total = bytes.len() as u64;
	while cursor.position() < total {
		let record_start = cursor.position() as usize;
		let typ = match BigSize::read(&mut cursor) {
			Ok(t) => t.0,
			Err(_) => return bytes.len(),
		};
		let value_len = match BigSize::read(&mut cursor) {
			Ok(l) => l.0,
			Err(_) => return bytes.len(),
		};
		let end = match (cursor.position() as usize).checked_add(value_len as usize) {
			Some(e) => e,
			None => return bytes.len(),
		};
		if end > bytes.len() {
			return bytes.len();
		}
		if typ > record_type {
			return record_start;
		}
		cursor.set_position(end as u64);
	}
	bytes.len()
}

/// Parses the issuer's ML-DSA public key out of an `offer`'s serialized bytes. Returns `None` if
/// the metadata record is absent, too short, or not post-quantum.
pub(super) fn parse_offer_pq_pubkey(bytes: &[u8]) -> Option<[u8; PQ_PUBLIC_KEY_LEN]> {
	let payload = find_offer_pq_metadata(bytes)?;
	let mut pk = [0u8; PQ_PUBLIC_KEY_LEN];
	pk.copy_from_slice(&payload[..PQ_PUBLIC_KEY_LEN]);
	Some(pk)
}

/// Appends the ML-DSA signature record to an invoice's experimental TLV bytes. Callers append it
/// after any defined experimental records so TLV types stay in ascending order, before the
/// classical signing that covers it.
pub(crate) fn append_invoice_pq_signature(bytes: &mut Vec<u8>, signature: &[u8; PQ_SIGNATURE_LEN]) {
	append_record(bytes, INVOICE_PQ_SIGNATURE_TYPE, signature);
}

/// Inserts an unsigned invoice's post-quantum records (the ML-DSA signature when present, and the
/// per-path ML-KEM ciphertext list when non-empty) into its experimental TLV bytes, at the
/// position that keeps record types ascending. The subsequent classical signing covers them.
pub(super) fn insert_invoice_pq_records(
	experimental_bytes: &mut Vec<u8>, signature: Option<&[u8; PQ_SIGNATURE_LEN]>,
	cts: &[(usize, Vec<u8>)],
) {
	let mut records = Vec::new();
	if let Some(signature) = signature {
		append_invoice_pq_signature(&mut records, signature);
	}
	append_invoice_pq_kem_cts(&mut records, cts);
	if records.is_empty() {
		return;
	}
	let offset = pq_insert_offset(experimental_bytes, INVOICE_PQ_SIGNATURE_TYPE);
	experimental_bytes.splice(offset..offset, records);
}

/// Parses the ML-DSA signature out of a `Bolt12Invoice`'s serialized bytes. Returns `None` if the
/// record is absent or has an unexpected length.
pub(super) fn parse_invoice_pq_signature(bytes: &[u8]) -> Option<[u8; PQ_SIGNATURE_LEN]> {
	let value = find_record(bytes, INVOICE_PQ_SIGNATURE_TYPE)?;
	if value.len() != PQ_SIGNATURE_LEN {
		return None;
	}
	let mut sig = [0u8; PQ_SIGNATURE_LEN];
	sig.copy_from_slice(&value);
	Some(sig)
}

/// Appends the per-path ML-KEM ciphertext list record to `bytes`. `cts` is the list of
/// `(path_index, ciphertext_list)` pairs for the invoice's post-quantum blinded payment paths; if
/// empty, nothing is appended. Callers append the record to the unsigned invoice's experimental
/// TLV bytes just after the ML-DSA signature record, so TLV types stay ascending; see
/// `UnsignedBolt12Invoice::append_pq_records` and `UnsignedStaticInvoice::append_pq_records`.
pub(super) fn append_invoice_pq_kem_cts(bytes: &mut Vec<u8>, cts: &[(usize, Vec<u8>)]) {
	if cts.is_empty() {
		return;
	}
	let mut value = Vec::new();
	for (idx, ct) in cts {
		BigSize(*idx as u64).write(&mut value).expect("Vec writes cannot fail");
		BigSize(ct.len() as u64).write(&mut value).expect("Vec writes cannot fail");
		value.extend_from_slice(ct);
	}
	append_record(bytes, INVOICE_PQ_KEM_CT_TYPE, &value);
}

/// Encodes the `(path_index, ciphertext)` pairs of a refund's post-quantum blinded message paths
/// as the value of its typed experimental record (TLV type [`REFUND_PQ_KEM_CT_TYPE`], written by
/// the `pq_kem_cts` field of the experimental invoice_request TLV stream).
pub(super) fn encode_refund_pq_kem_cts(cts: &[(usize, [u8; PQ_KEM_CT_LEN])]) -> Vec<u8> {
	debug_assert_eq!(REFUND_PQ_KEM_CT_TYPE, 2_000_000_243);
	let mut value = Vec::with_capacity(cts.len() * (PQ_KEM_CT_LEN + 1));
	for (idx, ct) in cts {
		BigSize(*idx as u64).write(&mut value).expect("Vec writes cannot fail");
		value.extend_from_slice(ct);
	}
	value
}

/// Parses the `(path_index, ciphertext)` pairs out of a refund's typed experimental record value
/// (empty if the value is malformed); see [`REFUND_PQ_KEM_CT_TYPE`].
pub(super) fn parse_refund_pq_kem_cts(value: &[u8]) -> Vec<(usize, [u8; PQ_KEM_CT_LEN])> {
	let mut out = Vec::new();
	let mut cursor = Cursor::new(value);
	let total = value.len() as u64;
	while cursor.position() < total {
		let idx = match BigSize::read(&mut cursor) {
			Ok(b) => b.0 as usize,
			Err(_) => break,
		};
		let start = cursor.position() as usize;
		let end = match start.checked_add(PQ_KEM_CT_LEN) {
			Some(e) => e,
			None => break,
		};
		if end > value.len() {
			break;
		}
		let mut ct = [0u8; PQ_KEM_CT_LEN];
		ct.copy_from_slice(&value[start..end]);
		out.push((idx, ct));
		cursor.set_position(end as u64);
	}
	out
}

/// Parses the per-path ML-KEM ciphertext list record out of a `Bolt12Invoice`'s serialized bytes,
/// returning the `(path_index, ciphertext_list)` pairs (empty if the record is absent or malformed).
pub(super) fn parse_invoice_pq_kem_cts(bytes: &[u8]) -> Vec<(usize, Vec<u8>)> {
	let value = match find_record(bytes, INVOICE_PQ_KEM_CT_TYPE) {
		Some(value) => value,
		None => return Vec::new(),
	};
	let mut out = Vec::new();
	let mut cursor = Cursor::new(&value[..]);
	let total = value.len() as u64;
	while cursor.position() < total {
		let idx = match BigSize::read(&mut cursor) {
			Ok(b) => b.0 as usize,
			Err(_) => break,
		};
		let len = match BigSize::read(&mut cursor) {
			Ok(b) => b.0 as usize,
			Err(_) => break,
		};
		let start = cursor.position() as usize;
		let end = match start.checked_add(len) {
			Some(e) => e,
			None => break,
		};
		if end > value.len() {
			break;
		}
		out.push((idx, value[start..end].to_vec()));
		cursor.set_position(end as u64);
	}
	out
}

/// Test-only: returns the byte range of the value of the first TLV record with type `record_type`
/// in `bytes`, or `None` if it is absent.
#[cfg(test)]
pub(super) fn find_record_value_range(
	bytes: &[u8], record_type: u64,
) -> Option<core::ops::Range<usize>> {
	let mut cursor = Cursor::new(bytes);
	let total = bytes.len() as u64;
	while cursor.position() < total {
		let typ = BigSize::read(&mut cursor).ok()?.0;
		let value_len = BigSize::read(&mut cursor).ok()?.0;
		let start = cursor.position() as usize;
		let end = start.checked_add(value_len as usize)?;
		if end > bytes.len() {
			return None;
		}
		if typ == record_type {
			return Some(start..end);
		}
		cursor.set_position(end as u64);
	}
	None
}

/// Returns the bytes the `invoice`'s ML-DSA signature is computed over: the concatenation, in wire
/// order, of every TLV record except those in the signature range (240..=1000) and the
/// post-quantum records themselves. Excluding these drops the classical Schnorr signature, the
/// ML-DSA signature record (so it does not cover itself), and the ML-KEM ciphertext record, so the
/// same bytes are recoverable before signing (on the unsigned invoice) and when verifying (on the
/// signed invoice carrying all three records).
pub(super) fn pq_signable_bytes(bytes: &[u8]) -> Vec<u8> {
	let mut out = Vec::with_capacity(bytes.len());
	let mut cursor = Cursor::new(bytes);
	let total = bytes.len() as u64;
	while cursor.position() < total {
		let record_start = cursor.position() as usize;
		let typ = match BigSize::read(&mut cursor) {
			Ok(t) => t.0,
			Err(_) => break,
		};
		let value_len = match BigSize::read(&mut cursor) {
			Ok(l) => l.0,
			Err(_) => break,
		};
		let value_start = cursor.position() as usize;
		let end = match value_start.checked_add(value_len as usize) {
			Some(e) => e,
			None => break,
		};
		if end > bytes.len() {
			break;
		}
		if !SIGNATURE_TYPES.contains(&typ)
			&& typ != INVOICE_PQ_SIGNATURE_TYPE
			&& typ != INVOICE_PQ_KEM_CT_TYPE
		{
			out.extend_from_slice(&bytes[record_start..end]);
		}
		cursor.set_position(end as u64);
	}
	out
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::sign::pq::keypair_from_seed;

	#[test]
	fn offer_pq_metadata_round_trips() {
		let (_sk, pk) = keypair_from_seed(&[3u8; 32]);
		let cts = vec![(0usize, [7u8; PQ_KEM_CT_LEN]), (2usize, [9u8; PQ_KEM_CT_LEN])];
		let mut bytes = Vec::new();
		// A leading record (type 2, chains-like) so the metadata record is inserted mid-stream in
		// ascending order, and a trailing record (type 22, issuer_id-sized) after it.
		append_record(&mut bytes, 2, &[7u8; 32]);
		append_record(&mut bytes, 22, &[7u8; 33]);
		assert!(insert_offer_pq_metadata(&mut bytes, &pk, &cts).is_some());
		assert_eq!(parse_offer_pq_pubkey(&bytes), Some(pk));
		assert_eq!(parse_offer_pq_kem_cts(&bytes), cts);
		assert_eq!(parse_invoice_pq_signature(&bytes), None);
		// The record landed between the type 2 and type 22 records, keeping types ascending.
		let mut cursor = Cursor::new(&bytes[..]);
		let first = BigSize::read(&mut cursor).unwrap().0;
		assert_eq!(first, 2);
		// A second insert is a no-op (the metadata record is already present).
		let before = bytes.clone();
		assert!(insert_offer_pq_metadata(&mut bytes, &pk, &cts).is_none());
		assert_eq!(bytes, before);
	}

	#[test]
	fn offer_pq_metadata_ignores_ordinary_metadata() {
		// An offer whose metadata record is ordinary derivation material (no magic) is not treated
		// as post-quantum, and neither is a magic-prefixed value too short to hold a key.
		let mut bytes = Vec::new();
		append_record(&mut bytes, OFFER_METADATA_TYPE, &[7u8; 32]);
		assert_eq!(parse_offer_pq_pubkey(&bytes), None);
		assert!(parse_offer_pq_kem_cts(&bytes).is_empty());
		let mut short = Vec::new();
		let mut value = PQ_OFFER_METADATA_MAGIC.to_vec();
		value.extend_from_slice(&[1u8; 10]);
		append_record(&mut short, OFFER_METADATA_TYPE, &value);
		assert_eq!(parse_offer_pq_pubkey(&short), None);
	}

	#[test]
	fn invoice_pq_signature_round_trips() {
		let sig = [9u8; PQ_SIGNATURE_LEN];
		let mut bytes = Vec::new();
		append_record(&mut bytes, 240, &[1u8; 64]); // classical signature record
		append_invoice_pq_signature(&mut bytes, &sig);
		assert_eq!(parse_invoice_pq_signature(&bytes), Some(sig));
	}

	#[test]
	fn invoice_pq_kem_cts_round_trip() {
		// Two post-quantum payment paths (indices 0 and 2) with different-length ciphertext lists, plus
		// a leading classical signature record to ensure parsing skips earlier records.
		let cts = vec![(0usize, vec![7u8; 3 * PQ_KEM_CT_LEN]), (2usize, vec![9u8; PQ_KEM_CT_LEN])];
		let mut bytes = Vec::new();
		append_record(&mut bytes, 240, &[1u8; 64]); // classical signature record
		append_invoice_pq_signature(&mut bytes, &[2u8; PQ_SIGNATURE_LEN]);
		append_invoice_pq_kem_cts(&mut bytes, &cts);
		assert_eq!(parse_invoice_pq_kem_cts(&bytes), cts);
		// The signature record still parses (the ciphertext record sits after it in ascending order).
		assert_eq!(parse_invoice_pq_signature(&bytes), Some([2u8; PQ_SIGNATURE_LEN]));
		// An empty list appends nothing and parses back as empty.
		let mut empty = Vec::new();
		append_invoice_pq_kem_cts(&mut empty, &[]);
		assert!(empty.is_empty());
		assert!(parse_invoice_pq_kem_cts(&empty).is_empty());
	}

	#[test]
	fn refund_pq_kem_cts_round_trip() {
		// Two post-quantum message paths (indices 0 and 2), matching the offer-side pair encoding.
		let cts = vec![(0usize, [7u8; PQ_KEM_CT_LEN]), (2usize, [9u8; PQ_KEM_CT_LEN])];
		let value = encode_refund_pq_kem_cts(&cts);
		assert_eq!(parse_refund_pq_kem_cts(&value), cts);
		// A truncated value parses only the complete leading entries.
		assert_eq!(parse_refund_pq_kem_cts(&value[..value.len() - 1]).len(), 1);
		assert!(parse_refund_pq_kem_cts(&[]).is_empty());
	}

	#[test]
	fn signable_bytes_excludes_signature_range() {
		let (_sk, pk) = keypair_from_seed(&[1u8; 32]);
		let mut bytes = Vec::new();
		// Offer/invoice content (the metadata record in the offer range and type 200 in the
		// invoice range).
		assert!(insert_offer_pq_metadata(&mut bytes, &pk, &[]).is_some());
		append_record(&mut bytes, 200, &[5u8; 32]);
		let content_only = bytes.clone();
		// Append the signature records, which must be filtered back out.
		append_record(&mut bytes, 240, &[2u8; 64]);
		append_invoice_pq_signature(&mut bytes, &[6u8; PQ_SIGNATURE_LEN]);
		assert_eq!(pq_signable_bytes(&bytes), content_only);
		// A stream with no signature records is returned unchanged.
		assert_eq!(pq_signable_bytes(&content_only), content_only);
	}
}
