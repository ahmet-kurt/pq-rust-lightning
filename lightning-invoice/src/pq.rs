// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Carrier for hybrid post-quantum (ML-DSA / FIPS 204) BOLT 11 invoice signatures. The payee's
//! ML-DSA public key (1312 bytes) and the signature over the invoice (2420 bytes) are far larger
//! than a single BOLT 11 tagged field, whose 10-bit length caps it at 639 bytes. Each is therefore
//! split across several fields, carried as opaque tagged fields under a post-quantum-specific tag.
//! Vanilla nodes skip these unknown fields, so interoperability is preserved; the actual ML-DSA
//! crypto lives in the `lightning` crate.

use crate::prelude::*;
use crate::RawTaggedField;
use bech32::{ByteIterExt, Fe32, Fe32IterExt};

/// BOLT 11 tag carrying a chunk of the payee's ML-DSA public key. BOLT 11 has no assigned
/// post-quantum field, so this is provisional pending a BOLT proposal. The 5-bit tag must avoid the
/// assigned field types: core BOLT 11 uses 1, 3, 5, 6, 9, 13, 16, 19, 23, 24, and 27, and bLIP-39
/// assigns type 20 (`b`) for blinded payment paths (so a reader such as LND parses a chunk under tag
/// 20 as a malformed blinded path and rejects the invoice). Type 25 (`e`) is unassigned in both, so
/// vanilla readers skip it as an unknown field.
pub const TAG_PQ_PUBLIC_KEY: u8 = 25;

/// BOLT 11 tag carrying a chunk of the ML-DSA signature over the invoice. Type 22 (`k`) is unassigned
/// by both core BOLT 11 and bLIP-39; provisional pending a BOLT proposal. See [`TAG_PQ_PUBLIC_KEY`].
pub const TAG_PQ_SIGNATURE: u8 = 22;

/// The maximum number of data bytes a single BOLT 11 tagged field can carry. The length field is
/// 10 bits, so a field holds at most 1023 base32 values, i.e. floor(1023 * 5 / 8) = 639 bytes.
const MAX_FIELD_BYTES: usize = 639;

/// Splits `data` into chunks of at most [`MAX_FIELD_BYTES`] and appends each as a tagged field
/// under `tag` to `fields`. Used to carry an ML-DSA public key or signature, which are too large
/// for a single field. The chunks are appended in order and reassembled by [`read_chunks`].
pub fn append_chunks(fields: &mut Vec<RawTaggedField>, tag: u8, data: &[u8]) {
	for chunk in data.chunks(MAX_FIELD_BYTES) {
		let data_fes: Vec<Fe32> = chunk.iter().copied().bytes_to_fes().collect();
		let len = data_fes.len();
		// Each chunk is at most 639 bytes, which is exactly 1023 base32 values, so the length
		// always fits the 10-bit field-length encoding.
		let mut field = Vec::with_capacity(3 + len);
		field.push(Fe32::try_from(tag).expect("post-quantum tag must be < 32"));
		field.push(Fe32::try_from((len / 32) as u8).expect("length high bits < 32"));
		field.push(Fe32::try_from((len % 32) as u8).expect("length low bits < 32"));
		field.extend(data_fes);
		fields.push(RawTaggedField::UnknownSemantics(field));
	}
}

/// Returns whether `field` is an unknown-semantics tagged field carrying the given post-quantum
/// `tag`. The tag is the first base32 value of the stored field.
pub fn field_has_tag(field: &RawTaggedField, tag: u8) -> bool {
	match field {
		RawTaggedField::UnknownSemantics(content) => {
			Fe32::try_from(tag).map_or(false, |t| content.first() == Some(&t))
		},
		RawTaggedField::KnownSemantics(_) => false,
	}
}

/// Reassembles the bytes carried by all tagged fields under `tag`, concatenated in encounter
/// order. Each field's chunk is converted back to bytes independently (each chunk is a whole
/// number of bytes), so concatenating the decoded bytes recovers the original value. Returns the
/// (possibly empty) reassembled bytes; callers must validate the expected length.
pub fn read_chunks(fields: &[RawTaggedField], tag: u8) -> Vec<u8> {
	let mut out = Vec::new();
	for field in fields {
		if !field_has_tag(field, tag) {
			continue;
		}
		if let RawTaggedField::UnknownSemantics(content) = field {
			// Skip the 3-value header (tag plus the two length values) and decode the chunk.
			if content.len() < 3 {
				continue;
			}
			out.extend(content[3..].iter().copied().fes_to_bytes());
		}
	}
	out
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn chunk_round_trip_pubkey_and_signature() {
		// ML-DSA-44 public key (1312 B) and signature (2420 B) lengths.
		for (len, expected_fields) in [(1312usize, 3usize), (2420, 4)] {
			let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
			let mut fields = Vec::new();
			append_chunks(&mut fields, TAG_PQ_SIGNATURE, &data);
			assert_eq!(fields.len(), expected_fields);
			assert_eq!(read_chunks(&fields, TAG_PQ_SIGNATURE), data);
		}
	}

	#[test]
	fn reads_only_the_requested_tag() {
		let pubkey: Vec<u8> = (0..1312).map(|i| (i % 251) as u8).collect();
		let sig: Vec<u8> = (0..2420).map(|i| (i % 241) as u8).collect();
		let mut fields = Vec::new();
		append_chunks(&mut fields, TAG_PQ_PUBLIC_KEY, &pubkey);
		append_chunks(&mut fields, TAG_PQ_SIGNATURE, &sig);
		assert_eq!(read_chunks(&fields, TAG_PQ_PUBLIC_KEY), pubkey);
		assert_eq!(read_chunks(&fields, TAG_PQ_SIGNATURE), sig);
		assert!(read_chunks(&fields, TAG_PQ_PUBLIC_KEY) != sig);
	}

	#[test]
	fn max_field_holds_639_bytes() {
		// A 639-byte chunk is exactly the 1023 base32-value field-length maximum; 640 would split.
		let mut fields = Vec::new();
		append_chunks(&mut fields, TAG_PQ_SIGNATURE, &[0u8; 639]);
		assert_eq!(fields.len(), 1);
		let mut fields = Vec::new();
		append_chunks(&mut fields, TAG_PQ_SIGNATURE, &[0u8; 640]);
		assert_eq!(fields.len(), 2);
	}

	#[test]
	fn absent_tag_reads_empty() {
		let fields = Vec::new();
		assert!(read_chunks(&fields, TAG_PQ_SIGNATURE).is_empty());
	}
}
