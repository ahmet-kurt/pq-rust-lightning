# pq-rust-lightning, `configurable` branch

This branch is the `main` branch of the fork plus one commit. The [README of the `main` branch](https://github.com/ahmet-kurt/pq-rust-lightning/blob/main/README.md) describes the fork itself, its design, its build and test instructions, and the paper behind it. This file describes only the additions of the extra commit.

* [Purpose](#purpose)
* [Selecting the Parameter Sets](#selecting-the-parameter-sets)
* [What the Commit Changes](#what-the-commit-changes)
* [Measuring a Pairing](#measuring-a-pairing)
* [Caveats](#caveats)

## Purpose

The `main` branch fixes the post-quantum primitives at ML-DSA-44 and ML-KEM-768, because ML-DSA-44 is the smallest standardized signature set and ML-KEM-768 is the set deployed by TLS and Signal. This branch makes the signature scheme and both parameter sets selectable at build time, so we can measure the communication and computation overhead of PQLN at every NIST security category and with FN-DSA (Falcon) in place of ML-DSA. NIST selected FN-DSA as the third lattice signature scheme for standardization, and its keys and signatures are much smaller than those of ML-DSA. The parameter set comparison in the evaluation section of the paper comes from this branch, and so does its FN-DSA-512 timing column.

## Selecting the Parameter Sets

The selection happens through cargo features of the `lightning` crate. The features take effect only together with the `post-quantum` feature, a build may enable at most one signature feature and one ML-KEM feature, and a compile-time check rejects any other combination. Without a selection the build uses the defaults of the `main` branch.

| Feature | Signature scheme | Public key | Signature | Crate |
|---|---|---|---|---|
| (default) | ML-DSA-44 | 1312 bytes | 2420 bytes | `fips204` 0.4.6 |
| `pq-ml-dsa-65` | ML-DSA-65 | 1952 bytes | 3309 bytes | `fips204` 0.4.6 |
| `pq-ml-dsa-87` | ML-DSA-87 | 2592 bytes | 4627 bytes | `fips204` 0.4.6 |
| `pq-fn-dsa-512` | FN-DSA-512 | 897 bytes | 666 bytes | `fn-dsa` 0.4.0 |
| `pq-fn-dsa-1024` | FN-DSA-1024 | 1793 bytes | 1280 bytes | `fn-dsa` 0.4.0 |

| Feature | Key exchange | Encapsulation key | Ciphertext | Crate |
|---|---|---|---|---|
| (default) | ML-KEM-768 | 1184 bytes | 1088 bytes | `fips203` 0.4.3 |
| `pq-ml-kem-512` | ML-KEM-512 | 800 bytes | 768 bytes | `fips203` 0.4.3 |
| `pq-ml-kem-1024` | ML-KEM-1024 | 1568 bytes | 1568 bytes | `fips203` 0.4.3 |

For example, the following command builds the fork with FN-DSA-512 and ML-KEM-1024 and runs its test suite:

```bash
cargo test -p lightning --lib --features "post-quantum,pq-fn-dsa-512,pq-ml-kem-1024"
```

The complete `lightning` test suite passes at all 15 pairings of a signature set with an ML-KEM set.

## What the Commit Changes

- **Every size follows the selected set.** The commit sizes every wire format, buffer and pin through the length constants of the selected set instead of literal sizes. The three `node_announcement` records therefore add 12 bytes plus the public key, the encapsulation key and the signature, and the `channel_update` record adds 4 bytes plus the signature. The two ciphertext lists of `update_add_htlc` keep their 20 and 10 entries and grow with the ciphertext, so the payment list ranges from 15,370 bytes with ML-KEM-512 to 31,370 bytes with ML-KEM-1024.
- **The relay budget doubles when needed.** The gossip relay budget stays at 8192 bytes, but it doubles to 16,384 bytes for the pairings with `node_announcement` records above 8192 bytes. Only ML-DSA-87 with ML-KEM-768 and ML-DSA-87 with ML-KEM-1024 need the larger budget, as the table below shows.
- **A second signature backend.** The signature primitive sits behind one interface with an ML-DSA backend and an FN-DSA backend, and the rest of the crate only uses that interface. The FN-DSA backend derives keys from the same 32-byte seeds through a SHAKE256 stream in place of the crate's random source, and it derandomizes signing from the key, the context and the message, so keys and signatures stay reproducible as they are with ML-DSA. It keeps the encoded signing key and decodes it for every signature.
- **The dummy ciphertexts follow the set.** The generator that pads the ciphertext lists with dummies takes the compression parameters of FIPS 203 from the selected ML-KEM set, and so does the test that checks the dummies against the distribution of real ciphertexts.
- **The logs name the sets.** The `PQ:` log lines and the test printouts name the selected sets through the new `PQ_SIG_SCHEME` and `PQ_KEM_SCHEME` constants instead of hard-coding ML-DSA-44 and ML-KEM-768.
- **The tests respect the invoice length cap.** rust-lightning refuses to parse a BOLT 11 invoice longer than 7089 characters. Only ML-DSA-44 keeps every invoice below this cap, since ML-DSA-65 pushes the invoice with an embedded public key beyond it and ML-DSA-87 pushes even the signature-only invoice beyond it. The BOLT 11 round-trip tests therefore skip the decode leg when the encoded invoice exceeds the cap.
- **A size report.** An ignored test next to the timing test of the `main` branch prints the wire size of every post-quantum addition at the selected sets with the production encoders, so the communication overhead of every pairing is reproducible from the repository.

The three records add the following bytes to a `node_announcement` at every pairing. The two pairings marked with an asterisk exceed 8192 bytes and build with the 16,384-byte relay budget.

| Signature set | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 |
|---|---|---|---|
| ML-DSA-44 | 4544 | 4928 | 5312 |
| ML-DSA-65 | 6073 | 6457 | 6841 |
| ML-DSA-87 | 8031 | 8415\* | 8799\* |
| FN-DSA-512 | 2375 | 2759 | 3143 |
| FN-DSA-1024 | 3885 | 4269 | 4653 |

## Measuring a Pairing

The size report prints one `PQ-SIZE` line per addition, from the public key and the signature through the gossip records, the handshake acts, the ciphertext lists and the chunked BOLT 11 fields to the relay budget of the build:

```bash
cargo test -p lightning --lib --features "post-quantum,pq-fn-dsa-512" --release -- size_tests --ignored --nocapture
```

The timing test of the `main` branch runs unchanged at any pairing and names the selected sets in its output:

```bash
cargo test -p lightning --lib --features "post-quantum,pq-fn-dsa-512" --release -- timing_tests --ignored --nocapture
```

Cargo ignores both tests by default, so they run only on request, and both should run in release mode.

## Caveats

- NIST had not published FIPS 206 at the time of writing, so the `fn-dsa` crate implements the expected draft and its encodings may still change.
- FN-DSA signs and verifies faster than ML-DSA but generates keys far more slowly, around 2 ms at degree 512 and around 10 ms at degree 1024 on the workstation of the paper, and its signing uses floating-point arithmetic. A node generates its identity key once, but a BOLT 12 payee derives a fresh per-offer key for every invoice.
- The larger ML-DSA sets produce BOLT 11 invoices beyond the parser cap of rust-lightning, as noted above, so they serve the measurements rather than a deployable configuration.
- This branch exists for the evaluation. The `main` branch remains the reference implementation of PQLN.
