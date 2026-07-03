# pq-rust-lightning: A Post-Quantum Fork of rust-lightning

This repository is a research fork of [rust-lightning](https://github.com/lightningdevkit/rust-lightning), the Lightning Development Kit (LDK), that adds post-quantum cryptography to the off-chain surfaces of the Bitcoin Lightning Network. It implements PQLN, the design of the paper below, and it produced the measurements reported there. The fork builds on the `main` branch of rust-lightning at commit [384e0d6](https://github.com/lightningdevkit/rust-lightning/commit/384e0d613) (August 2026), and all post-quantum code sits behind the `post-quantum` cargo feature.

If you use this code in your research, please cite the paper:

```bibtex
@misc{kurt2026pqln,
  author = {Ahmet Kurt and Abdul-Salem Beibitkhan and Yacoub Hanna and Abdullah Aydeger},
  title  = {{PQLN}: Post-Quantum Security for the {Bitcoin} {Lightning} {Network's} Off-Chain Surfaces},
  year   = {2026},
  url    = {https://arxiv.org/abs/2609.13781}
}
```

The node implementation that drives this fork with real nodes lives in [pq-ldk-sample](https://github.com/ahmet-kurt/pq-ldk-sample). The [`configurable`](https://github.com/ahmet-kurt/pq-rust-lightning/tree/configurable) branch of this repository makes the parameter sets selectable at build time for the measurements of the paper. This fork is a research artifact rather than a production release, so the emphasis lies on the correctness of the protocol and the cryptography and on measuring their cost, not on production hardening. For the upstream project itself, see the [rust-lightning README](https://github.com/lightningdevkit/rust-lightning/blob/main/README.md).

* [Overview](#overview)
* [Threat Model](#threat-model)
* [Design](#design)
    * [Gossip (BOLT 7)](#gossip-bolt-7)
    * [Transport (BOLT 8)](#transport-bolt-8)
    * [Invoices (BOLT 11)](#invoices-bolt-11)
    * [Offers (BOLT 12)](#offers-bolt-12)
    * [Payment Onion (BOLT 4)](#payment-onion-bolt-4)
* [Configuration and Runtime Behavior](#configuration-and-runtime-behavior)
* [Wire Format and Constants](#wire-format-and-constants)
* [Implementation Map and API](#implementation-map-and-api)
* [Building and Testing](#building-and-testing)
* [Coverage and Limitations](#coverage-and-limitations)
* [Related Repositories](#related-repositories)
* [License](#license)

## Overview

A cryptographically relevant quantum computer runs Shor's algorithm and thereby recovers the secret key behind any secp256k1 public key. Lightning rests on secp256k1 everywhere, since nodes authenticate gossip with ECDSA, derive the keys of every peer connection with ECDH, sign invoices with ECDSA and Schnorr signatures, and build payment onions from one ECDH secret per hop. A quantum adversary can therefore impersonate nodes, decrypt recorded transport sessions, forge invoices, and deanonymize payments. Only the keys inside funding, commitment and penalty transactions are rooted in Bitcoin and need a Bitcoin consensus change. Everything else lives in messages between Lightning nodes, so these off-chain surfaces can adopt post-quantum cryptography through a software update, and they stay exposed even after Bitcoin adopts post-quantum outputs.

PQLN follows a hybrid conservative-extension approach. Every classical mechanism stays in place and PQLN adds a post-quantum primitive alongside it, so an unmodified node, called a vanilla node below, keeps working and ignores the extra data while a PQLN node gains the protection. Signatures use ML-DSA (FIPS 204) and key exchange uses ML-KEM (FIPS 203), both from pure-Rust crates. Against a classical adversary the fork is therefore at least as secure as vanilla rust-lightning, and a quantum adversary additionally has to break the lattice primitive.

The following table maps every BOLT to its Shor-vulnerable surface and to its treatment in this fork. The surfaces of BOLTs 2, 3 and 5 are rooted in Bitcoin transactions and stay out of scope, whereas the remaining five BOLTs carry cryptography that lives purely off-chain, and the fork protects all five of them.

| BOLT | Specification | Shor-vulnerable surface | Treatment in this fork |
|---|---|---|---|
| 1, 10 | Base protocol and DNS bootstrap | None | Not applicable |
| 2 | Peer protocol for channel management | ECDSA over on-chain transactions | Out of scope (rooted on-chain) |
| 3 | Bitcoin transaction and script formats | secp256k1 keys inside Bitcoin Script | Out of scope (requires a Bitcoin change) |
| 4 | Onion routing protocol | Per-hop ECDH | Protected, hybrid ML-KEM ([details](#payment-onion-bolt-4)) |
| 5 | On-chain transaction handling | ECDSA over on-chain transactions | Out of scope (rooted on-chain) |
| 7 | P2P node and channel discovery | Node-key ECDSA on gossip messages | Protected, ML-DSA ([details](#gossip-bolt-7)) |
| 8 | Encrypted and authenticated transport | ECDH in the Noise handshake | Protected, hybrid ML-KEM ([details](#transport-bolt-8)) |
| 9 | Assigned feature flags | None | Two experimental feature bits registered |
| 11 | Invoice protocol for payments | Node-key recoverable ECDSA | Protected, ML-DSA ([details](#invoices-bolt-11)) |
| 12 | Flexible protocol for payments (offers) | Schnorr signatures and per-hop ECDH | Protected, ML-DSA and hybrid ML-KEM ([details](#offers-bolt-12)) |

## Threat Model

We assume an adversary that possesses a cryptographically relevant quantum computer and runs Shor's algorithm at scale. It recovers the secret key behind every observed secp256k1 public key, so it can forge the ECDSA and Schnorr signatures of any node with a key exposed in gossip, in an invoice or on the wire, and it can compute the shared secret of any ECDH exchange from the two public keys alone. Symmetric primitives and hash functions only face Grover's quadratic speedup, so we treat ChaCha20-Poly1305, SHA-256 and HMAC as secure. The adversary records classical traffic today and breaks it once a quantum computer exists (harvest now, decrypt later), and it also attacks in real time by forging signatures, substituting keys and inserting itself into new sessions. It controls the network, runs well-connected nodes of its own, and can act as the counterparty, the routing hop or the payee of a victim. We consider the following threats.

1. **Node impersonation.** The adversary forges a victim node's gossip signatures to announce substituted keys or attacker-chosen parameters on the victim's behalf.
2. **Transport decryption.** The adversary breaks the ECDH operations of the BOLT 8 handshake to decrypt recorded sessions or to impersonate a responder in new sessions.
3. **Invoice forgery.** The adversary forges the payee signature on a BOLT 11 or BOLT 12 invoice to substitute the payment hash, the amount or the payment paths.
4. **Payment deanonymization.** The adversary recovers the per-hop ECDH secrets of the payment onion, unwraps its layers and links payer, route and payee. The same capability strips the privacy of blinded paths and onion messages.
5. **Downgrade attacks.** The adversary strips or tampers with the post-quantum additions of a message so that the receiver processes it as a vanilla message, and then breaks the exchange like any other vanilla exchange.

Attacks on the Bitcoin layer are outside the model, since they await Bitcoin's own post-quantum transition. These include the theft of channel funds by breaking the secp256k1 keys of funding, commitment or HTLC outputs. Denial-of-service attacks are orthogonal to quantum resistance, and we assume honest endpoints. The trust-on-first-use model further assumes that a node pinned the keys of its peers before a cryptographically relevant quantum computer exists, because a live adversary can intercept a first contact made afterwards. The paper states this assumption formally and reduces every guarantee to the standard security notions of ML-DSA and ML-KEM.

## Design

Two constraints shape the design. No Lightning upgrade can change Bitcoin's consensus rules, so the secp256k1 keys inside funding, commitment and penalty transactions stay as they are. The network also cannot upgrade at once, so every mechanism has to interoperate with vanilla nodes. The fork therefore adds its protection where the extensibility rules of the BOLTs let vanilla nodes skip it as unknown data, namely odd TLV records, unknown BOLT 11 tagged fields and experimental BOLT 12 records.

Signatures use ML-DSA-44 with public keys of 1312 bytes and signatures of 2420 bytes. We chose the smallest standardized set because signature and key material dominates the wire overhead. Key exchange uses ML-KEM-768 with encapsulation keys of 1184 bytes, ciphertexts of 1088 bytes and 32-byte shared secrets, the set adopted by TLS and OpenSSH. Every node derives its ML-DSA signing key at hardened BIP 32 index 9 and its static ML-KEM key at index 10 from the seed of its `KeysManager`, so the wallet backup that restores the classical identity also restores the post-quantum identity. Hardened derivation is one-way, so a node key recovered with Shor's algorithm reveals nothing about the post-quantum keys derived from the same seed. ML-DSA signs with the deterministic variant of FIPS 204, so a signature is reproducible from the key and the message. ML-KEM encapsulation and the ephemeral handshake key draw fresh randomness for every connection and every payment, and only the tests fix that randomness.

The gossip layer distributes these keys and serves as the trust anchor. Every node publishes its ML-DSA and ML-KEM public keys inside its signed `node_announcement`, and every PQLN node pins these keys on first sight. All other surfaces then verify against the pinned keys under this trust-on-first-use model. The only exception is BOLT 12, where an offer additionally commits a per-offer signing key so that invoice verification works even for payees that never appeared in gossip. The signature surfaces of gossip, invoices and offers are always on, whereas the key-exchange surfaces of the transport, the payment onion and the blinded paths need both endpoints and are explicit opt-ins, as the [configuration section](#configuration-and-runtime-behavior) explains.

### Gossip (BOLT 7)

Gossip comes first because every node already receives a `node_announcement` from every other node. A PQLN node appends three odd TLV records to the excess data at the tail of its `node_announcement`. Record 27 carries its ML-DSA public key, record 29 carries its static ML-KEM encapsulation key and record 31 carries an ML-DSA signature over the serialized announcement including the two key records, computed under the gossip context string. The node produces its classical ECDSA signature afterwards over the complete message, so the classical signature commits to the records. A vanilla node therefore verifies the announcement exactly as today and skips the records under the odd-type rule of BOLT 1. A `channel_update` carries only the signature record, since the verifier already knows the signer's ML-DSA key from its `node_announcement`. The records add 4928 bytes to a `node_announcement` and 2424 bytes to a `channel_update`.

A PQLN node runs the post-quantum checks after the classical checks and updates its pins only after every check has passed, so a rejected message never alters a pin. The verifier rejects an announcement that carries a key without the signature, or the signature without the ML-DSA key, as malformed. Otherwise it verifies the ML-DSA signature against the embedded key. If the announcing node is new, the verifier pins its ML-DSA and ML-KEM keys in its `NetworkGraph`, where they persist with the rest of the graph. If the node is already pinned, the verifier rejects the announcement when a key differs from the pinned key, when a pinned key is missing, or when the signature is missing. A `channel_update` from a pinned node must likewise carry a valid ML-DSA signature under the pinned key. The downgrade defense therefore rests on the stored pin rather than on a forgeable feature bit.

Vanilla rust-lightning refuses to relay a gossip message with more than 1024 bytes of unrecognized trailing data, so a vanilla node accepts, verifies and stores a post-quantum announcement but does not forward it. The fork raises this relay budget to 8192 bytes under the feature, so post-quantum gossip propagates across the post-quantum-aware part of the network while a vanilla node on the way stops the propagation without rejecting the message.

The fork deliberately leaves `channel_announcement` classical. Two of its four signatures prove ownership of the on-chain funding output, so no off-chain change can protect them, and a quantum adversary could still half forge the message if only the two node-key signatures were protected. A node's identity keys and forwarding parameters stay fully protected through `node_announcement` and `channel_update`, and the gossip query messages carry no signatures at all.

### Transport (BOLT 8)

The Noise_XK handshake derives the session keys from three ECDH operations on secp256k1, and the operation against the responder's static key also authenticates the responder. The fork hybridizes the handshake with two ML-KEM encapsulations. In act one, the initiator encapsulates to the responder's static ML-KEM key and appends the ciphertext together with a freshly generated ephemeral ML-KEM public key, so only the true responder can decapsulate the ciphertext and derive the same keys. The responder encapsulates to the ephemeral key and appends the resulting ciphertext to act two, which provides forward secrecy, because a later compromise of the static keys does not reveal the ephemeral secret. Act three stays unchanged. The handshake folds each ML-KEM shared secret into the Noise chaining key right after the ECDH secret of the same act and absorbs both ciphertexts and the ephemeral key into the transcript hash, so the session keys become hybrid over five shared secrets and any tampering fails the handshake. Act one grows from 50 to 2322 bytes and act two from 50 to 1138 bytes.

A key exchange cannot fall back silently, because both ends must take part, and a quantum adversary could rewrite any in-band negotiation to force a downgrade. The hybrid handshake therefore runs on a dedicated port through separate entry points, `PeerManager::new_outbound_connection_pq` and `PeerManager::new_inbound_connection_pq`, with matching helpers in `lightning-net-tokio`, while the classical port stays byte-identical to vanilla and the unmodified BOLT 8 test vectors still pass. The initiator supplies the responder's static ML-KEM key from its gossip pin or out of band, just as Noise_XK already assumes for the classical static key. Initiator authentication stays classical, since Lightning nodes accept inbound connections from anonymous peers by design and the other surfaces authenticate every further action of a connected peer.

### Invoices (BOLT 11)

A BOLT 11 invoice binds the payment hash, the amount and the destination to the payee through a recoverable ECDSA signature, and the payer usually recovers the payee's node id from that signature rather than reading it from the invoice. The fork adds the payee's ML-DSA signature and optionally its ML-DSA public key. A tagged field carries at most 639 bytes because of its 10-bit length encoding, so the fork splits the two values into chunks and carries them as several tagged fields under two unassigned tags, tag 25 for the public key in three fields and tag 22 for the signature in four fields. Vanilla decoders skip unknown tagged fields, so the invoice still parses everywhere. The ML-DSA signature covers the human-readable part and the data part of the invoice, including the embedded public key fields, under the BOLT 11 context string, and the payee produces the classical signature afterwards so that it commits to the post-quantum fields. An announced payee can omit the public key through `Bolt11InvoiceParameters::pq_omit_pubkey`, since the payer finds the key in gossip. A vanilla invoice of our nodes is around 400 characters long, the signature-only invoice is 4286 characters long and still fits the 4296-character limit of a QR code, and the self-contained invoice is 6396 characters long.

Verification runs inside `ChannelManager::pay_for_bolt11_invoice` with no opt-in. Before dispatching any HTLC, the payer resolves a trusted key for the payee, either from `OptionalBolt11PaymentParams::trusted_pq_key` or from the payee's gossip pin. When a trusted key exists, the payer requires a valid ML-DSA signature under that key, refuses the invoice as a downgrade if the signature is missing, and refuses an embedded key that differs from the trusted key. All three refusals return `Bolt11PaymentError::PqVerificationFailed`. Without a trusted key, the payer pays a vanilla invoice as today, and it pays an invoice with post-quantum fields only if they are well formed and the signature verifies under the carried key. We call this last case unanchored, and it gives no protection, because a signature under a self-asserted key proves nothing against an adversary who can mint both. A first contact with an unannounced payee therefore stays unprotected, and phantom invoices stay classical.

### Offers (BOLT 12)

With offers, the payer sends an `invoice_request` over a blinded onion message path and receives a freshly signed invoice in return. Only a Schnorr signature binds the invoice to the offer, and the gossip pin rarely helps here, because offer payees are commonly unannounced nodes reachable only through blinded paths. The fork therefore uses a trust anchor already in the payer's possession, namely the offer itself. When a node builds an offer with derived signing keys and blinded paths, as `ChannelManager::create_offer_builder` does, it derives a per-offer ML-DSA key and commits the public key inside the offer. The signing seed is an HMAC of the node's symmetric offer key and the offer's nonce, so a quantum adversary cannot recover it from any published key, and distinct offers carry unlinkable keys. A hand-built offer with an explicit signing key commits no post-quantum key.

The committed key travels in the offer's metadata record behind the magic prefix `PQO1`, together with one ML-KEM ciphertext per post-quantum blinded path of the offer. A vanilla payer copies this record verbatim into its `invoice_request` and the payee echoes it back, so every classical implementation handles it consistently, whereas a PQLN payer strips it from its request and excludes it from the offer id. The payee re-derives the per-offer key from the nonce and signs the responding invoice under the BOLT 12 context string. It places the signature in an odd record of the experimental invoice TLV range and writes it into the unsigned invoice, so the classical Schnorr signature covers it and a vanilla node round-trips it untouched. Verification again runs in the pay path with no opt-in. A payer that scanned a post-quantum offer records the committed key and requires a valid signature under exactly that key before it dispatches any HTLC, and a failure surfaces as `Bolt12PaymentError::PqVerificationFailed`. An often-offline payee pre-signs static invoices for asynchronous payments, and the same anchor covers them. These verify under a distinct context string, so nobody can replay a static-invoice signature as a regular invoice.

The privacy surfaces of BOLT 12 use the hybrid key exchange of the payment onion. When `build_post_quantum_blinded_paths` is set, the node builds the message paths of its offers, the reply paths of its requests and the blinded payment paths of its invoices with the hybrid route blinding of the [next section](#payment-onion-bolt-4), and it builds the message and payment paths of its refunds the same way. The senders receive the corresponding ciphertexts in the offer metadata, after the onion packet of an onion message, in a second experimental record of the invoice, and in a typed experimental record of the refund under the payer's stateless-verification HMAC, so the payer detects a stripped refund record when the invoice echoes the refund back. Two BOLT 12 signatures stay classical, namely the payer's signature on the `invoice_request` and the payee's signature on a refund's invoice, because the verifier holds no trusted key for either signer and an ML-DSA signature there would be strippable scaffolding. An offer grows from 416 to 2528 characters through its committed key, and to 4332 characters with post-quantum blinded paths.

### Payment Onion (BOLT 4)

The Sphinx packet carries a fixed 1300-byte payload, so a single ML-KEM ciphertext of 1088 bytes would nearly fill it, and vanilla nodes cannot forward a packet of any other size. The fork keeps the onion at 1300 bytes and makes the per-hop keys hybrid instead. For every hop, the sender encapsulates to the hop's pinned ML-KEM key and folds the shared secret into the hop's classical Sphinx secret through a tagged SHA-256, so the encryption and MAC keys of that layer become hybrid while the onion keeps its vanilla format. The ciphertexts travel beside the onion in an odd TLV field of `update_add_htlc` as a fixed list of 20 entries, the onion's maximum hop count. Real entries come first in hop order and dummies fill the rest, so the list looks the same for every route length and adds a constant 21,770 bytes to the message. The dummies are not random bytes but are compressed and encoded from uniformly random polynomial coefficients exactly as FIPS 203 builds a ciphertext, because the compression makes some encoded values more likely than others and a hop could otherwise count the real entries. Each hop decapsulates the front entry, folds the secret into its classical ECDH result, peels its layer with the hybrid keys and rotates the entry to the back. The list carries no key or MAC of its own and takes its integrity from the hybrid onion MAC, so a tampered, reordered or dropped entry yields a wrong hybrid secret at that hop and the payment fails closed. A quantum adversary who recovers a hop's classical secret therefore gains no oracle to trace the route.

The hybrid secret also becomes the hop's incoming secret, so the return error onion and its attribution data inherit the protection. The recipient rather than the sender builds blinded payment paths, so the recipient protects them. It encapsulates to each path hop's ML-KEM key and folds the secrets into the route-blinding schedule, so the blinded node ids and the encrypted per-hop data are hybrid before the sender sees the path. These ciphertexts reach the sender in the invoice record of the [offers section](#offers-bolt-12) and travel in a second fixed list of 10 entries beside the onion, which adds 10,890 bytes. The fork keys trampoline payments the same way at both layers, and the trampoline hops' ciphertexts ride in the same 20-entry list behind the outer hops' entries. The ephemeral key blinding chain of the onion stays classical, because it advances public points rather than keys. Phantom payments stay classical.

A key exchange needs both endpoints, so the fork cannot force the hybrid onion on every route. A sender builds the hybrid onion whenever every hop, including every trampoline hop, has a pinned ML-KEM key, and otherwise falls back to a classical onion unless `require_post_quantum_payments` forbids the fallback. Similarly, `require_post_quantum_inbound` makes a forwarding or receiving node fail back any HTLC that arrives without the hybrid protection. A refused route is a deterministic failure, so the sender abandons the payment instead of retrying it.

## Configuration and Runtime Behavior

Everything in this section requires a build with `--features post-quantum`. With the feature off, the build is upstream rust-lightning and the wire format is byte-identical to vanilla, because every post-quantum field is an optional record that serializes to nothing when absent.

The signature surfaces of gossip, invoices and offers are always on. A node with a post-quantum identity attaches its ML-DSA signatures wherever it signs, a vanilla peer ignores them, and a verifier with a trusted key gains the protection. Protection takes effect on the verifying side and anchors to a key already trusted by the verifier, namely the gossip pin for gossip and BOLT 11 and the committed offer key for BOLT 12. When no anchor exists, the verifier falls back to classical behavior with no protection but also no failure, so the fork preserves interoperability.

The key-exchange surfaces of the transport, the payment onion and the blinded paths need both endpoints and are explicit opt-ins. The hybrid transport handshake runs on a dedicated port through the entry points named above, while the classical port is untouched. Three fields of `UserConfig` control the remaining surfaces, and all three default to `false`.

| Field | Effect when set |
|---|---|
| `build_post_quantum_blinded_paths` | The node builds post-quantum blinded paths for its offers, invoices, reply paths and refunds whenever every hop of a path has a pinned ML-KEM key. |
| `require_post_quantum_payments` | The node refuses to send a payment unless every hop has a pinned ML-KEM key, instead of falling back to a classical onion. |
| `require_post_quantum_inbound` | The node fails back any inbound HTLC, forwarded or received, that carries no ML-KEM ciphertext list. |

The fork announces its support through two experimental odd feature bits, 139 for post-quantum gossip and 141 for post-quantum payments, in its init and node features. A quantum adversary can flip these bits, so no security decision depends on them. Every post-quantum operation logs a line with the prefix `PQ:`, from the signing of a `node_announcement` and the pinning of a peer's keys to the construction of a hybrid onion and every refusal, so the protection is visible at runtime and in the tests.

## Wire Format and Constants

The following values are experimental and still need assignment through the BOLT process.

| Item | Value |
|---|---|
| `node_announcement` records (appended to the excess data) | type 27 ML-DSA public key (1312 bytes), type 29 ML-KEM encapsulation key (1184 bytes), type 31 ML-DSA signature (2420 bytes) |
| `channel_update` record | type 31 ML-DSA signature |
| Gossip relay budget | 8192 bytes of unrecognized data per message (vanilla: 1024 bytes) |
| Feature bits | 139 post-quantum gossip, 141 post-quantum payments (optional, in the init and node features) |
| BOLT 8 acts | act one 2322 bytes (50 classical, 1088 ciphertext, 1184 ephemeral key), act two 1138 bytes (50 classical, 1088 ciphertext), act three 66 bytes unchanged |
| BOLT 11 tagged fields | tag 25 (`e`) ML-DSA public key in three fields, tag 22 (`k`) ML-DSA signature in four fields, at most 639 bytes per field |
| BOLT 12 offer | metadata record (type 4) with the magic `PQO1`, the ML-DSA public key and one (path index, ML-KEM ciphertext) pair per post-quantum message path |
| BOLT 12 invoice and static invoice | record 3000000241 ML-DSA signature, record 3000000243 ML-KEM ciphertext lists of the blinded payment paths, both in the experimental range and covered by the classical signature |
| BOLT 12 refund | record 2000000243 with the ML-KEM ciphertexts of the blinded message paths, covered by the payer metadata HMAC |
| `onion_message` | the receiving hop's ML-KEM ciphertext after the onion packet |
| `update_add_htlc` | record 120009 ciphertext list of 20 entries (21,760 bytes), record 120011 blinded tail list of 10 entries (10,880 bytes) |
| Key derivation | BIP 32 hardened index 9 for the ML-DSA seed and index 10 for the ML-KEM seed, under the node's master key |
| Signature contexts | `LDK-PQ-BOLT7-gossip`, `LDK-PQ-BOLT11-invoice`, `LDK-PQ-BOLT12-invoice`, `LDK-PQ-BOLT12-static-invoice` |
| Hybrid secrets | SHA-256 over a tag, the classical secret and the ML-KEM secret, with the tags `LDK-PQ-payment-onion-hybrid-ss` and `LDK-PQ-blinded-path-hybrid-ss` |
| Per-offer signing seed | HMAC-SHA256 under the node's offer key over the prefix `LDK PQ Offer ~~~` and the offer nonce |

## Implementation Map and API

The fork adds about 11,000 lines, and `git diff 384e0d6` shows every change. The following files hold the post-quantum code.

| Surface | Files |
|---|---|
| Primitives and identity | `lightning/src/sign/pq.rs` (ML-DSA, context strings, gossip records, timing test), `lightning/src/crypto/pq_kem.rs` (ML-KEM, dummy ciphertexts, secret folding), `lightning/src/sign/mod.rs` (the `NodeSigner` methods and the `KeysManager` derivation) |
| Gossip | `lightning/src/routing/gossip.rs` (verification, pinning, relay budget), `lightning/src/ln/peer_handler.rs` (record attachment), `lightning-types/src/features.rs` (feature bits) |
| Transport | `lightning/src/ln/peer_channel_encryptor.rs` (hybrid handshake), `lightning/src/ln/peer_handler.rs` (connection entry points), `lightning-net-tokio/src/lib.rs` (socket helpers) |
| Invoices | `lightning-invoice/src/pq.rs` (tags and chunking), `lightning-invoice/src/lib.rs` (signable bytes), `lightning/src/ln/invoice_utils.rs` (signing and verification), `lightning/src/ln/channelmanager.rs` (pay path) |
| Offers | `lightning/src/offers/pq.rs` (records and per-offer keys), the offer, invoice request, invoice, static invoice, refund, signer and flow modules under `lightning/src/offers/`, `lightning/src/onion_message/messenger.rs`, `lightning/src/onion_message/packet.rs`, `lightning/src/blinded_path/message.rs` |
| Payment onion | `lightning/src/ln/onion_utils.rs` (hybrid onion and ciphertext list), `lightning/src/ln/onion_payment.rs`, `lightning/src/ln/channelmanager.rs`, `lightning/src/ln/outbound_payment.rs`, `lightning/src/routing/router.rs`, `lightning/src/blinded_path/payment.rs`, `lightning/src/blinded_path/utils.rs`, `lightning/src/ln/msgs.rs`, `lightning/src/ln/channel.rs` |
| Configuration | `lightning/src/util/config.rs` |
| Tests | `lightning/src/ln/payment_tests.rs`, `lightning/src/ln/blinded_payment_tests.rs`, `lightning/src/ln/bolt11_payment_tests.rs`, `lightning/src/ln/offers_tests.rs`, `lightning/src/ln/async_payments_tests.rs`, `lightning/src/onion_message/functional_tests.rs`, and the test modules of the files above |

The public API grows by the following items, all behind the feature.

- **Signer.** `NodeSigner` gains `get_pq_node_id`, `sign_pq_gossip_message`, `sign_pq_bolt11_invoice`, `get_pq_kem_node_id` and `pq_kem_decapsulate`, each with a default implementation that returns `None`. `KeysManager` implements all five from the derivation indices above.
- **Graph and routing.** `NodeInfo` exposes the pinned keys through `pq_node_id` and `pq_kem_node_id`. `Router` gains `pq_kem_key_for_node`, `pq_node_id_for_node` and `create_pq_blinded_payment_paths`, and `MessageRouter` gains `create_pq_blinded_paths`. `BlindedMessagePath::new_pq`, `BlindedPaymentPath::new_pq` and `BlindedPaymentPath::new_for_trampoline_pq` build hybrid paths.
- **Transport.** `PeerManager::new_outbound_connection_pq` and `PeerManager::new_inbound_connection_pq` run the hybrid handshake, and `lightning-net-tokio` adds `setup_inbound_pq`, `setup_outbound_pq` and `connect_outbound_pq` on top of them.
- **Invoices.** `Bolt11InvoiceParameters::pq_omit_pubkey` selects the signature-only invoice, `OptionalBolt11PaymentParams::trusted_pq_key` supplies an out-of-band anchor, `Bolt11PaymentError::PqVerificationFailed` reports a refusal, and `verify_bolt11_pq_signature` in `invoice_utils` exposes the verification policy. `lightning_invoice::pq` holds the tags and the chunking helpers, and `RawBolt11Invoice::pq_signable_bytes` returns the signed bytes.
- **Offers.** `Offer::issuer_pq_id` returns the committed key, `Bolt12Invoice::verify_pq_signature` and `StaticInvoice::verify_pq_signature` verify against it, `Bolt12PaymentError::PqVerificationFailed` reports a refusal, and `OffersMessageFlow::with_pq_kem_key` enables post-quantum path building.
- **Configuration and features.** `UserConfig` gains the three fields of the previous section, and the feature types gain the usual setters and queries for the two bits, for example `set_pq_gossip_optional` and `supports_pq_payments`.

## Building and Testing

The fork needs a Rust toolchain at version 1.75 or later, the minimum version declared by the `lightning` crate. The post-quantum crates are pure Rust, but LDK's `bitcoin` dependency compiles `secp256k1-sys` from C, so a C toolchain such as `gcc` or `clang` must be available. We build and test on Linux, and on Windows the fork builds inside WSL2 or any environment that provides a C toolchain.

```bash
# Vanilla build, which must stay green
cargo test -p lightning --lib

# Post-quantum build
cargo test -p lightning --lib --features post-quantum
```

The `post-quantum` feature of the `lightning` crate pulls in the `fips204` and `fips203` crates and enables the matching feature of `lightning-invoice`. The `lightning-net-tokio` crate has its own `post-quantum` feature for the transport helpers. With the feature disabled, the fork passes the complete upstream test suite. With it enabled, the fork also passes 99 added tests. These include adversarial tests for every protected surface, which cover substituted keys, stripped or tampered signatures and records, tampered or dropped ciphertexts and lists, and classical routes or HTLCs under the two enforcement flags. The fork refuses each attack without altering state or moving funds.

An ignored test measures the execution time of every post-quantum primitive through the production entry points, next to the classical secp256k1 operations of the same surfaces. It runs in release mode:

```bash
cargo test -p lightning --lib --features post-quantum --release -- timing_tests --ignored --nocapture
```

The `configurable` branch adds a matching size report and makes the parameter sets selectable at build time, and its [README](https://github.com/ahmet-kurt/pq-rust-lightning/blob/configurable/README.md) describes both. The network measurements of the paper come from real nodes built from [pq-ldk-sample](https://github.com/ahmet-kurt/pq-ldk-sample).

## Coverage and Limitations

The following table lists every sub-surface of the five protected BOLTs and its status in the fork.

| BOLT | Sub-surface | Classical primitive | Post-quantum mechanism | Status |
|---|---|---|---|---|
| 7 | `node_announcement` | Node-key ECDSA | ML-DSA signature, ML-DSA and ML-KEM keys published and pinned on first sight | Protected, always on |
| 7 | `channel_update` | Node-key ECDSA | ML-DSA signature verified against the pin | Protected once the node is pinned |
| 7 | `channel_announcement` | Two node-key and two funding-key ECDSA | None | Classical, two signatures are rooted on-chain |
| 8 | Session keys, responder authentication, forward secrecy | Noise_XK ECDH | Static and ephemeral ML-KEM secrets folded into the chaining key | Protected on the dedicated port |
| 8 | Initiator authentication | Act three ECDH | None | Classical by choice |
| 11 | Invoice signature and verification | Recoverable ECDSA | ML-DSA in chunked tagged fields, verified against the gossip pin or an out-of-band key | Protected when the payee is pinned |
| 11 | First contact with an unannounced payee | Recoverable ECDSA | None, the in-band key is self-asserted | Classical, inherent |
| 11 | Phantom invoices | Recoverable ECDSA | None | Classical |
| 12 | Offer-to-invoice binding, static invoices | Schnorr | Per-offer ML-DSA key committed in the offer, invoice signed under it | Protected for offers with derived keys and blinded paths |
| 12 | Message paths, reply paths, blinded payment paths, refund paths | Per-hop ECDH | Hybrid ML-KEM route blinding | Protected with `build_post_quantum_blinded_paths` |
| 12 | `invoice_request` signature, refund response signature | Schnorr | None, the verifier holds no key for the payer | Classical, inherent |
| 4 | Payment onion, including MPP, keysend, return errors and attribution data | Per-hop ECDH | ML-KEM secret folded into each hop's Sphinx secret, ciphertext list beside the onion | Protected when every hop is pinned |
| 4 | Blinded payment tail | Per-hop ECDH | Recipient-built hybrid cascade, second ciphertext list | Protected with `build_post_quantum_blinded_paths` |
| 4 | Trampoline payments | Per-hop ECDH | The same list carries the trampoline hops' ciphertexts | Protected on the flows implemented upstream |
| 4 | Phantom payments | Per-hop ECDH | None | Classical |
| 4 | Ephemeral key blinding chain | secp256k1 | None needed, it advances public points rather than keys | Not applicable |
| 4 | Enforcement | Policy | `require_post_quantum_payments`, `require_post_quantum_inbound` | Configurable |

The fork has the following limitations.

- **Bitcoin-rooted surfaces are out of scope.** The funding, commitment and HTLC keys of BOLT 3 are secp256k1 and need a Bitcoin consensus change. The same root cause keeps `channel_announcement` classical and keeps BOLTs 2 and 5 out of scope.
- **The protection is trust-on-first-use.** Every payment, transport and blinded-path protection anchors to a node's gossip-pinned keys, and a pin is quantum-safe only if the node established it before a quantum adversary existed. The fork also does not yet rotate pinned keys, although a node needs rotation after a key compromise or for a move to another scheme. The paper discusses two additions that close these gaps without a consensus change.
- **Some signatures stay classical by necessity.** These are the BOLT 12 `invoice_request` and refund response signatures, since the verifier holds no trusted key for the payer, and the BOLT 11 invoice of an unannounced payee at first contact. BOLT 8 initiator authentication stays classical by choice.
- **Key-exchange surfaces have no silent interoperability.** Both ends must be post-quantum-aware, and a blinded path's introduction node is public by design.
- **Phantom payments stay classical**, because they are a rust-lightning feature rather than part of the BOLT specifications.
- **Only the static invoice signature protects asynchronous payments.** A static invoice carries ML-KEM ciphertexts only for its payment paths, so `build_post_quantum_blinded_paths` does not compose with asynchronous receive in the current implementation. Upstream rust-lightning validates and then rejects trampoline forwards, so that unreachable dispatch path stays classical as well.
- **Rapid gossip sync is unchanged.** A client that fetches the graph from a snapshot server receives no pins, although such a server could add the post-quantum keys to its snapshot.
- **The wire assignments are experimental.** The TLV types, invoice tags and feature bits of the previous sections still need assignment through the BOLT process, and we evaluated the fork against rust-lightning nodes only.

## Related Repositories

- [pq-ldk-sample](https://github.com/ahmet-kurt/pq-ldk-sample) is the node implementation that drives this fork with real nodes and ran the network experiments of the paper.
- The [`configurable`](https://github.com/ahmet-kurt/pq-rust-lightning/tree/configurable) branch of this repository makes the ML-DSA and ML-KEM parameter sets selectable at build time and can replace ML-DSA with FN-DSA.
- [rust-lightning](https://github.com/lightningdevkit/rust-lightning) is the upstream project, and [ldk-sample](https://github.com/lightningdevkit/ldk-sample) is the upstream reference node.

## License

Like upstream rust-lightning, this fork is licensed under either the Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)) or the MIT License ([LICENSE-MIT](LICENSE-MIT)), at your option.
