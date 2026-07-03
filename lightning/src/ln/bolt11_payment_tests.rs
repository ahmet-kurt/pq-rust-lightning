// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Tests for verifying the correct end-to-end handling of BOLT11 payments, including metadata propagation.

use crate::events::Event;
use crate::ln::channelmanager::{OptionalBolt11PaymentParams, PaymentId};
use crate::ln::functional_test_utils::*;
use crate::ln::msgs::ChannelMessageHandler;
use crate::ln::outbound_payment::Bolt11PaymentError;
use crate::sign::{NodeSigner, Recipient};
use lightning_invoice::{Bolt11Invoice, Currency, InvoiceBuilder};
use std::time::SystemTime;

#[test]
fn payment_metadata_end_to_end_for_invoice_with_amount() {
	// Test that a payment metadata read from an invoice passed to `pay_invoice` makes it all
	// the way out through the `PaymentClaimable` event.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes(&nodes, 0, 1);

	let payment_metadata = vec![42, 43, 44, 45, 46, 47, 48, 49, 42];

	let (payment_hash, payment_secret, encrypted_metadata) = nodes[1]
		.node
		.create_inbound_payment(None, 7200, None, Some(payment_metadata.clone()))
		.unwrap();

	let timestamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
	let invoice = InvoiceBuilder::new(Currency::Bitcoin)
		.description("test".into())
		.payment_hash(payment_hash)
		.payment_secret(payment_secret)
		.duration_since_epoch(timestamp)
		.min_final_cltv_expiry_delta(144)
		.amount_milli_satoshis(50_000)
		.payment_metadata(encrypted_metadata.unwrap())
		.build_raw()
		.unwrap();
	let sig = nodes[1].keys_manager.backing.sign_invoice(&invoice, Recipient::Node).unwrap();
	let invoice = invoice.sign::<_, ()>(|_| Ok(sig)).unwrap();
	let invoice = Bolt11Invoice::from_signed(invoice).unwrap();

	match nodes[0].node.pay_for_bolt11_invoice(
		&invoice,
		PaymentId(payment_hash.0),
		Some(100),
		OptionalBolt11PaymentParams::default(),
	) {
		Err(Bolt11PaymentError::InvalidAmount) => (),
		_ => panic!("Unexpected result"),
	};

	nodes[0]
		.node
		.pay_for_bolt11_invoice(
			&invoice,
			PaymentId(payment_hash.0),
			None,
			OptionalBolt11PaymentParams::default(),
		)
		.unwrap();

	check_added_monitors(&nodes[0], 1);
	let send_event = SendEvent::from_node(&nodes[0]);
	nodes[1].node.handle_update_add_htlc(nodes[0].node.get_our_node_id(), &send_event.msgs[0]);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &send_event.commitment_msg, false, false);

	expect_and_process_pending_htlcs(&nodes[1], false);

	let mut events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events.pop().unwrap() {
		Event::PaymentClaimable { onion_fields, .. } => {
			assert_eq!(Some(payment_metadata), onion_fields.unwrap().payment_metadata);
		},
		_ => panic!("Unexpected event"),
	}
}

#[test]
fn payment_metadata_end_to_end_for_invoice_with_no_amount() {
	// Test that a payment metadata read from an invoice passed to `pay_invoice` makes it all
	// the way out through the `PaymentClaimable` event.
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes(&nodes, 0, 1);

	let payment_metadata = vec![42, 43, 44, 45, 46, 47, 48, 49, 42];

	let (payment_hash, payment_secret, encrypted_metadata) = nodes[1]
		.node
		.create_inbound_payment(None, 7200, None, Some(payment_metadata.clone()))
		.unwrap();

	let timestamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
	let invoice = InvoiceBuilder::new(Currency::Bitcoin)
		.description("test".into())
		.payment_hash(payment_hash)
		.payment_secret(payment_secret)
		.duration_since_epoch(timestamp)
		.min_final_cltv_expiry_delta(144)
		.payment_metadata(encrypted_metadata.unwrap())
		.build_raw()
		.unwrap();
	let sig = nodes[1].keys_manager.backing.sign_invoice(&invoice, Recipient::Node).unwrap();
	let invoice = invoice.sign::<_, ()>(|_| Ok(sig)).unwrap();
	let invoice = Bolt11Invoice::from_signed(invoice).unwrap();

	match nodes[0].node.pay_for_bolt11_invoice(
		&invoice,
		PaymentId(payment_hash.0),
		None,
		OptionalBolt11PaymentParams::default(),
	) {
		Err(Bolt11PaymentError::InvalidAmount) => (),
		_ => panic!("Unexpected result"),
	};

	nodes[0]
		.node
		.pay_for_bolt11_invoice(
			&invoice,
			PaymentId(payment_hash.0),
			Some(50_000),
			OptionalBolt11PaymentParams::default(),
		)
		.unwrap();

	check_added_monitors(&nodes[0], 1);
	let send_event = SendEvent::from_node(&nodes[0]);
	nodes[1].node.handle_update_add_htlc(nodes[0].node.get_our_node_id(), &send_event.msgs[0]);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &send_event.commitment_msg, false, false);

	expect_and_process_pending_htlcs(&nodes[1], false);

	let mut events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events.pop().unwrap() {
		Event::PaymentClaimable { onion_fields, .. } => {
			assert_eq!(Some(payment_metadata), onion_fields.unwrap().payment_metadata);
		},
		_ => panic!("Unexpected event"),
	}
}

#[cfg(feature = "post-quantum")]
#[test]
fn pq_bolt11_auto_anchors_to_gossip_pin() {
	// The payer enforces the post-quantum signature AUTOMATICALLY when it holds the payee's
	// gossip-pinned ML-DSA key, with no caller-supplied trusted key (the default params). A correctly
	// signed invoice is paid; a downgraded (classical) invoice from the same pinned payee is refused.
	// Without the auto-anchor an unanchored invoice would simply be paid, so this proves the opt-in
	// gap is closed and BOLT 11 now matches the automatic gossip and BOLT 12 invoice enforcement.
	use crate::ln::channelmanager::Bolt11InvoiceParameters;
	use lightning_invoice::{PaymentHash, PaymentSecret};

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes(&nodes, 0, 1);

	let payee_id = nodes[1].node.get_our_node_id();
	let payee_pin =
		nodes[1].keys_manager.get_pq_node_id().expect("payee has a post-quantum identity");
	// In production the payer reads this from the payee's gossip-pinned `NodeInfo::pq_node_id`; the
	// test harness injects it into the payer's router directly.
	nodes[0].router.pq_node_ids.lock().unwrap().insert(payee_id, payee_pin);

	// A correctly signed invoice is paid with DEFAULT params (no trusted_pq_key): the auto-anchor
	// binds the signature to the pin and verification passes.
	let invoice = nodes[1]
		.node
		.create_bolt11_invoice(Bolt11InvoiceParameters {
			amount_msats: Some(10_000),
			..Default::default()
		})
		.unwrap();
	let payment_hash = invoice.payment_hash();
	nodes[0]
		.node
		.pay_for_bolt11_invoice(
			&invoice,
			PaymentId(payment_hash.0),
			None,
			OptionalBolt11PaymentParams::default(),
		)
		.unwrap();
	check_added_monitors(&nodes[0], 1);
	let send_event = SendEvent::from_node(&nodes[0]);
	nodes[1].node.handle_update_add_htlc(nodes[0].node.get_our_node_id(), &send_event.msgs[0]);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &send_event.commitment_msg, false, false);
	expect_and_process_pending_htlcs(&nodes[1], false);
	let mut events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events.pop().unwrap() {
		Event::PaymentClaimable { .. } => {},
		_ => panic!("expected PaymentClaimable"),
	}

	// Adversarial: a vanilla (classical) invoice from the same pinned payee is refused as a downgrade
	// with DEFAULT params, because the auto-anchor finds the pin. Without the auto-anchor this would
	// have been paid.
	let timestamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
	let raw = InvoiceBuilder::new(Currency::Bitcoin)
		.description("downgrade".into())
		.payment_hash(PaymentHash([7; 32]))
		.payment_secret(PaymentSecret([8; 32]))
		.duration_since_epoch(timestamp)
		.min_final_cltv_expiry_delta(144)
		.build_raw()
		.unwrap();
	let sig = nodes[1].keys_manager.backing.sign_invoice(&raw, Recipient::Node).unwrap();
	let vanilla = Bolt11Invoice::from_signed(raw.sign::<_, ()>(|_| Ok(sig)).unwrap()).unwrap();
	match nodes[0].node.pay_for_bolt11_invoice(
		&vanilla,
		PaymentId([9; 32]),
		None,
		OptionalBolt11PaymentParams::default(),
	) {
		Err(Bolt11PaymentError::PqVerificationFailed) => {},
		other => panic!("expected PqVerificationFailed for auto-anchored downgrade, got {:?}", other),
	}
}

#[cfg(feature = "post-quantum")]
#[test]
fn pay_for_bolt11_invoice_enforces_pq_signature() {
	// End-to-end: the payee's invoice carries a hybrid post-quantum signature, and the payer binds
	// it to the payee's pinned ML-DSA key before paying. Substitution and downgrade are refused; the
	// correctly-pinned invoice is paid through to the payee.
	use crate::ln::channelmanager::Bolt11InvoiceParameters;
	use crate::sign::NodeSigner;
	use lightning_invoice::{PaymentHash, PaymentSecret};

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	create_announced_chan_between_nodes(&nodes, 0, 1);

	// The payee creates an invoice; the post-quantum signature is attached automatically.
	let invoice = nodes[1]
		.node
		.create_bolt11_invoice(Bolt11InvoiceParameters {
			amount_msats: Some(10_000),
			..Default::default()
		})
		.unwrap();
	let payment_hash = invoice.payment_hash();
	let payee_pin =
		nodes[1].keys_manager.get_pq_node_id().expect("payee has a post-quantum identity");

	// A trusted key that does not match the invoice's key (a key-substitution attempt) is refused
	// before the payment is sent.
	let mut wrong_key_params = OptionalBolt11PaymentParams::default();
	wrong_key_params.trusted_pq_key = Some([0u8; 1312]);
	match nodes[0].node.pay_for_bolt11_invoice(&invoice, PaymentId([1; 32]), None, wrong_key_params)
	{
		Err(Bolt11PaymentError::PqVerificationFailed) => {},
		other => panic!("expected PqVerificationFailed, got {:?}", other),
	}

	// A vanilla invoice from a payee we hold a pin for is refused as a downgrade.
	let timestamp = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
	let raw = InvoiceBuilder::new(Currency::Bitcoin)
		.description("downgrade".into())
		.payment_hash(PaymentHash([7; 32]))
		.payment_secret(PaymentSecret([8; 32]))
		.duration_since_epoch(timestamp)
		.min_final_cltv_expiry_delta(144)
		.build_raw()
		.unwrap();
	let sig = nodes[1].keys_manager.backing.sign_invoice(&raw, Recipient::Node).unwrap();
	let vanilla = Bolt11Invoice::from_signed(raw.sign::<_, ()>(|_| Ok(sig)).unwrap()).unwrap();
	let mut downgrade_params = OptionalBolt11PaymentParams::default();
	downgrade_params.trusted_pq_key = Some(payee_pin);
	match nodes[0].node.pay_for_bolt11_invoice(&vanilla, PaymentId([9; 32]), None, downgrade_params)
	{
		Err(Bolt11PaymentError::PqVerificationFailed) => {},
		other => panic!("expected PqVerificationFailed for downgrade, got {:?}", other),
	}

	// The correct pinned key lets the payment through, and it flows to the payee.
	let mut params = OptionalBolt11PaymentParams::default();
	params.trusted_pq_key = Some(payee_pin);
	nodes[0]
		.node
		.pay_for_bolt11_invoice(&invoice, PaymentId(payment_hash.0), None, params)
		.unwrap();

	check_added_monitors(&nodes[0], 1);
	let send_event = SendEvent::from_node(&nodes[0]);
	nodes[1].node.handle_update_add_htlc(nodes[0].node.get_our_node_id(), &send_event.msgs[0]);
	do_commitment_signed_dance(&nodes[1], &nodes[0], &send_event.commitment_msg, false, false);
	expect_and_process_pending_htlcs(&nodes[1], false);
	let mut events = nodes[1].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	match events.pop().unwrap() {
		Event::PaymentClaimable { .. } => {},
		_ => panic!("expected PaymentClaimable"),
	}
}
