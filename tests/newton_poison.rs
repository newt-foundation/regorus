// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Newton Foundation.

//! Deeply nested literals once drove the parser into exponential backtracking
//! (2026-11-25 testnet gateway wedge). Loading them must stay fast whether the
//! parser accepts or rejects them.

use std::{
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use regorus::Engine;

const BUDGET: Duration = Duration::from_secs(2);

fn load(rego: String) -> (Duration, anyhow::Result<()>) {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let start = Instant::now();
        let loaded = Engine::new().add_policy("poison.rego".into(), rego).map(drop);
        let _ = tx.send((start.elapsed(), loaded));
    });
    rx.recv_timeout(BUDGET)
        .unwrap_or_else(|_| panic!("policy still loading after {BUDGET:?}"))
}

fn policy(x: &str) -> String {
    format!("package p\n\nx := {x}\n")
}

#[test]
fn incident_policies_are_rejected_quickly() {
    for rego in [
        include_str!("newton_poison/nested_array.rego"),
        include_str!("newton_poison/nested_object.rego"),
    ] {
        let (elapsed, loaded) = load(rego.into());
        let err = loaded.expect_err("200-deep nesting must exceed the parser depth limit");
        assert!(err.to_string().contains("too deep"), "{err:#}");
        assert!(elapsed < BUDGET, "{elapsed:?}");
    }
}

#[test]
fn nesting_below_the_limit_parses_quickly() {
    let depth = 24;
    for x in [
        format!("{}{}", "[".repeat(depth), "]".repeat(depth)),
        format!("{}1{}", r#"{"a":"#.repeat(depth), "}".repeat(depth)),
    ] {
        let (elapsed, loaded) = load(policy(&x));
        loaded.expect("nesting under the limit must parse");
        assert!(elapsed < BUDGET, "{elapsed:?}");
    }
}
