// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Newton Foundation.

//! Deeply nested literals once drove the parser into exponential backtracking
//! (2026-11-25 testnet gateway wedge). Loading them must stay fast whether the
//! parser accepts or rejects them, and must not overflow a default 2 MiB
//! thread stack (an overflow aborts the whole process).

use std::{
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use regorus::Engine;

const BUDGET: Duration = Duration::from_secs(2);

fn load(rego: String) -> (Duration, anyhow::Result<()>) {
    let (tx, rx) = mpsc::channel();
    thread::Builder::new()
        .stack_size(2 << 20)
        .spawn(move || {
            let start = Instant::now();
            let loaded = Engine::new().add_policy("poison.rego".into(), rego).map(drop);
            let _ = tx.send((start.elapsed(), loaded));
        })
        .unwrap();
    rx.recv_timeout(BUDGET)
        .unwrap_or_else(|_| panic!("policy still loading after {BUDGET:?}"))
}

fn nested(depth: usize) -> [String; 2] {
    [
        format!("package p\n\nx := {}{}\n", "[".repeat(depth), "]".repeat(depth)),
        format!("package p\n\nx := {}1{}\n", r#"{"a":"#.repeat(depth), "}".repeat(depth)),
    ]
}

#[test]
fn deep_nesting_is_rejected_quickly() {
    let incident = [
        include_str!("newton_poison/nested_array.rego"),
        include_str!("newton_poison/nested_object.rego"),
    ]
    .map(String::from);
    for rego in incident.into_iter().chain(nested(10_000)) {
        let (elapsed, loaded) = load(rego);
        let err = loaded.expect_err("nesting past the parser depth limit must be rejected");
        assert!(err.to_string().contains("too deep"), "{err:#}");
        assert!(elapsed < BUDGET, "{elapsed:?}");
    }
}

#[test]
fn nesting_below_the_limit_parses_quickly() {
    for rego in nested(24) {
        let (elapsed, loaded) = load(rego);
        loaded.expect("nesting under the limit must parse");
        assert!(elapsed < BUDGET, "{elapsed:?}");
    }
}
