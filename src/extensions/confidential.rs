// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Newton Foundation.

//! Newton confidential data extensions for Rego policy evaluation.
//!
//! Provides domain-flexible confidential data checks for policy evaluation.
//! Each confidential data domain (blacklist, allowlist, sanctions, etc.) defines its own
//! data struct, Rego built-in functions, and field accessors.
//!
//! ## Architecture
//!
//! Confidential data is domain-namespaced under `newton.confidential.*`. The domain
//! determines which schema is used to interpret the data and which Rego built-ins
//! are available. Domain is always required — there is no default.
//!
//! Two Rego APIs are provided:
//! - **Domain-namespaced built-ins** (primary): `newton.confidential.blacklist.contains(addr)`,
//!   `newton.confidential.allowlist.count()`. These are type-safe, validate inputs,
//!   and provide specific error messages.
//! - **Generic field accessor** (escape hatch): `newton.confidential.get("field_name")`.
//!   Returns the raw field value from the current domain's data. Useful for rapid
//!   prototyping with new domains before dedicated built-ins are written.
//!
//! ## Address comparison
//!
//! All `contains` checks normalize addresses to lowercase hex before comparison.
//! Both `0x`-prefixed and bare hex strings are accepted.
//!
//! ## Adding a new confidential data domain
//!
//! 1. Define a data struct implementing `PolicyDomainData` with `rego_prefix() -> "confidential"`
//! 2. Add a registration function `register_<domain>_extensions(engine, data)`
//! 3. Add an `Engine::with_newton_confidential_<domain>_extensions()` convenience method
//! 4. Wire up deserialization in the appropriate caller crate
//!
//! See `BlacklistData` below as the canonical example.

extern crate alloc;

use alloc::{
    boxed::Box, collections::BTreeMap, string::String, string::ToString, vec::Vec,
};
use std::sync::{Arc, RwLock};

use crate::{Engine, Value};
use anyhow::{bail, Result};

/// Shared confidential field storage for the generic `newton.confidential.get()` accessor.
///
/// When multiple confidential data domains are registered (e.g., blacklist + allowlist),
/// each domain merges its fields into this shared map. The `newton.confidential.get` closure
/// reads from it, so all domains' fields are accessible through a single extension.
///
/// Pass `None` when registering the first domain, then pass the returned handle
/// to subsequent domain registrations.
pub type SharedConfidentialFields = Arc<RwLock<BTreeMap<String, Value>>>;

use super::PolicyDomainData;

// ---------------------------------------------------------------------------
// Generic registration (works for any domain)
// ---------------------------------------------------------------------------

/// Registers or updates the generic `newton.confidential.get(field_name)` Rego built-in.
///
/// This accessor works across any domain by looking up field names in a shared
/// field map. Returns `undefined` (Rego's "no value") if the field does not
/// exist, allowing policy authors to use `default` patterns.
///
/// **Multi-domain support:** Pass `None` for the first domain registration.
/// The returned `SharedConfidentialFields` handle should be passed to subsequent
/// domain registrations so their fields merge into the same map — the
/// `newton.confidential.get` closure reads from it, making all domains' fields
/// accessible without re-registering the extension.
///
/// This is the escape hatch for rapid prototyping: a team adds a new domain
/// struct with custom fields and can immediately write
/// `newton.confidential.get("some_field")` in Rego without waiting for dedicated
/// domain built-ins.
pub fn register_generic_confidential_extensions(
    engine: &mut Engine,
    data: Box<dyn PolicyDomainData>,
    existing_fields: Option<SharedConfidentialFields>,
) -> Result<SharedConfidentialFields> {
    match existing_fields {
        Some(shared) => {
            // Merge new domain's fields into the existing shared map.
            // The newton.confidential.get closure already reads from this map.
            let new_fields = data.to_field_map();
            let mut map = shared
                .write()
                .map_err(|_| anyhow::anyhow!("confidential fields lock poisoned"))?;
            map.extend(new_fields);
            drop(map);
            Ok(shared)
        }
        None => {
            // First domain: create shared map and register the extension.
            let shared: SharedConfidentialFields = Arc::new(RwLock::new(data.to_field_map()));
            let fields_ref = shared.clone();
            engine.add_extension(
                "newton.confidential.get".to_string(),
                1,
                Box::new(move |params: Vec<Value>| {
                    let field_name = params[0].as_string().map_err(|_| {
                        anyhow::anyhow!("newton.confidential.get expects a string field name")
                    })?;
                    let map = fields_ref
                        .read()
                        .map_err(|_| anyhow::anyhow!("confidential fields lock poisoned"))?;
                    match map.get(field_name.as_ref()) {
                        Some(value) => Ok(value.clone()),
                        None => Ok(Value::Undefined),
                    }
                }),
            )?;
            Ok(shared)
        }
    }
}

// ---------------------------------------------------------------------------
// Blacklist domain
// ---------------------------------------------------------------------------

/// Blacklist domain data — a list of addresses denied by policy.
///
/// ## Fields
///
/// | Field | Type | Description |
/// |-------|------|-------------|
/// | `addresses` | Vec<String> | Hex-encoded Ethereum addresses (with or without `0x` prefix) |
#[derive(Debug, Clone, Default)]
pub struct BlacklistData {
    pub addresses: Vec<String>,
}

impl PolicyDomainData for BlacklistData {
    fn domain_name(&self) -> &str {
        "blacklist"
    }

    fn rego_prefix(&self) -> &str {
        "confidential"
    }

    fn to_field_map(&self) -> BTreeMap<String, Value> {
        let mut m = BTreeMap::new();
        let arr: Vec<Value> = self
            .addresses
            .iter()
            .map(|a| Value::from(a.clone()))
            .collect();
        m.insert("blacklist_addresses".to_string(), Value::from(arr));
        m.insert(
            "blacklist_count".to_string(),
            Value::from(self.addresses.len() as i64),
        );
        m
    }
}

/// Registers all blacklist confidential extensions with the engine.
///
/// Registers 2 domain-namespaced built-ins under `newton.confidential.blacklist.*`:
/// - `newton.confidential.blacklist.contains(address)` — true if address is blacklisted
/// - `newton.confidential.blacklist.count()` — number of entries in the blacklist
///
/// Also registers or merges into the generic `newton.confidential.get(field_name)` accessor.
///
/// Pass `None` for `existing_fields` when blacklist is the first domain. Pass
/// the returned `SharedConfidentialFields` to subsequent domain registrations so all
/// domains share a single `newton.confidential.get` accessor.
pub fn register_blacklist_extensions(
    engine: &mut Engine,
    data: BlacklistData,
    existing_fields: Option<SharedConfidentialFields>,
) -> Result<SharedConfidentialFields> {
    let shared =
        register_generic_confidential_extensions(engine, Box::new(data.clone()), existing_fields)?;

    let bl_contains = data.clone();
    engine.add_extension(
        "newton.confidential.blacklist.contains".to_string(),
        1,
        Box::new(move |params: Vec<Value>| blacklist_contains(params, &bl_contains)),
    )?;

    let bl_count = data.clone();
    engine.add_extension(
        "newton.confidential.blacklist.count".to_string(),
        0,
        Box::new(move |params: Vec<Value>| blacklist_count(params, &bl_count)),
    )?;

    Ok(shared)
}

// ---------------------------------------------------------------------------
// Allowlist domain
// ---------------------------------------------------------------------------

/// Allowlist domain data — a list of addresses permitted by policy.
///
/// ## Fields
///
/// | Field | Type | Description |
/// |-------|------|-------------|
/// | `addresses` | Vec<String> | Hex-encoded Ethereum addresses (with or without `0x` prefix) |
#[derive(Debug, Clone, Default)]
pub struct AllowlistData {
    pub addresses: Vec<String>,
}

impl PolicyDomainData for AllowlistData {
    fn domain_name(&self) -> &str {
        "allowlist"
    }

    fn rego_prefix(&self) -> &str {
        "confidential"
    }

    fn to_field_map(&self) -> BTreeMap<String, Value> {
        let mut m = BTreeMap::new();
        let arr: Vec<Value> = self
            .addresses
            .iter()
            .map(|a| Value::from(a.clone()))
            .collect();
        m.insert("allowlist_addresses".to_string(), Value::from(arr));
        m.insert(
            "allowlist_count".to_string(),
            Value::from(self.addresses.len() as i64),
        );
        m
    }
}

/// Registers all allowlist confidential extensions with the engine.
///
/// Registers 2 domain-namespaced built-ins under `newton.confidential.allowlist.*`:
/// - `newton.confidential.allowlist.contains(address)` — true if address is allowlisted
/// - `newton.confidential.allowlist.count()` — number of entries in the allowlist
///
/// Also registers or merges into the generic `newton.confidential.get(field_name)` accessor.
///
/// Pass `None` for `existing_fields` when allowlist is the first domain. Pass
/// the returned `SharedConfidentialFields` to subsequent domain registrations so all
/// domains share a single `newton.confidential.get` accessor.
pub fn register_allowlist_extensions(
    engine: &mut Engine,
    data: AllowlistData,
    existing_fields: Option<SharedConfidentialFields>,
) -> Result<SharedConfidentialFields> {
    let shared =
        register_generic_confidential_extensions(engine, Box::new(data.clone()), existing_fields)?;

    let al_contains = data.clone();
    engine.add_extension(
        "newton.confidential.allowlist.contains".to_string(),
        1,
        Box::new(move |params: Vec<Value>| allowlist_contains(params, &al_contains)),
    )?;

    let al_count = data.clone();
    engine.add_extension(
        "newton.confidential.allowlist.count".to_string(),
        0,
        Box::new(move |params: Vec<Value>| allowlist_count(params, &al_count)),
    )?;

    Ok(shared)
}

// ---------------------------------------------------------------------------
// Shared address helpers
// ---------------------------------------------------------------------------

/// Normalize an address string to lowercase hex without the `0x` prefix.
fn normalize_address(addr: &str) -> String {
    let stripped = addr.strip_prefix("0x").unwrap_or(addr);
    stripped.to_lowercase()
}

// ---------------------------------------------------------------------------
// Blacklist built-in implementations
// ---------------------------------------------------------------------------

fn blacklist_contains(params: Vec<Value>, data: &BlacklistData) -> Result<Value> {
    let addr = params[0].as_string().map_err(|_| {
        anyhow::anyhow!("newton.confidential.blacklist.contains expects a string address")
    })?;
    if addr.is_empty() {
        bail!("newton.confidential.blacklist.contains expects a non-empty address");
    }
    let normalized = normalize_address(addr.as_ref());
    let found = data
        .addresses
        .iter()
        .any(|a| normalize_address(a) == normalized);
    Ok(Value::from(found))
}

fn blacklist_count(_params: Vec<Value>, data: &BlacklistData) -> Result<Value> {
    Ok(Value::from(data.addresses.len() as i64))
}

// ---------------------------------------------------------------------------
// Allowlist built-in implementations
// ---------------------------------------------------------------------------

fn allowlist_contains(params: Vec<Value>, data: &AllowlistData) -> Result<Value> {
    let addr = params[0].as_string().map_err(|_| {
        anyhow::anyhow!("newton.confidential.allowlist.contains expects a string address")
    })?;
    if addr.is_empty() {
        bail!("newton.confidential.allowlist.contains expects a non-empty address");
    }
    let normalized = normalize_address(addr.as_ref());
    let found = data
        .addresses
        .iter()
        .any(|a| normalize_address(a) == normalized);
    Ok(Value::from(found))
}

fn allowlist_count(_params: Vec<Value>, data: &AllowlistData) -> Result<Value> {
    Ok(Value::from(data.addresses.len() as i64))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn blacklist(addresses: Vec<&str>) -> BlacklistData {
        BlacklistData {
            addresses: addresses.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn allowlist(addresses: Vec<&str>) -> AllowlistData {
        AllowlistData {
            addresses: addresses.iter().map(|s| s.to_string()).collect(),
        }
    }

    // -- PolicyDomainData trait tests --

    #[test]
    fn blacklist_domain_name_is_blacklist() {
        let data = BlacklistData::default();
        assert_eq!(data.domain_name(), "blacklist");
    }

    #[test]
    fn allowlist_domain_name_is_allowlist() {
        let data = AllowlistData::default();
        assert_eq!(data.domain_name(), "allowlist");
    }

    #[test]
    fn blacklist_field_map_contains_addresses_and_count() {
        let data = blacklist(vec!["0xabc", "0xdef"]);
        let fields = data.to_field_map();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields["blacklist_count"], Value::from(2i64));
    }

    #[test]
    fn allowlist_field_map_contains_addresses_and_count() {
        let data = allowlist(vec!["0x123"]);
        let fields = data.to_field_map();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields["allowlist_count"], Value::from(1i64));
    }

    // -- normalize_address tests --

    #[test]
    fn normalize_strips_0x_and_lowercases() {
        assert_eq!(normalize_address("0xABCD"), "abcd");
        assert_eq!(normalize_address("ABCD"), "abcd");
        assert_eq!(normalize_address("0xabcd"), "abcd");
    }

    // -- blacklist_contains tests --

    #[test]
    fn blacklist_contains_exact_match() {
        let data = blacklist(vec!["0xdeadbeef"]);
        let params = vec![Value::from("0xdeadbeef")];
        assert!(blacklist_contains(params, &data).unwrap().as_bool().unwrap());
    }

    #[test]
    fn blacklist_contains_case_insensitive() {
        let data = blacklist(vec!["0xDEADBEEF"]);
        let params = vec![Value::from("0xdeadbeef")];
        assert!(blacklist_contains(params, &data).unwrap().as_bool().unwrap());
    }

    #[test]
    fn blacklist_contains_without_0x_prefix() {
        let data = blacklist(vec!["deadbeef"]);
        let params = vec![Value::from("0xdeadbeef")];
        assert!(blacklist_contains(params, &data).unwrap().as_bool().unwrap());
    }

    #[test]
    fn blacklist_contains_not_found() {
        let data = blacklist(vec!["0xdeadbeef"]);
        let params = vec![Value::from("0xcafebabe")];
        assert!(!blacklist_contains(params, &data).unwrap().as_bool().unwrap());
    }

    #[test]
    fn blacklist_contains_empty_list() {
        let data = blacklist(vec![]);
        let params = vec![Value::from("0xdeadbeef")];
        assert!(!blacklist_contains(params, &data).unwrap().as_bool().unwrap());
    }

    #[test]
    fn blacklist_contains_empty_address_errors() {
        let data = blacklist(vec!["0xdeadbeef"]);
        let params = vec![Value::from("")];
        assert!(blacklist_contains(params, &data).is_err());
    }

    // -- blacklist_count tests --

    #[test]
    fn blacklist_count_returns_length() {
        let data = blacklist(vec!["0xaaa", "0xbbb", "0xccc"]);
        let result = blacklist_count(vec![], &data).unwrap();
        assert_eq!(result, Value::from(3i64));
    }

    #[test]
    fn blacklist_count_empty() {
        let data = blacklist(vec![]);
        let result = blacklist_count(vec![], &data).unwrap();
        assert_eq!(result, Value::from(0i64));
    }

    // -- allowlist_contains tests --

    #[test]
    fn allowlist_contains_exact_match() {
        let data = allowlist(vec!["0xcafebabe"]);
        let params = vec![Value::from("0xcafebabe")];
        assert!(allowlist_contains(params, &data).unwrap().as_bool().unwrap());
    }

    #[test]
    fn allowlist_contains_case_insensitive() {
        let data = allowlist(vec!["0xCAFEBABE"]);
        let params = vec![Value::from("0xcafebabe")];
        assert!(allowlist_contains(params, &data).unwrap().as_bool().unwrap());
    }

    #[test]
    fn allowlist_contains_not_found() {
        let data = allowlist(vec!["0xcafebabe"]);
        let params = vec![Value::from("0xdeadbeef")];
        assert!(!allowlist_contains(params, &data).unwrap().as_bool().unwrap());
    }

    #[test]
    fn allowlist_contains_empty_address_errors() {
        let data = allowlist(vec!["0xcafebabe"]);
        let params = vec![Value::from("")];
        assert!(allowlist_contains(params, &data).is_err());
    }

    // -- allowlist_count tests --

    #[test]
    fn allowlist_count_returns_length() {
        let data = allowlist(vec!["0xaaa", "0xbbb"]);
        let result = allowlist_count(vec![], &data).unwrap();
        assert_eq!(result, Value::from(2i64));
    }

    // -- Generic get tests --

    #[test]
    fn generic_get_returns_blacklist_count() {
        let mut engine = Engine::new();
        let data = blacklist(vec!["0xabc", "0xdef"]);
        register_generic_confidential_extensions(&mut engine, Box::new(data), None).unwrap();

        engine
            .add_policy(
                "test.rego".to_string(),
                r#"
                package test
                count = newton.confidential.get("blacklist_count")
                missing = newton.confidential.get("nonexistent")
                "#
                .to_string(),
            )
            .unwrap();

        engine.set_input(Value::from_json_str("{}").unwrap());

        let count = engine.eval_rule("data.test.count".to_string()).unwrap();
        assert_eq!(count, Value::from(2i64));

        let missing = engine.eval_rule("data.test.missing".to_string()).unwrap();
        assert_eq!(missing, Value::Undefined);
    }

    #[test]
    fn generic_get_merges_multiple_domains() {
        let mut engine = Engine::new();
        let bl = blacklist(vec!["0xabc"]);
        let al = allowlist(vec!["0x111", "0x222"]);

        let shared =
            register_generic_confidential_extensions(&mut engine, Box::new(bl), None).unwrap();
        register_generic_confidential_extensions(&mut engine, Box::new(al), Some(shared)).unwrap();

        engine
            .add_policy(
                "test.rego".to_string(),
                r#"
                package test
                bl_count = newton.confidential.get("blacklist_count")
                al_count = newton.confidential.get("allowlist_count")
                "#
                .to_string(),
            )
            .unwrap();

        engine.set_input(Value::from_json_str("{}").unwrap());

        let bl_count = engine.eval_rule("data.test.bl_count".to_string()).unwrap();
        assert_eq!(bl_count, Value::from(1i64));

        let al_count = engine.eval_rule("data.test.al_count".to_string()).unwrap();
        assert_eq!(al_count, Value::from(2i64));
    }

    // -- Full engine integration tests --

    #[test]
    fn engine_blacklist_contains_rego() {
        let mut engine = Engine::new();
        let data = blacklist(vec!["0xdeadbeef", "0xcafebabe"]);
        register_blacklist_extensions(&mut engine, data, None).unwrap();

        engine
            .add_policy(
                "test.rego".to_string(),
                r#"
                package test
                blocked = newton.confidential.blacklist.contains("0xdeadbeef")
                not_blocked = newton.confidential.blacklist.contains("0x12345678")
                count = newton.confidential.blacklist.count()
                "#
                .to_string(),
            )
            .unwrap();

        engine.set_input(Value::from_json_str("{}").unwrap());

        let blocked = engine.eval_rule("data.test.blocked".to_string()).unwrap();
        assert!(blocked.as_bool().unwrap());

        let not_blocked = engine.eval_rule("data.test.not_blocked".to_string()).unwrap();
        assert!(!not_blocked.as_bool().unwrap());

        let count = engine.eval_rule("data.test.count".to_string()).unwrap();
        assert_eq!(count, Value::from(2i64));
    }

    #[test]
    fn engine_allowlist_contains_rego() {
        let mut engine = Engine::new();
        let data = allowlist(vec!["0xABCDEF"]);
        register_allowlist_extensions(&mut engine, data, None).unwrap();

        engine
            .add_policy(
                "test.rego".to_string(),
                r#"
                package test
                allowed = newton.confidential.allowlist.contains("0xabcdef")
                not_allowed = newton.confidential.allowlist.contains("0x000000")
                count = newton.confidential.allowlist.count()
                "#
                .to_string(),
            )
            .unwrap();

        engine.set_input(Value::from_json_str("{}").unwrap());

        let allowed = engine.eval_rule("data.test.allowed".to_string()).unwrap();
        assert!(allowed.as_bool().unwrap());

        let not_allowed = engine.eval_rule("data.test.not_allowed".to_string()).unwrap();
        assert!(!not_allowed.as_bool().unwrap());

        let count = engine.eval_rule("data.test.count".to_string()).unwrap();
        assert_eq!(count, Value::from(1i64));
    }

    #[test]
    fn engine_blacklist_and_allowlist_together() {
        let mut engine = Engine::new();
        let bl = blacklist(vec!["0xbad"]);
        let al = allowlist(vec!["0xgood"]);

        let shared = register_blacklist_extensions(&mut engine, bl, None).unwrap();
        register_allowlist_extensions(&mut engine, al, Some(shared)).unwrap();

        engine
            .add_policy(
                "test.rego".to_string(),
                r#"
                package test
                allow if {
                    not newton.confidential.blacklist.contains(input.addr)
                    newton.confidential.allowlist.contains(input.addr)
                }
                "#
                .to_string(),
            )
            .unwrap();

        engine.set_input(Value::from_json_str(r#"{"addr": "0xgood"}"#).unwrap());
        let result = engine.eval_rule("data.test.allow".to_string()).unwrap();
        assert!(result.as_bool().unwrap());

        engine.set_input(Value::from_json_str(r#"{"addr": "0xbad"}"#).unwrap());
        let result = engine.eval_rule("data.test.allow".to_string()).unwrap();
        // blacklist.contains returns true, so "not" fails, allow is undefined
        assert_eq!(result, Value::Undefined);
    }
}
