// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Newton Foundation.

//! Newton privacy extensions for Rego policy evaluation.
//!
//! Provides domain-flexible privacy data checks for policy evaluation.
//! Each privacy domain (KYC, social, credit, professional, etc.) defines its own
//! data struct, Rego built-in functions, and field accessors.
//!
//! ## Architecture
//!
//! Privacy data is domain-namespaced. The `identity_domain` (bytes32) stored on-chain
//! determines which schema is used to deserialize the data and which Rego built-ins
//! are available. Domain is always required — there is no default.
//!
//! Two Rego APIs are provided:
//! - **Domain-namespaced built-ins** (primary): `newton.privacy.kyc.age_gte(21)`,
//!   `newton.privacy.kyc.check_approved()`. These are type-safe, validate inputs,
//!   and provide specific error messages.
//! - **Generic field accessor** (escape hatch): `newton.privacy.get("field_name")`.
//!   Returns the raw field value from the current domain's data. Useful for rapid
//!   prototyping with new domains before dedicated built-ins are written.
//!
//! ## Adding a new privacy domain
//!
//! 1. Define a data struct implementing `PrivacyDomainData`
//! 2. Add a registration function `register_<domain>_extensions(engine, data)`
//! 3. Add an `Engine::with_newton_privacy_<domain>_extensions()` convenience method
//! 4. Wire up deserialization in `crates/chainio/src/privacy_data.rs`
//!
//! See `KycPrivacyData` below as the canonical example.

extern crate alloc;

use alloc::{
    boxed::Box, collections::BTreeMap, format, string::String, string::ToString, vec::Vec,
};
use chrono::prelude::*;
use std::sync::{Arc, RwLock};

use crate::{Engine, Value};
use anyhow::{bail, Result};

const PARSE_FORMAT: &str = "%Y-%m-%d";

/// Shared privacy field storage for the generic `newton.privacy.get()` accessor.
///
/// When multiple privacy domains are registered (e.g., KYC + social), each domain
/// merges its fields into this shared map. The `newton.privacy.get` closure reads
/// from it, so all domains' fields are accessible through a single extension.
///
/// Pass `None` when registering the first domain, then pass the returned handle
/// to subsequent domain registrations.
pub type SharedPrivacyFields = Arc<RwLock<BTreeMap<String, Value>>>;

// ---------------------------------------------------------------------------
// Domain trait
// ---------------------------------------------------------------------------

/// Trait that all privacy domain data structs must implement.
///
/// Each domain (KYC, social, credit, etc.) provides:
/// - A domain name for Rego namespace routing
/// - A reference date for time-based comparisons
/// - A flat field map for the generic `newton.privacy.get()` accessor
///
/// The generic `get` accessor enables policy authors to use new domain fields
/// immediately, without waiting for domain-specific built-in functions.
pub trait PrivacyDomainData: Send + Sync + std::fmt::Debug {
    /// The domain name used for Rego namespace routing (e.g., "kyc", "social").
    fn domain_name(&self) -> &str;

    /// Reference timestamp as YYYY-MM-DD, used for time-based comparisons.
    fn reference_date(&self) -> &str;

    /// Returns all fields as a flat string→Value map for the generic `get` accessor.
    /// Keys should match the struct field names exactly.
    fn to_field_map(&self) -> BTreeMap<String, Value>;
}

// ---------------------------------------------------------------------------
// Generic registration (works for any domain)
// ---------------------------------------------------------------------------

/// Registers or updates the generic `newton.privacy.get(field_name)` Rego built-in.
///
/// This accessor works across any domain by looking up field names in a shared
/// field map. Returns `undefined` (Rego's "no value") if the field does not
/// exist, allowing policy authors to use `default` patterns.
///
/// **Multi-domain support:** Pass `None` for the first domain registration.
/// The returned `SharedPrivacyFields` handle should be passed to subsequent
/// domain registrations so their fields merge into the same map — the
/// `newton.privacy.get` closure reads from it, making all domains' fields
/// accessible without re-registering the extension.
///
/// This is the escape hatch for rapid prototyping: a team adds a new domain
/// struct with fields like `platform`, `handle`, `follower_count` and can
/// immediately write `newton.privacy.get("follower_count") >= 1000` in Rego
/// without waiting for `newton.privacy.social.follower_count_gte()`.
pub fn register_generic_privacy_extensions(
    engine: &mut Engine,
    data: Box<dyn PrivacyDomainData>,
    existing_fields: Option<SharedPrivacyFields>,
) -> Result<SharedPrivacyFields> {
    match existing_fields {
        Some(shared) => {
            // Merge new domain's fields into the existing shared map.
            // The newton.privacy.get closure already reads from this map.
            let new_fields = data.to_field_map();
            let mut map = shared
                .write()
                .map_err(|_| anyhow::anyhow!("privacy fields lock poisoned"))?;
            map.extend(new_fields);
            drop(map);
            Ok(shared)
        }
        None => {
            // First domain: create shared map and register the extension.
            let shared: SharedPrivacyFields = Arc::new(RwLock::new(data.to_field_map()));
            let fields_ref = shared.clone();
            engine.add_extension(
                "newton.privacy.get".to_string(),
                1,
                Box::new(move |params: Vec<Value>| {
                    let field_name = params[0].as_string().map_err(|_| {
                        anyhow::anyhow!("newton.privacy.get expects a string field name")
                    })?;
                    let map = fields_ref
                        .read()
                        .map_err(|_| anyhow::anyhow!("privacy fields lock poisoned"))?;
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
// KYC domain
// ---------------------------------------------------------------------------

/// KYC (Know Your Customer) privacy data.
///
/// This is the first implemented privacy domain. All 8 original
/// `newton.privacy.*` built-ins have been migrated to the `newton.privacy.kyc.*`
/// namespace. Domain is always required — these functions are not registered
/// under the bare `newton.privacy.*` prefix.
///
/// ## Fields
///
/// | Field | Type | Description |
/// |-------|------|-------------|
/// | `reference_date` | YYYY-MM-DD | Timestamp of "now" for time-based checks |
/// | `status` | String | KYC status: approved, pending, completed, failed, expired, declined |
/// | `selected_country_code` | ISO 3166-1 alpha-2 | Country selected during KYC process |
/// | `address_subdivision` | String | State/province from document address |
/// | `address_country_code` | ISO 3166-1 alpha-2 | Country from document address |
/// | `birthdate` | YYYY-MM-DD | Date of birth |
/// | `expiration_date` | YYYY-MM-DD | Document expiration date |
/// | `issue_date` | YYYY-MM-DD | Document issuance date |
/// | `issuing_authority` | String | Issuing country or state |
#[derive(Debug, Clone, Default)]
pub struct KycPrivacyData {
    pub reference_date: String,
    pub status: String,
    pub selected_country_code: String,
    pub address_subdivision: String,
    pub address_country_code: String,
    pub birthdate: String,
    pub expiration_date: String,
    pub issue_date: String,
    pub issuing_authority: String,
}

impl PrivacyDomainData for KycPrivacyData {
    fn domain_name(&self) -> &str {
        "kyc"
    }

    fn reference_date(&self) -> &str {
        &self.reference_date
    }

    fn to_field_map(&self) -> BTreeMap<String, Value> {
        let mut m = BTreeMap::new();
        m.insert(
            "reference_date".to_string(),
            Value::from(self.reference_date.clone()),
        );
        m.insert("status".to_string(), Value::from(self.status.clone()));
        m.insert(
            "selected_country_code".to_string(),
            Value::from(self.selected_country_code.clone()),
        );
        m.insert(
            "address_subdivision".to_string(),
            Value::from(self.address_subdivision.clone()),
        );
        m.insert(
            "address_country_code".to_string(),
            Value::from(self.address_country_code.clone()),
        );
        m.insert("birthdate".to_string(), Value::from(self.birthdate.clone()));
        m.insert(
            "expiration_date".to_string(),
            Value::from(self.expiration_date.clone()),
        );
        m.insert(
            "issue_date".to_string(),
            Value::from(self.issue_date.clone()),
        );
        m.insert(
            "issuing_authority".to_string(),
            Value::from(self.issuing_authority.clone()),
        );
        m
    }
}

/// Registers all KYC privacy extensions with the engine.
///
/// Registers 8 domain-namespaced built-ins under `newton.privacy.kyc.*`.
/// Also registers the generic `newton.privacy.get(field_name)` accessor
/// for field-level access without dedicated built-ins.
///
/// Pass `None` for `existing_fields` when KYC is the first domain. Pass
/// the returned `SharedPrivacyFields` to subsequent domain registrations
/// so all domains share a single `newton.privacy.get` accessor.
pub fn register_kyc_privacy_extensions(
    engine: &mut Engine,
    data: KycPrivacyData,
    existing_fields: Option<SharedPrivacyFields>,
) -> Result<SharedPrivacyFields> {
    // Register generic accessor (creates or merges into shared field map)
    let shared =
        register_generic_privacy_extensions(engine, Box::new(data.clone()), existing_fields)?;

    let id_approve = data.clone();
    engine.add_extension(
        "newton.privacy.kyc.check_approved".to_string(),
        0,
        Box::new(move |params: Vec<Value>| kyc_check_approved(params, &id_approve)),
    )?;

    let id_country = data.clone();
    engine.add_extension(
        "newton.privacy.kyc.address_in_countries".to_string(),
        1,
        Box::new(move |params: Vec<Value>| kyc_address_in_countries(params, &id_country)),
    )?;

    let id_state = data.clone();
    engine.add_extension(
        "newton.privacy.kyc.address_in_subdivision".to_string(),
        1,
        Box::new(move |params: Vec<Value>| kyc_address_in_subdivision(params, &id_state)),
    )?;

    let id_not_state = data.clone();
    engine.add_extension(
        "newton.privacy.kyc.address_not_in_subdivision".to_string(),
        1,
        Box::new(move |params: Vec<Value>| kyc_address_not_in_subdivision(params, &id_not_state)),
    )?;

    let id_age = data.clone();
    engine.add_extension(
        "newton.privacy.kyc.age_gte".to_string(),
        1,
        Box::new(move |params: Vec<Value>| kyc_age_gte(params, &id_age)),
    )?;

    let id_not_expired = data.clone();
    engine.add_extension(
        "newton.privacy.kyc.not_expired".to_string(),
        0,
        Box::new(move |params: Vec<Value>| kyc_not_expired(params, &id_not_expired)),
    )?;

    let id_valid_for = data.clone();
    engine.add_extension(
        "newton.privacy.kyc.valid_for".to_string(),
        1,
        Box::new(move |params: Vec<Value>| kyc_valid_for(params, &id_valid_for)),
    )?;

    let id_issued_since = data.clone();
    engine.add_extension(
        "newton.privacy.kyc.issued_since".to_string(),
        1,
        Box::new(move |params: Vec<Value>| kyc_issued_since(params, &id_issued_since)),
    )?;

    Ok(shared)
}

// ---------------------------------------------------------------------------
// KYC built-in implementations
// ---------------------------------------------------------------------------

fn kyc_check_approved(_params: Vec<Value>, data: &KycPrivacyData) -> Result<Value> {
    Ok(Value::from(data.status == "approved"))
}

fn kyc_address_in_countries(params: Vec<Value>, data: &KycPrivacyData) -> Result<Value> {
    match &params[0].as_array() {
        Ok(countries) => {
            if countries.is_empty() {
                bail!("newton.privacy.kyc.address_in_countries expects a non-empty array")
            }

            if data.address_country_code.is_empty() {
                bail!("newton.privacy.kyc.address_in_countries requires non-empty address_country_code");
            }

            Ok(Value::from(
                data.address_country_code.len() == 2
                    && countries.contains(&Value::from(data.address_country_code.clone())),
            ))
        }
        _ => bail!(
            "newton.privacy.kyc.address_in_countries expects an array of string country codes"
        ),
    }
}

fn kyc_address_in_subdivision(params: Vec<Value>, data: &KycPrivacyData) -> Result<Value> {
    match &params[0].as_array() {
        Ok(states) => {
            if states.is_empty() {
                bail!("newton.privacy.kyc.address_in_subdivision expects a non-empty array")
            }

            if data.address_country_code.is_empty() || data.address_subdivision.is_empty() {
                bail!("newton.privacy.kyc.address_in_subdivision requires non-empty address_country_code and address_subdivision");
            }

            Ok(Value::from(states.contains(&Value::from(format!(
                "{}-{}",
                data.address_country_code, data.address_subdivision
            )))))
        }
        _ => {
            bail!("newton.privacy.kyc.address_in_subdivision expects an array of string iso codes")
        }
    }
}

fn kyc_address_not_in_subdivision(params: Vec<Value>, data: &KycPrivacyData) -> Result<Value> {
    match &params[0].as_array() {
        Ok(states) => {
            if states.is_empty() {
                bail!("newton.privacy.kyc.address_not_in_subdivision expects a non-empty array")
            }

            if data.address_country_code.is_empty() || data.address_subdivision.is_empty() {
                bail!("newton.privacy.kyc.address_not_in_subdivision requires non-empty address_country_code and address_subdivision");
            }

            Ok(Value::from(!states.contains(&Value::from(format!(
                "{}-{}",
                data.address_country_code, data.address_subdivision
            )))))
        }
        _ => {
            bail!("newton.privacy.kyc.address_not_in_subdivision expects an array of string iso codes")
        }
    }
}

fn kyc_age_gte(params: Vec<Value>, data: &KycPrivacyData) -> Result<Value> {
    match params[0].as_i64() {
        Ok(min_age) => {
            if min_age <= 0 {
                bail!("newton.privacy.kyc.age_gte expects a positive valued age")
            }

            let now = NaiveDate::parse_from_str(&data.reference_date, PARSE_FORMAT)?;
            let birthdate = NaiveDate::parse_from_str(&data.birthdate, PARSE_FORMAT)?;

            match now.years_since(birthdate) {
                Some(years) => Ok(Value::from(min_age <= years.into())),
                _ => bail!(
                    "newton.privacy.kyc.age_gte received invalid birthdate or reference date"
                ),
            }
        }
        _ => bail!("newton.privacy.kyc.age_gte expects a number"),
    }
}

fn kyc_not_expired(_params: Vec<Value>, data: &KycPrivacyData) -> Result<Value> {
    let now = NaiveDate::parse_from_str(&data.reference_date, PARSE_FORMAT)?;
    let expiration = NaiveDate::parse_from_str(&data.expiration_date, PARSE_FORMAT)?;

    Ok(Value::from(now.le(&expiration)))
}

fn kyc_valid_for(params: Vec<Value>, data: &KycPrivacyData) -> Result<Value> {
    match params[0].as_i64() {
        Ok(num_days) => {
            if num_days <= 0 {
                bail!("newton.privacy.kyc.valid_for expects a positive number of days")
            }

            let now = NaiveDate::parse_from_str(&data.reference_date, PARSE_FORMAT)?;
            let expiration = NaiveDate::parse_from_str(&data.expiration_date, PARSE_FORMAT)?;

            Ok(Value::from(num_days <= (expiration - now).num_days()))
        }
        _ => bail!("newton.privacy.kyc.valid_for expects a number"),
    }
}

fn kyc_issued_since(params: Vec<Value>, data: &KycPrivacyData) -> Result<Value> {
    match params[0].as_i64() {
        Ok(num_days) => {
            if num_days <= 0 {
                bail!("newton.privacy.kyc.issued_since expects a positive number of days")
            }

            let now = NaiveDate::parse_from_str(&data.reference_date, PARSE_FORMAT)?;
            let issuance = NaiveDate::parse_from_str(&data.issue_date, PARSE_FORMAT)?;

            Ok(Value::from(num_days <= (now - issuance).num_days()))
        }
        _ => bail!("newton.privacy.kyc.issued_since expects a number"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn kyc_data(overrides: impl FnOnce(&mut KycPrivacyData)) -> KycPrivacyData {
        let mut data = KycPrivacyData::default();
        overrides(&mut data);
        data
    }

    // -- PrivacyDomainData trait tests --

    #[test]
    fn domain_name_is_kyc() {
        let data = KycPrivacyData::default();
        assert_eq!(data.domain_name(), "kyc");
    }

    #[test]
    fn field_map_contains_all_fields() {
        let data = kyc_data(|d| {
            d.reference_date = "2026-01-01".to_string();
            d.status = "approved".to_string();
            d.selected_country_code = "US".to_string();
            d.address_subdivision = "CA".to_string();
            d.address_country_code = "US".to_string();
            d.birthdate = "1990-01-01".to_string();
            d.expiration_date = "2030-01-01".to_string();
            d.issue_date = "2020-01-01".to_string();
            d.issuing_authority = "CA".to_string();
        });

        let fields = data.to_field_map();
        assert_eq!(fields.len(), 9);
        assert_eq!(fields["status"], Value::from("approved"));
        assert_eq!(fields["birthdate"], Value::from("1990-01-01"));
        assert_eq!(fields["address_country_code"], Value::from("US"));
    }

    // -- Generic get tests --

    #[test]
    fn generic_get_returns_field_value() {
        let mut engine = Engine::new();
        let data = kyc_data(|d| {
            d.status = "approved".to_string();
            d.address_country_code = "US".to_string();
        });

        register_generic_privacy_extensions(&mut engine, Box::new(data), None).unwrap();

        engine
            .add_policy(
                "test.rego".to_string(),
                r#"
                package test
                status = newton.privacy.get("status")
                country = newton.privacy.get("address_country_code")
                missing = newton.privacy.get("nonexistent")
                "#
                .to_string(),
            )
            .unwrap();

        engine.set_input(Value::from_json_str("{}").unwrap());

        let status = engine.eval_rule("data.test.status".to_string()).unwrap();
        assert_eq!(status, Value::from("approved"));

        let country = engine.eval_rule("data.test.country".to_string()).unwrap();
        assert_eq!(country, Value::from("US"));

        let missing = engine.eval_rule("data.test.missing".to_string()).unwrap();
        assert_eq!(missing, Value::Undefined);
    }

    // -- KYC built-in tests (migrated to kyc.* namespace) --

    #[test]
    fn test_kyc_check_approved() {
        let id_approved = kyc_data(|d| d.status = "approved".to_string());
        assert!(kyc_check_approved(vec![], &id_approved)
            .unwrap()
            .as_bool()
            .unwrap());

        let id_unapproved = kyc_data(|d| d.status = "pending".to_string());
        assert!(!kyc_check_approved(vec![], &id_unapproved)
            .unwrap()
            .as_bool()
            .unwrap());
    }

    #[test]
    fn test_kyc_address_in_countries() {
        let id_us = kyc_data(|d| d.address_country_code = "US".to_string());
        let params1 = vec![Value::from(vec![Value::from("US")])];
        assert!(kyc_address_in_countries(params1, &id_us)
            .unwrap()
            .as_bool()
            .unwrap());

        let params2 = vec![Value::from(vec![Value::from("US"), Value::from("CA")])];
        assert!(kyc_address_in_countries(params2, &id_us)
            .unwrap()
            .as_bool()
            .unwrap());

        let params3 = vec![Value::from(vec![Value::from("DE"), Value::from("CA")])];
        assert!(!kyc_address_in_countries(params3, &id_us)
            .unwrap()
            .as_bool()
            .unwrap());

        let params4 = vec![Value::from(vec![Value::from("US"), Value::from("CA")])];
        let id_malformed1 = kyc_data(|d| d.address_country_code = "USA".to_string());
        assert!(!kyc_address_in_countries(params4.clone(), &id_malformed1)
            .unwrap()
            .as_bool()
            .unwrap());

        let id_malformed2 = kyc_data(|d| d.address_country_code = "".to_string());
        assert!(kyc_address_in_countries(params4, &id_malformed2).is_err());

        let params_malformed1 = vec![Value::from(vec![])];
        assert!(kyc_address_in_countries(params_malformed1, &id_us).is_err());

        let params_malformed2 = vec![Value::from("test")];
        assert!(kyc_address_in_countries(params_malformed2, &id_us).is_err());
    }

    #[test]
    fn test_kyc_address_in_subdivision() {
        let id_ca = kyc_data(|d| {
            d.address_country_code = "US".to_string();
            d.address_subdivision = "CA".to_string();
        });
        let params1 = vec![Value::from(vec![Value::from("US-CA")])];
        assert!(kyc_address_in_subdivision(params1, &id_ca)
            .unwrap()
            .as_bool()
            .unwrap());

        let params2 = vec![Value::from(vec![
            Value::from("US-CA"),
            Value::from("US-OR"),
        ])];
        assert!(kyc_address_in_subdivision(params2, &id_ca)
            .unwrap()
            .as_bool()
            .unwrap());

        let params3 = vec![Value::from(vec![
            Value::from("US-OR"),
            Value::from("US-WA"),
        ])];
        assert!(!kyc_address_in_subdivision(params3.clone(), &id_ca)
            .unwrap()
            .as_bool()
            .unwrap());

        assert!(kyc_address_in_subdivision(vec![Value::from(vec![])], &id_ca).is_err());
        assert!(kyc_address_in_subdivision(vec![Value::from("test")], &id_ca).is_err());

        let id_empty_country = kyc_data(|d| {
            d.address_country_code = "".to_string();
            d.address_subdivision = "CA".to_string();
        });
        assert!(kyc_address_in_subdivision(params3.clone(), &id_empty_country).is_err());

        let id_empty_sub = kyc_data(|d| {
            d.address_country_code = "US".to_string();
            d.address_subdivision = "".to_string();
        });
        assert!(kyc_address_in_subdivision(params3, &id_empty_sub).is_err());
    }

    #[test]
    fn test_kyc_address_not_in_subdivision() {
        let id_ca = kyc_data(|d| {
            d.address_country_code = "US".to_string();
            d.address_subdivision = "CA".to_string();
        });
        let params1 = vec![Value::from(vec![Value::from("US-NY")])];
        assert!(kyc_address_not_in_subdivision(params1, &id_ca)
            .unwrap()
            .as_bool()
            .unwrap());

        let params2 = vec![Value::from(vec![
            Value::from("US-NY"),
            Value::from("US-NC"),
        ])];
        assert!(kyc_address_not_in_subdivision(params2, &id_ca)
            .unwrap()
            .as_bool()
            .unwrap());

        let params3 = vec![Value::from(vec![
            Value::from("US-CA"),
            Value::from("US-WA"),
        ])];
        assert!(!kyc_address_not_in_subdivision(params3.clone(), &id_ca)
            .unwrap()
            .as_bool()
            .unwrap());

        let id_by = kyc_data(|d| {
            d.address_country_code = "DE".to_string();
            d.address_subdivision = "BY".to_string();
        });
        let params4 = vec![Value::from(vec![
            Value::from("US-CA"),
            Value::from("US-WA"),
        ])];
        assert!(kyc_address_not_in_subdivision(params4, &id_by)
            .unwrap()
            .as_bool()
            .unwrap());

        assert!(kyc_address_not_in_subdivision(vec![Value::from(vec![])], &id_ca).is_err());
        assert!(kyc_address_not_in_subdivision(vec![Value::from("test")], &id_ca).is_err());
    }

    #[test]
    fn test_kyc_age_gte() {
        let id_30 = kyc_data(|d| {
            d.reference_date = "2026-02-25".to_string();
            d.birthdate = "1996-01-01".to_string();
        });

        assert!(kyc_age_gte(vec![Value::from(21)], &id_30)
            .unwrap()
            .as_bool()
            .unwrap());
        assert!(!kyc_age_gte(vec![Value::from(31)], &id_30)
            .unwrap()
            .as_bool()
            .unwrap());
        assert!(kyc_age_gte(vec![Value::from(30)], &id_30)
            .unwrap()
            .as_bool()
            .unwrap());

        // Birthdate in the future relative to reference_date
        let id_future = kyc_data(|d| {
            d.birthdate = "2026-02-25".to_string();
            d.reference_date = "1996-01-01".to_string();
        });
        assert!(kyc_age_gte(vec![Value::from(30)], &id_future).is_err());

        // Empty birthdate
        let id_empty = kyc_data(|d| {
            d.birthdate = "".to_string();
            d.reference_date = "2026-02-25".to_string();
        });
        assert!(kyc_age_gte(vec![Value::from(30)], &id_empty).is_err());

        // Bad format
        let id_bad_fmt = kyc_data(|d| {
            d.birthdate = "03/28/2025".to_string();
            d.reference_date = "2026-02-25".to_string();
        });
        assert!(kyc_age_gte(vec![Value::from(30)], &id_bad_fmt).is_err());

        // Negative age
        assert!(kyc_age_gte(vec![Value::from(-10)], &id_30).is_err());

        // Non-number
        assert!(kyc_age_gte(vec![Value::from("test")], &id_30).is_err());

        // Leap year edge cases
        let id_leap1 = kyc_data(|d| {
            d.birthdate = "2000-02-29".to_string();
            d.reference_date = "2026-02-28".to_string();
        });
        assert!(!kyc_age_gte(vec![Value::from(26)], &id_leap1)
            .unwrap()
            .as_bool()
            .unwrap());

        let id_leap2 = kyc_data(|d| {
            d.birthdate = "2001-03-01".to_string();
            d.reference_date = "2028-02-29".to_string();
        });
        assert!(!kyc_age_gte(vec![Value::from(27)], &id_leap2)
            .unwrap()
            .as_bool()
            .unwrap());
    }

    #[test]
    fn test_kyc_not_expired() {
        let id_valid = kyc_data(|d| {
            d.reference_date = "2026-02-25".to_string();
            d.expiration_date = "2027-02-25".to_string();
        });
        assert!(kyc_not_expired(vec![], &id_valid)
            .unwrap()
            .as_bool()
            .unwrap());

        let id_expired = kyc_data(|d| {
            d.reference_date = "2026-02-25".to_string();
            d.expiration_date = "2000-02-25".to_string();
        });
        assert!(!kyc_not_expired(vec![], &id_expired)
            .unwrap()
            .as_bool()
            .unwrap());
    }

    #[test]
    fn test_kyc_valid_for() {
        let id_year = kyc_data(|d| {
            d.reference_date = "2026-02-25".to_string();
            d.expiration_date = "2027-02-25".to_string();
        });

        assert!(kyc_valid_for(vec![Value::from(100)], &id_year)
            .unwrap()
            .as_bool()
            .unwrap());
        assert!(!kyc_valid_for(vec![Value::from(366)], &id_year)
            .unwrap()
            .as_bool()
            .unwrap());
        assert!(kyc_valid_for(vec![Value::from(365)], &id_year)
            .unwrap()
            .as_bool()
            .unwrap());

        assert!(kyc_valid_for(vec![Value::from(-10)], &id_year).is_err());
        assert!(kyc_valid_for(vec![Value::from("test")], &id_year).is_err());

        let id_expired = kyc_data(|d| {
            d.expiration_date = "2000-02-29".to_string();
            d.reference_date = "2026-02-28".to_string();
        });
        assert!(!kyc_valid_for(vec![Value::from(100)], &id_expired)
            .unwrap()
            .as_bool()
            .unwrap());

        // Leap year edge case
        let id_leap = kyc_data(|d| {
            d.expiration_date = "2029-03-01".to_string();
            d.reference_date = "2028-02-29".to_string();
        });
        assert!(kyc_valid_for(vec![Value::from(364)], &id_leap)
            .unwrap()
            .as_bool()
            .unwrap());
    }

    #[test]
    fn test_kyc_issued_since() {
        let id_year = kyc_data(|d| {
            d.reference_date = "2026-02-25".to_string();
            d.issue_date = "2025-02-25".to_string();
        });

        assert!(kyc_issued_since(vec![Value::from(100)], &id_year)
            .unwrap()
            .as_bool()
            .unwrap());
        assert!(!kyc_issued_since(vec![Value::from(366)], &id_year)
            .unwrap()
            .as_bool()
            .unwrap());
        assert!(kyc_issued_since(vec![Value::from(365)], &id_year)
            .unwrap()
            .as_bool()
            .unwrap());

        assert!(kyc_issued_since(vec![Value::from(-10)], &id_year).is_err());
        assert!(kyc_issued_since(vec![Value::from("test")], &id_year).is_err());

        let id_future = kyc_data(|d| {
            d.reference_date = "2000-02-29".to_string();
            d.issue_date = "2026-02-28".to_string();
        });
        assert!(!kyc_issued_since(vec![Value::from(100)], &id_future)
            .unwrap()
            .as_bool()
            .unwrap());

        // Leap year edge case
        let id_leap = kyc_data(|d| {
            d.reference_date = "2029-03-01".to_string();
            d.issue_date = "2028-02-29".to_string();
        });
        assert!(kyc_issued_since(vec![Value::from(366)], &id_leap)
            .unwrap()
            .as_bool()
            .unwrap());
    }

    // -- Integration test: KYC extensions registered on engine --

    #[test]
    fn test_kyc_extensions_full_policy() {
        let mut engine = Engine::new();
        let data = kyc_data(|d| {
            d.reference_date = "2026-01-01".to_string();
            d.status = "approved".to_string();
            d.address_country_code = "US".to_string();
            d.address_subdivision = "CA".to_string();
            d.birthdate = "1990-01-01".to_string();
            d.expiration_date = "2030-01-01".to_string();
        });

        register_kyc_privacy_extensions(&mut engine, data, None).unwrap();

        engine
            .add_policy(
                "test.rego".to_string(),
                r#"
                package test
                import future.keywords.if

                default allow = false

                allow if {
                    newton.privacy.kyc.check_approved()
                    newton.privacy.kyc.age_gte(18)
                    newton.privacy.kyc.not_expired()
                    newton.privacy.kyc.address_in_countries(["US", "CA"])
                }
                "#
                .to_string(),
            )
            .unwrap();

        engine.set_input(Value::from_json_str("{}").unwrap());

        let result = engine.eval_rule("data.test.allow".to_string()).unwrap();
        assert_eq!(result, Value::from(true));
    }

    #[test]
    fn test_kyc_extensions_with_generic_get() {
        let mut engine = Engine::new();
        let data = kyc_data(|d| {
            d.status = "approved".to_string();
            d.address_country_code = "US".to_string();
        });

        register_kyc_privacy_extensions(&mut engine, data, None).unwrap();

        engine
            .add_policy(
                "test.rego".to_string(),
                r#"
                package test
                status = newton.privacy.get("status")
                country = newton.privacy.get("address_country_code")
                "#
                .to_string(),
            )
            .unwrap();

        engine.set_input(Value::from_json_str("{}").unwrap());

        let status = engine.eval_rule("data.test.status".to_string()).unwrap();
        assert_eq!(status, Value::from("approved"));

        let country = engine.eval_rule("data.test.country".to_string()).unwrap();
        assert_eq!(country, Value::from("US"));
    }
}
