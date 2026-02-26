// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Newton Foundation.

//! Newton identity extensions for Rego policy evaluation.
//!
//! Provides checks on an inputted identity.

extern crate alloc;

use alloc::{boxed::Box, string::ToString, vec::Vec, sync::Arc, string::String};
use chrono::prelude::*;

use crate::{Engine, Value};
use anyhow::{bail, Result};

const PARSE_FORMAT: &str = "%Y-%m-%d";

#[derive(Debug, Clone)]
pub struct IdentityData {
    /// the reference time of "now" for all time based checks as a YYYY-MM-DD string
    pub reference_date: String,
    /// either created, pending, completed, approved, failed, expired, declined, or needs review
    pub status: String,
    /// the country code selected by the user during the process
    pub selected_country_code: String,
    /// the state from the document address
    pub address_subdivision: String,
    /// the country from the document address
    pub address_country_code: String,
    /// the birthdate as a YYYY-MM-DD string
    pub birthdate: String,
    /// the expiration date of the document
    pub expiration_date: String,
    /// the issuing date of the document
    pub issue_date: String,
    /// the country or state that issued the document
    pub issuing_authority: String,
}

/// Registers all Newton identity extensions with the engine.
pub fn register_newton_identity_extensions(engine: &mut Engine, data: IdentityData) -> Result<()> {
    let identity_data = Arc::new(data);
    let id_approve = Arc::clone(&identity_data);
    engine.add_extension(
        "newton.identity.check_approved".to_string(),
        0,
        Box::new(move |params: Vec<Value>| check_approved(params, &id_approve)),
    )?;
    
    let id_country = Arc::clone(&identity_data);
    engine.add_extension(
        "newton.identity.address_in_countries".to_string(),
        1,
        Box::new(move |params: Vec<Value>| address_in_countries(params, &id_country)),
    )?;
    
    let id_state = Arc::clone(&identity_data);
    engine.add_extension(
        "newton.identity.address_in_states".to_string(),
        1,
        Box::new(move |params: Vec<Value>| address_in_states(params, &id_state)),
    )?;

    let id_not_state = Arc::clone(&identity_data);
    engine.add_extension(
        "newton.identity.address_not_in_states".to_string(),
        1,
        Box::new(move |params: Vec<Value>| address_not_in_states(params, &id_not_state)),
    )?;

    let id_age = Arc::clone(&identity_data);
    engine.add_extension(
        "newton.identity.age_gte".to_string(),
        1,
        Box::new(move |params: Vec<Value>| age_gte(params, &id_age)),
    )?;

    let id_not_expired = Arc::clone(&identity_data);
    engine.add_extension(
        "newton.identity.not_expired".to_string(),
        0,
        Box::new(move |params: Vec<Value>| not_expired(params, &id_not_expired)),
    )?;

    let id_valid_for = Arc::clone(&identity_data);
    engine.add_extension(
        "newton.identity.valid_for".to_string(),
        1,
        Box::new(move |params: Vec<Value>| valid_for(params, &id_valid_for)),
    )?;

    let id_issued_since = Arc::clone(&identity_data);
    engine.add_extension(
        "newton.identity.issued_since".to_string(),
        1,
        Box::new(move |params: Vec<Value>| issued_since(params, &id_issued_since)),
    )?;

    Ok(())
}

fn check_approved(_params: Vec<Value>, data: &IdentityData) -> Result<Value> {
    Ok(Value::from(data.status == "approved"))
}

fn address_in_countries(params: Vec<Value>, data: &IdentityData) -> Result<Value> {
    match &params[0].as_array() {
        Ok(countries) => {
            if countries.is_empty() {
                bail!("address_in_countries expects a non-empty array")
            }

            Ok(Value::from(
                data.address_country_code.len() == 2 // valid code (non-empty)
                && countries.contains(&Value::from(data.address_country_code.clone())),
            ))
        }
        _ => bail!("address_in_countries expects an array of string country codes"),
    }
}

fn address_in_states(params: Vec<Value>, data: &IdentityData) -> Result<Value> {
    match &params[0].as_array() {
        Ok(states) => {
            if states.is_empty() {
                bail!("address_in_states expects a non-empty array")
            }

            Ok(Value::from(
                data.address_country_code == "US"
                && data.address_subdivision.len() == 2 // valid code (non-empty)
                && states.contains(&Value::from(data.address_subdivision.clone())),
            ))
        }
        _ => bail!("address_in_states expects an array of string state codes"),
    }
}

fn address_not_in_states(params: Vec<Value>, data: &IdentityData) -> Result<Value> {
    match &params[0].as_array() {
        Ok(states) => {
            if states.is_empty() {
                bail!("address_not_in_states expects a non-empty array")
            }

            Ok(Value::from(
                data.address_subdivision.len() == 2 // valid code (non-empty)
                && !states.contains(&Value::from(data.address_subdivision.clone())),
            ))
        }
        _ => bail!("address_not_in_states expects an array of string state codes"),
    }
}

fn age_gte(params: Vec<Value>, data: &IdentityData) -> Result<Value> {
    match params[0].as_i64() {
        Ok(min_age) => {
            if min_age <= 0 {
                bail!("age_gte expects a positive valued age")
            }

            let now = NaiveDate::parse_from_str(&data.reference_date, PARSE_FORMAT)?;
            let birthdate = NaiveDate::parse_from_str(&data.birthdate, PARSE_FORMAT)?;

            match now.years_since(birthdate) {
                Some(years) => Ok(Value::from(min_age <= years.into())),
                _ => bail!("age_gte recieved invalid birthdate")
            }
        }
        _ => bail!("age_gte expects a number"),
    }
}

fn not_expired(_params: Vec<Value>, data: &IdentityData) -> Result<Value> {
    let now = NaiveDate::parse_from_str(&data.reference_date, PARSE_FORMAT)?;
    let expiration = NaiveDate::parse_from_str(&data.expiration_date, PARSE_FORMAT)?;

    Ok(Value::from(now.le(&expiration)))
}

fn valid_for(params: Vec<Value>, data: &IdentityData) -> Result<Value> {
    match params[0].as_i64() {
        Ok(num_days) => {
            if num_days <= 0 {
                bail!("valid_for expects a positive number of days")
            }

            let now = NaiveDate::parse_from_str(&data.reference_date, PARSE_FORMAT)?;
            let expiration = NaiveDate::parse_from_str(&data.expiration_date, PARSE_FORMAT)?;

            Ok(Value::from(num_days <= (expiration - now).num_days()))
        }
        _ => bail!("valid_for expects a number"),
    }
}

fn issued_since(params: Vec<Value>, data: &IdentityData) -> Result<Value> {
    match params[0].as_i64() {
        Ok(num_days) => {
            if num_days <= 0 {
                bail!("issued_since expects a positive number of days")
            }

            let now = NaiveDate::parse_from_str(&data.reference_date, PARSE_FORMAT)?;
            let issuance = NaiveDate::parse_from_str(&data.issue_date, PARSE_FORMAT)?;

            Ok(Value::from(num_days <= (now - issuance).num_days()))
        }
        _ => bail!("issued_since expects a number"),
    }
}
