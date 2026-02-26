// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Newton Foundation.

//! Newton identity extensions for Rego policy evaluation.
//!
//! Provides checks on an inputted identity.

extern crate alloc;

use alloc::{boxed::Box, string::ToString, format, vec::Vec, string::String};
use chrono::prelude::*;

use crate::{Engine, Value};
use anyhow::{bail, Result};

const PARSE_FORMAT: &str = "%Y-%m-%d";

#[derive(Debug, Clone, Default)]
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
    let id_approve = data.clone();
    engine.add_extension(
        "newton.identity.check_approved".to_string(),
        0,
        Box::new(move |params: Vec<Value>| check_approved(params, &id_approve)),
    )?;
    
    let id_country = data.clone();
    engine.add_extension(
        "newton.identity.address_in_countries".to_string(),
        1,
        Box::new(move |params: Vec<Value>| address_in_countries(params, &id_country)),
    )?;
    
    let id_state = data.clone();
    engine.add_extension(
        "newton.identity.address_in_subdivision".to_string(),
        1,
        Box::new(move |params: Vec<Value>| address_in_subdivision(params, &id_state)),
    )?;

    let id_not_state = data.clone();
    engine.add_extension(
        "newton.identity.address_not_in_subdivision".to_string(),
        1,
        Box::new(move |params: Vec<Value>| address_not_in_subdivision(params, &id_not_state)),
    )?;

    let id_age = data.clone();
    engine.add_extension(
        "newton.identity.age_gte".to_string(),
        1,
        Box::new(move |params: Vec<Value>| age_gte(params, &id_age)),
    )?;

    let id_not_expired = data.clone();
    engine.add_extension(
        "newton.identity.not_expired".to_string(),
        0,
        Box::new(move |params: Vec<Value>| not_expired(params, &id_not_expired)),
    )?;

    let id_valid_for = data.clone();
    engine.add_extension(
        "newton.identity.valid_for".to_string(),
        1,
        Box::new(move |params: Vec<Value>| valid_for(params, &id_valid_for)),
    )?;

    let id_issued_since = data.clone();
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

            if data.address_country_code.is_empty() {
                bail!("address_in_countries requires non-empty address_country_code");
            }

            Ok(Value::from(
                data.address_country_code.len() == 2 // valid code (non-empty)
                && countries.contains(&Value::from(data.address_country_code.clone())),
            ))
        }
        _ => bail!("address_in_countries expects an array of string country codes"),
    }
}

fn address_in_subdivision(params: Vec<Value>, data: &IdentityData) -> Result<Value> {
    match &params[0].as_array() {
        Ok(states) => {
            if states.is_empty() {
                bail!("address_in_subdivision expects a non-empty array")
            }

            if data.address_country_code.is_empty() || data.address_subdivision.is_empty() {
                bail!("address_in_subdivision requires non-empty address_country_code and address_subdivision");
            }

            Ok(Value::from(
                states.contains(&Value::from(format!("{}-{}", data.address_country_code, data.address_subdivision))),
            ))
        }
        _ => bail!("address_in_subdivision expects an array of string iso codes"),
    }
}

fn address_not_in_subdivision(params: Vec<Value>, data: &IdentityData) -> Result<Value> {
    match &params[0].as_array() {
        Ok(states) => {
            if states.is_empty() {
                bail!("address_not_in_subdivision expects a non-empty array")
            }

            if data.address_country_code.is_empty() || data.address_subdivision.is_empty() {
                bail!("address_not_in_subdivision requires non-empty address_country_code and address_subdivision");
            }

            Ok(Value::from(
                !states.contains(&Value::from(format!("{}-{}", data.address_country_code, data.address_subdivision))),
            ))
        }
        _ => bail!("address_not_in_subdivision expects an array of string iso codes"),
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
                _ => bail!("age_gte received invalid birthdate or reference date")
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


#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_check_approved() {
        let id_approved = IdentityData{ status: "approved".to_string(), ..Default::default() };

        assert!(check_approved(vec![], &id_approved).unwrap().as_bool().unwrap());

        let id_unapproved = IdentityData{ status: "pending".to_string(), ..Default::default() };

        assert!(!check_approved(vec![], &id_unapproved).unwrap().as_bool().unwrap());
    }

    #[test]
    fn test_address_in_countries() {
        let id_us = IdentityData{ address_country_code: "US".to_string(), ..Default::default() };
        let params1 = vec![Value::from(vec![Value::from("US")])];

        assert!(address_in_countries(params1, &id_us).unwrap().as_bool().unwrap());

        let params2 = vec![Value::from(vec![Value::from("US"), Value::from("CA")])];

        assert!(address_in_countries(params2, &id_us).unwrap().as_bool().unwrap());

        let params3 = vec![Value::from(vec![Value::from("DE"), Value::from("CA")])];

        assert!(!address_in_countries(params3, &id_us).unwrap().as_bool().unwrap());

        let params4 = vec![Value::from(vec![Value::from("US"), Value::from("CA")])];
        let id_malformed1 = IdentityData{ address_country_code: "USA".to_string(), ..Default::default() };

        assert!(!address_in_countries(params4.clone(), &id_malformed1).unwrap().as_bool().unwrap());

        let id_malformed2 = IdentityData{ address_country_code: "".to_string(), ..Default::default() };

        assert_eq!(format!("{}",address_in_countries(params4, &id_malformed2).unwrap_err()), "address_in_countries requires non-empty address_country_code");

        let params_malformed1 = vec![Value::from(vec![])];

        assert_eq!(format!("{}",address_in_countries(params_malformed1, &id_us).unwrap_err()), "address_in_countries expects a non-empty array");

        let params_malformed2 = vec![Value::from("test")];

        assert_eq!(format!("{}",address_in_countries(params_malformed2, &id_us).unwrap_err()), "address_in_countries expects an array of string country codes");
    }

    #[test]
    fn test_address_in_subdivision() {
        let id_ca = IdentityData{ address_country_code: "US".to_string(), address_subdivision: "CA".to_string(), ..Default::default() };
        let params1 = vec![Value::from(vec![Value::from("US-CA")])];

        assert!(address_in_subdivision(params1, &id_ca).unwrap().as_bool().unwrap());

        let params2 = vec![Value::from(vec![Value::from("US-CA"), Value::from("US-OR")])];

        assert!(address_in_subdivision(params2, &id_ca).unwrap().as_bool().unwrap());

        let params3 = vec![Value::from(vec![Value::from("US-OR"), Value::from("US-WA")])];

        assert!(!address_in_subdivision(params3.clone(), &id_ca).unwrap().as_bool().unwrap());

        let params_malformed1 = vec![Value::from(vec![])];

        assert_eq!(format!("{}",address_in_subdivision(params_malformed1, &id_ca).unwrap_err()), "address_in_subdivision expects a non-empty array");

        let params_malformed2 = vec![Value::from("test")];

        assert_eq!(format!("{}",address_in_subdivision(params_malformed2, &id_ca).unwrap_err()), "address_in_subdivision expects an array of string iso codes");

        let id_malformed1 = IdentityData{ address_country_code: "".to_string(), address_subdivision: "CA".to_string(), ..Default::default() };

        assert_eq!(format!("{}",address_in_subdivision(params3.clone(), &id_malformed1).unwrap_err()), "address_in_subdivision requires non-empty address_country_code and address_subdivision");

        let id_malformed2 = IdentityData{ address_country_code: "US".to_string(), address_subdivision: "".to_string(), ..Default::default() };

        assert_eq!(format!("{}",address_in_subdivision(params3.clone(), &id_malformed2).unwrap_err()), "address_in_subdivision requires non-empty address_country_code and address_subdivision");

        let id_malformed3 = IdentityData{ address_country_code: "".to_string(), address_subdivision: "".to_string(), ..Default::default() };

        assert_eq!(format!("{}",address_in_subdivision(params3, &id_malformed3).unwrap_err()), "address_in_subdivision requires non-empty address_country_code and address_subdivision");
    }

    #[test]
    fn test_address_not_in_subdivision() {
        let id_ca = IdentityData{ address_country_code: "US".to_string(), address_subdivision: "CA".to_string(), ..Default::default() };
        let params1 = vec![Value::from(vec![Value::from("US-NY")])];
        
        assert!(address_not_in_subdivision(params1, &id_ca).unwrap().as_bool().unwrap());
        
        let params2 = vec![Value::from(vec![Value::from("US-NY"), Value::from("US-NC")])];
        
        assert!(address_not_in_subdivision(params2, &id_ca).unwrap().as_bool().unwrap());
        
        let params3 = vec![Value::from(vec![Value::from("US-CA"), Value::from("US-WA")])];
        
        assert!(!address_not_in_subdivision(params3.clone(), &id_ca).unwrap().as_bool().unwrap());
        
        let id_by = IdentityData{ address_country_code: "DE".to_string(), address_subdivision: "BY".to_string(), ..Default::default() };
        let params4 = vec![Value::from(vec![Value::from("US-CA"), Value::from("US-WA")])];

        assert!(address_not_in_subdivision(params4, &id_by).unwrap().as_bool().unwrap());

        let params_malformed1 = vec![Value::from(vec![])];

        assert_eq!(format!("{}",address_not_in_subdivision(params_malformed1, &id_ca).unwrap_err()), "address_not_in_subdivision expects a non-empty array");

        let params_malformed2 = vec![Value::from("test")];

        assert_eq!(format!("{}",address_not_in_subdivision(params_malformed2, &id_ca).unwrap_err()), "address_not_in_subdivision expects an array of string iso codes");

        let id_malformed1 = IdentityData{ address_country_code: "".to_string(), address_subdivision: "CA".to_string(), ..Default::default() };

        assert_eq!(format!("{}",address_not_in_subdivision(params3.clone(), &id_malformed1).unwrap_err()), "address_not_in_subdivision requires non-empty address_country_code and address_subdivision");

        let id_malformed2 = IdentityData{ address_country_code: "US".to_string(), address_subdivision: "".to_string(), ..Default::default() };

        assert_eq!(format!("{}",address_not_in_subdivision(params3.clone(), &id_malformed2).unwrap_err()), "address_not_in_subdivision requires non-empty address_country_code and address_subdivision");

        let id_malformed3 = IdentityData{ address_country_code: "".to_string(), address_subdivision: "".to_string(), ..Default::default() };

        assert_eq!(format!("{}",address_not_in_subdivision(params3, &id_malformed3).unwrap_err()), "address_not_in_subdivision requires non-empty address_country_code and address_subdivision");
    }

    #[test]
    fn test_age_gte() {
        let id_30 = IdentityData{ reference_date: "2026-02-25".to_string(), birthdate: "1996-01-01".to_string(), ..Default::default() };
        let params1 = vec![Value::from(21)];

        assert!(age_gte(params1, &id_30).unwrap().as_bool().unwrap());

        let params2 = vec![Value::from(31)];

        assert!(!age_gte(params2, &id_30).unwrap().as_bool().unwrap());

        let params2 = vec![Value::from(30)];

        assert!(age_gte(params2.clone(), &id_30).unwrap().as_bool().unwrap());

        let id_malformed1 = IdentityData{ birthdate: "2026-02-25".to_string(), reference_date: "1996-01-01".to_string(), ..Default::default() };

        assert_eq!(format!("{}",age_gte(params2.clone(), &id_malformed1).unwrap_err()), "age_gte received invalid birthdate or reference date");

        let id_malformed2 = IdentityData{ birthdate: "2066-02-25".to_string(), reference_date: "2026-02-25".to_string(), ..Default::default() };

        assert_eq!(format!("{}",age_gte(params2.clone(), &id_malformed2).unwrap_err()), "age_gte received invalid birthdate or reference date");

        let id_malformed3 = IdentityData{ birthdate: "".to_string(), reference_date: "2026-02-25".to_string(), ..Default::default() };

        assert_eq!(format!("{}",age_gte(params2.clone(), &id_malformed3).unwrap_err()), "premature end of input");

        let id_malformed4 = IdentityData{ birthdate: "03/28/2025".to_string(), reference_date: "2026-02-25".to_string(), ..Default::default() };

        assert_eq!(format!("{}",age_gte(params2.clone(), &id_malformed4).unwrap_err()), "input contains invalid characters");

        let params_malformed1 = vec![Value::from(-10)];

        assert_eq!(format!("{}",age_gte(params_malformed1, &id_30).unwrap_err()), "age_gte expects a positive valued age");

        let params_malformed2 = vec![Value::from("test")];

        assert_eq!(format!("{}",age_gte(params_malformed2, &id_30).unwrap_err()), "age_gte expects a number");

        let id_pathological1 = IdentityData{ birthdate: "2000-02-29".to_string(), reference_date: "2026-02-28".to_string(), ..Default::default() };
        let params_pathological1 = vec![Value::from(26)];

        assert!(!age_gte(params_pathological1, &id_pathological1).unwrap().as_bool().unwrap());

        let id_pathological2 = IdentityData{ birthdate: "2001-03-01".to_string(), reference_date: "2028-02-29".to_string(), ..Default::default() };
        let params_pathological2 = vec![Value::from(27)];

        assert!(!age_gte(params_pathological2, &id_pathological2).unwrap().as_bool().unwrap());
    }

    #[test]
    fn test_not_expired() {
        let id_year = IdentityData{ reference_date: "2026-02-25".to_string(), expiration_date: "2027-02-25".to_string(), ..Default::default() };

        assert!(not_expired(vec![], &id_year).unwrap().as_bool().unwrap());

        let id_expired = IdentityData{ reference_date: "2026-02-25".to_string(), expiration_date: "2000-02-25".to_string(), ..Default::default() };

        assert!(!not_expired(vec![], &id_expired).unwrap().as_bool().unwrap());
    }

    #[test]
    fn test_valid_for() {
        let id_year = IdentityData{ reference_date: "2026-02-25".to_string(), expiration_date: "2027-02-25".to_string(), ..Default::default() };
        let params1 = vec![Value::from(100)];

        assert!(valid_for(params1, &id_year).unwrap().as_bool().unwrap());

        let params2 = vec![Value::from(366)];

        assert!(!valid_for(params2, &id_year).unwrap().as_bool().unwrap());

        let params2 = vec![Value::from(365)];

        assert!(valid_for(params2.clone(), &id_year).unwrap().as_bool().unwrap());

        let params_malformed1 = vec![Value::from(-10)];

        assert_eq!(format!("{}",valid_for(params_malformed1, &id_year).unwrap_err()), "valid_for expects a positive number of days");

        let params_malformed2 = vec![Value::from("test")];

        assert_eq!(format!("{}",valid_for(params_malformed2, &id_year).unwrap_err()), "valid_for expects a number");

        let id_expired = IdentityData{ expiration_date: "2000-02-29".to_string(), reference_date: "2026-02-28".to_string(), ..Default::default() };
        let params3 = vec![Value::from(100)];

        assert!(!valid_for(params3, &id_expired).unwrap().as_bool().unwrap());

        let id_pathological = IdentityData{ expiration_date: "2029-03-01".to_string(), reference_date: "2028-02-29".to_string(), ..Default::default() };
        let params_pathological = vec![Value::from(364)];

        assert!(valid_for(params_pathological, &id_pathological).unwrap().as_bool().unwrap());
    }

    #[test]
    fn test_issued_since() {
        let id_year = IdentityData{ reference_date: "2026-02-25".to_string(), issue_date: "2025-02-25".to_string(), ..Default::default() };
        let params1 = vec![Value::from(100)];

        assert!(issued_since(params1, &id_year).unwrap().as_bool().unwrap());

        let params2 = vec![Value::from(366)];

        assert!(!issued_since(params2, &id_year).unwrap().as_bool().unwrap());

        let params2 = vec![Value::from(365)];

        assert!(issued_since(params2.clone(), &id_year).unwrap().as_bool().unwrap());

        let params_malformed1 = vec![Value::from(-10)];

        assert_eq!(format!("{}",issued_since(params_malformed1, &id_year).unwrap_err()), "issued_since expects a positive number of days");

        let params_malformed2 = vec![Value::from("test")];

        assert_eq!(format!("{}",issued_since(params_malformed2, &id_year).unwrap_err()), "issued_since expects a number");

        let id_expired = IdentityData{ reference_date: "2000-02-29".to_string(), issue_date: "2026-02-28".to_string(), ..Default::default() };
        let params3 = vec![Value::from(100)];

        assert!(!issued_since(params3, &id_expired).unwrap().as_bool().unwrap());

        let id_pathological = IdentityData{ reference_date: "2029-03-01".to_string(), issue_date: "2028-02-29".to_string(), ..Default::default() };
        let params_pathological = vec![Value::from(366)];

        assert!(issued_since(params_pathological, &id_pathological).unwrap().as_bool().unwrap());
    }
}
