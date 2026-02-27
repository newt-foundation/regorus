// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Newton Foundation.

//! Newton identity extensions for Rego policy evaluation.
//!
//! Provides checks on an inputted identity.

extern crate alloc;

use alloc::{boxed::Box, string::ToString, format, vec::Vec, string::String};

use crate::{Engine, Value};
use anyhow::{bail, Result};

#[derive(Debug, Clone, Default)]
pub struct IdentityData {
    /// the state from the document address
    pub address_subdivision: String,
    /// the country from the document address
    pub address_country_code: String,
    /// flag for if the user was over 18 at time of screening
    pub is_over_18: bool,
    /// flag for if the user was over 21 at time of screening
    pub is_over_21: bool,
}

/// Registers all Newton identity extensions with the engine.
pub fn register_newton_identity_extensions(engine: &mut Engine, data: IdentityData) -> Result<()> {
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

    let id_over_18 = data.clone();
    engine.add_extension(
        "newton.identity.is_over_18".to_string(),
        0,
        Box::new(move |params: Vec<Value>| over_18(params, &id_over_18)),
    )?;

    let id_over_21 = data.clone();
    engine.add_extension(
        "newton.identity.is_over_21".to_string(),
        0,
        Box::new(move |params: Vec<Value>| over_21(params, &id_over_21)),
    )?;

    Ok(())
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

fn over_18(_params: Vec<Value>, data: &IdentityData) -> Result<Value> {
    Ok(Value::from(data.is_over_18))
}

fn over_21(_params: Vec<Value>, data: &IdentityData) -> Result<Value> {
    Ok(Value::from(data.is_over_21))
}


#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

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
    fn test_over_18() {
        let id_approved = IdentityData{ is_over_18: true, ..Default::default() };

        assert!(over_18(vec![], &id_approved).unwrap().as_bool().unwrap());

        let id_unapproved = IdentityData{ is_over_18: false, ..Default::default() };

        assert!(!over_18(vec![], &id_unapproved).unwrap().as_bool().unwrap());
    }

    #[test]
    fn test_over_21() {
        let id_approved = IdentityData{ is_over_21: true, ..Default::default() };

        assert!(over_21(vec![], &id_approved).unwrap().as_bool().unwrap());

        let id_unapproved = IdentityData{ is_over_21: false, ..Default::default() };

        assert!(!over_21(vec![], &id_unapproved).unwrap().as_bool().unwrap());
    }
}
