// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Newton Foundation.

//! Newton time utility extensions for Rego policy evaluation.
//!
//! Provides date arithmetic builtins that any policy can use, regardless of
//! data domain. All functions operate on YYYY-MM-DD date strings and are
//! pure (no system clock access — reference dates must be passed explicitly).
//!
//! ## Available Functions
//!
//! | Function | Args | Returns | Description |
//! |----------|------|---------|-------------|
//! | `newton.time.days_between(date_a, date_b)` | 2 strings | number | Absolute days between two dates |
//! | `newton.time.days_since(past_date, reference_date)` | 2 strings | number | Days from past_date to reference_date (positive if past_date < reference_date) |
//! | `newton.time.is_within_days(date, reference_date, max_days)` | 2 strings + number | bool | True if |date - reference_date| <= max_days |
//! | `newton.time.is_before(date_a, date_b)` | 2 strings | bool | True if date_a < date_b |
//! | `newton.time.is_after(date_a, date_b)` | 2 strings | bool | True if date_a > date_b |
//! | `newton.time.age_years(birthdate, reference_date)` | 2 strings | number | Complete years between birthdate and reference_date |

extern crate alloc;

use alloc::{boxed::Box, string::ToString, vec::Vec};

use anyhow::{bail, Result};
use chrono::NaiveDate;

use crate::{Engine, Value};

const PARSE_FORMAT: &str = "%Y-%m-%d";

fn parse_date(s: &str, fn_name: &str) -> Result<NaiveDate> {
    NaiveDate::parse_from_str(s, PARSE_FORMAT)
        .map_err(|e| anyhow::anyhow!("{}: invalid date '{}': {}", fn_name, s, e))
}

fn extract_string(v: &Value, fn_name: &str, arg_name: &str) -> Result<alloc::string::String> {
    v.as_string()
        .map(|s| s.to_string())
        .map_err(|_| anyhow::anyhow!("{}: {} must be a string", fn_name, arg_name))
}

/// Register all Newton time utility extensions on the given engine.
pub fn register_newton_time_extensions(engine: &mut Engine) -> Result<()> {
    engine.add_extension(
        "newton.time.days_between".to_string(),
        2,
        Box::new(time_days_between),
    )?;
    engine.add_extension(
        "newton.time.days_since".to_string(),
        2,
        Box::new(time_days_since),
    )?;
    engine.add_extension(
        "newton.time.is_within_days".to_string(),
        3,
        Box::new(time_is_within_days),
    )?;
    engine.add_extension(
        "newton.time.is_before".to_string(),
        2,
        Box::new(time_is_before),
    )?;
    engine.add_extension(
        "newton.time.is_after".to_string(),
        2,
        Box::new(time_is_after),
    )?;
    engine.add_extension(
        "newton.time.age_years".to_string(),
        2,
        Box::new(time_age_years),
    )?;
    Ok(())
}

fn time_days_between(params: Vec<Value>) -> Result<Value> {
    let fn_name = "newton.time.days_between";
    let a = extract_string(&params[0], fn_name, "date_a")?;
    let b = extract_string(&params[1], fn_name, "date_b")?;
    let date_a = parse_date(&a, fn_name)?;
    let date_b = parse_date(&b, fn_name)?;
    let days = (date_b - date_a).num_days().abs();
    Ok(Value::from(days))
}

fn time_days_since(params: Vec<Value>) -> Result<Value> {
    let fn_name = "newton.time.days_since";
    let past = extract_string(&params[0], fn_name, "past_date")?;
    let reference = extract_string(&params[1], fn_name, "reference_date")?;
    let past_date = parse_date(&past, fn_name)?;
    let ref_date = parse_date(&reference, fn_name)?;
    let days = (ref_date - past_date).num_days();
    Ok(Value::from(days))
}

fn time_is_within_days(params: Vec<Value>) -> Result<Value> {
    let fn_name = "newton.time.is_within_days";
    let date_str = extract_string(&params[0], fn_name, "date")?;
    let ref_str = extract_string(&params[1], fn_name, "reference_date")?;
    let max_days = params[2]
        .as_i64()
        .map_err(|_| anyhow::anyhow!("{}: max_days must be a number", fn_name))?;
    if max_days < 0 {
        bail!("{}: max_days must be non-negative", fn_name);
    }
    let date = parse_date(&date_str, fn_name)?;
    let ref_date = parse_date(&ref_str, fn_name)?;
    let days = (ref_date - date).num_days().abs();
    Ok(Value::from(days <= max_days))
}

fn time_is_before(params: Vec<Value>) -> Result<Value> {
    let fn_name = "newton.time.is_before";
    let a = extract_string(&params[0], fn_name, "date_a")?;
    let b = extract_string(&params[1], fn_name, "date_b")?;
    let date_a = parse_date(&a, fn_name)?;
    let date_b = parse_date(&b, fn_name)?;
    Ok(Value::from(date_a < date_b))
}

fn time_is_after(params: Vec<Value>) -> Result<Value> {
    let fn_name = "newton.time.is_after";
    let a = extract_string(&params[0], fn_name, "date_a")?;
    let b = extract_string(&params[1], fn_name, "date_b")?;
    let date_a = parse_date(&a, fn_name)?;
    let date_b = parse_date(&b, fn_name)?;
    Ok(Value::from(date_a > date_b))
}

fn time_age_years(params: Vec<Value>) -> Result<Value> {
    let fn_name = "newton.time.age_years";
    let birth = extract_string(&params[0], fn_name, "birthdate")?;
    let reference = extract_string(&params[1], fn_name, "reference_date")?;
    let birthdate = parse_date(&birth, fn_name)?;
    let ref_date = parse_date(&reference, fn_name)?;
    match ref_date.years_since(birthdate) {
        Some(years) => Ok(Value::from(i64::from(years))),
        None => bail!("{}: birthdate must be before reference_date", fn_name),
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::Engine;

    #[test]
    fn test_days_between() {
        let result = time_days_between(vec![
            Value::from("2026-01-01"),
            Value::from("2026-01-31"),
        ])
        .unwrap();
        assert_eq!(result.as_i64().unwrap(), 30);
    }

    #[test]
    fn test_days_between_reverse() {
        let result = time_days_between(vec![
            Value::from("2026-01-31"),
            Value::from("2026-01-01"),
        ])
        .unwrap();
        assert_eq!(result.as_i64().unwrap(), 30); // absolute value
    }

    #[test]
    fn test_days_since() {
        let result = time_days_since(vec![
            Value::from("2026-01-01"),
            Value::from("2026-04-01"),
        ])
        .unwrap();
        assert_eq!(result.as_i64().unwrap(), 90);
    }

    #[test]
    fn test_days_since_negative() {
        // future date returns negative
        let result = time_days_since(vec![
            Value::from("2026-04-01"),
            Value::from("2026-01-01"),
        ])
        .unwrap();
        assert_eq!(result.as_i64().unwrap(), -90);
    }

    #[test]
    fn test_is_within_days_true() {
        let result = time_is_within_days(vec![
            Value::from("2026-03-15"),
            Value::from("2026-04-01"),
            Value::from(30_i64),
        ])
        .unwrap();
        assert!(result.as_bool().unwrap());
    }

    #[test]
    fn test_is_within_days_false() {
        let result = time_is_within_days(vec![
            Value::from("2025-01-01"),
            Value::from("2026-04-01"),
            Value::from(30_i64),
        ])
        .unwrap();
        assert!(!result.as_bool().unwrap());
    }

    #[test]
    fn test_is_before() {
        let result = time_is_before(vec![
            Value::from("2026-01-01"),
            Value::from("2026-04-01"),
        ])
        .unwrap();
        assert!(result.as_bool().unwrap());
    }

    #[test]
    fn test_is_after() {
        let result = time_is_after(vec![
            Value::from("2026-04-01"),
            Value::from("2026-01-01"),
        ])
        .unwrap();
        assert!(result.as_bool().unwrap());
    }

    #[test]
    fn test_age_years() {
        let result = time_age_years(vec![
            Value::from("1996-01-15"),
            Value::from("2026-04-01"),
        ])
        .unwrap();
        assert_eq!(result.as_i64().unwrap(), 30);
    }

    #[test]
    fn test_age_years_not_yet_birthday() {
        let result = time_age_years(vec![
            Value::from("1996-06-15"),
            Value::from("2026-04-01"),
        ])
        .unwrap();
        assert_eq!(result.as_i64().unwrap(), 29); // birthday hasn't happened yet in 2026
    }

    #[test]
    fn test_invalid_date_format() {
        let result = time_days_between(vec![
            Value::from("not-a-date"),
            Value::from("2026-04-01"),
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn test_time_builtins_in_rego() {
        let mut engine = Engine::new();
        register_newton_time_extensions(&mut engine).unwrap();

        engine
            .add_policy(
                "test.rego".to_string(),
                r#"
            package test
            default allow = false
            allow if {
                newton.time.days_since("2026-03-01", "2026-04-01") <= 90
                newton.time.is_before("2026-01-01", "2026-12-31")
            }
            "#
                .to_string(),
            )
            .unwrap();

        engine.set_input_json("{}").unwrap();
        let result = engine
            .eval_rule("data.test.allow".to_string())
            .unwrap();
        assert_eq!(result, Value::from(true));
    }
}
