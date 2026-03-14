# Newton Identity Extensions

Newton-specific Rego built-in functions for checking identity data within the Rego environment, enabled via the `newton-identity` feature flag.

## Overview

The Newton identity extensions provide domain-flexible Rego built-in functions for checking user age, location, and approval status. Each identity domain (KYC, social, credit, etc.) registers its own namespaced built-ins under `newton.identity.<domain>.*`. A generic `newton.identity.get(field)` accessor works across any domain for ad-hoc field access.

These functions require identity data passed in from the environment initializing the engine. The intent is to allow policy writers to check against data that they know the policy evaluator can source without having direct access to it in a personally identifying way.

## Feature Flag

Enable newton-identity extensions in your `Cargo.toml`:

```toml
regorus = { version = "0.5", features = ["newton-identity"] }
```

Register the KYC identity extensions with your engine:

```rust
use regorus::Engine;
use regorus::extensions::identity::KycIdentityData;

let mut engine = Engine::new();
let data = KycIdentityData {
    reference_date: "2026-01-01".to_string(),
    status: "approved".to_string(),
    // ... other fields
    ..Default::default()
};
engine.with_newton_identity_kyc_extensions(data)?;
```

## Domain Architecture

Identity data is domain-namespaced. The `identity_domain` (bytes32) stored on-chain determines which schema is used to deserialize the data and which Rego built-ins are available. Domain is always required.

Two Rego APIs are provided:

- **Domain-namespaced built-ins** (primary): `newton.identity.kyc.age_gte(21)`. Type-safe, validate inputs, provide specific error messages.
- **Generic field accessor** (escape hatch): `newton.identity.get("field_name")`. Returns the raw field value from the current domain's data. Useful for rapid prototyping before dedicated built-ins exist.

### IdentityDomainData Trait

All domain data structs implement `IdentityDomainData`:

```rust
pub trait IdentityDomainData: Send + Sync {
    fn domain_name(&self) -> &str;
    fn reference_date(&self) -> &str;
    fn to_field_map(&self) -> BTreeMap<String, Value>;
}
```

## KYC Domain Data Type

```rust
pub struct KycIdentityData {
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
```

## Built-in Functions

### KYC Domain (`newton.identity.kyc.*`)

| Builtin                                        | Description                                                                         |
|------------------------------------------------|-------------------------------------------------------------------------------------|
| newton.identity.kyc.check_approved             | Check the status to ensure the data passed all approval checks before submitting    |
| newton.identity.kyc.address_in_countries       | Check that the country on the submitted document is included in a list of countries |
| newton.identity.kyc.address_in_subdivision     | Check that the address on the submitted document is included in a list of states    |
| newton.identity.kyc.address_not_in_subdivision | Check that the address on the submitted document is not within a list of states     |
| newton.identity.kyc.age_gte                    | Check that the birthdate in the data implies an age greater or equal to the input   |
| newton.identity.kyc.not_expired                | Check that the document expiration date has not passed                              |
| newton.identity.kyc.valid_for                  | Check that the document expiration date is valid for subsequent inputted duration   |
| newton.identity.kyc.issued_since               | Check that the document issuing data was at least the specified time ago            |

### Generic Accessor

| Builtin                | Description                                                    |
|------------------------|----------------------------------------------------------------|
| newton.identity.get    | Get any field by name from the current domain's identity data  |

### newton.identity.kyc.check_approved

Requires identity_data.status to equal "approved"

**Signature:**

```rego
result := newton.identity.kyc.check_approved()
```

**Returns:**

| Type   | Description                                                |
|--------|------------------------------------------------------------|
| bool   | true if identity_data.status is "approved" otherwise false |

**Example:**

```rego
package example

import future.keywords.if

# Verify the identity data is approved
authorized if {
    newton.identity.kyc.check_approved()
}
```

### newton.identity.kyc.address_in_countries

Requires identity_data.address_country_code to be found within the inputted list of country codes.

**Signature:**

```rego
result := newton.identity.kyc.address_in_countries(country_code_array)
```

**Arguments:**

| Argument             | Type     | Description                                               |
|----------------------|----------|-----------------------------------------------------------|
| `country_code_array` | string[] | Array of 2 letter country codes to check against the data |

**Returns:**

| Type   | Description                                                    |
|--------|----------------------------------------------------------------|
| bool   | true if the address country is within the list otherwise false |

**Example:**

```rego
package example

import future.keywords.if

# Verify the identity data matches address requirements
authorized if {
    newton.identity.kyc.address_in_countries(["US","DE","CA"])
}
```

### newton.identity.kyc.address_in_subdivision

Requires the ISO subdivision location code for identity_data.address_country_code and identity_data.address_subdivision to be found within the inputted list to check against.

**Signature:**

```rego
result := newton.identity.kyc.address_in_subdivision(iso_code_array)
```

**Arguments:**

| Argument         | Type     | Description                                                        |
|------------------|----------|--------------------------------------------------------------------|
| `iso_code_array` | string[] | Array of XX-XX or XX-XXX ISO codes to match with the identity data |

**Returns:**

| Type   | Description                                            |
|--------|--------------------------------------------------------|
| bool   | true if the address is within the list otherwise false |

**Example:**

```rego
package example

import future.keywords.if

# Verify the identity data matches address requirements
authorized if {
    newton.identity.kyc.address_in_subdivision(["US-CA","US-OR","US-WA"])
}
```

### newton.identity.kyc.address_not_in_subdivision

Requires the ISO subdivision location code for identity_data.address_country_code and identity_data.address_subdivision to not be found within the inputted list to check against. Useful when also using newton.identity.kyc.address_in_countries to exclude certain subdivisions while including all others within the same country as opposed to submitting a really long list to newton.identity.kyc.address_in_subdivision.

**Signature:**

```rego
result := newton.identity.kyc.address_not_in_subdivision(iso_code_array)
```

**Arguments:**

| Argument         | Type     | Description                                                          |
|------------------|----------|----------------------------------------------------------------------|
| `iso_code_array` | string[] | Array of XX-XX or XX-XXX ISO codes to exclude from the identity data |

**Returns:**

| Type   | Description                                            |
|--------|--------------------------------------------------------|
| bool   | true if the address is within the list otherwise false |

**Example:**

```rego
package example

import future.keywords.if

# Verify the identity data matches address requirements
authorized if {
    newton.identity.kyc.address_in_countries(["US"])
    newton.identity.kyc.address_not_in_subdivision(["US-NY","US-NC","US-HI"])
}
```

### newton.identity.kyc.age_gte

Requires identity_data.birthdate to be at least the required number of years ago with respect to the reference date.

**Signature:**

```rego
result := newton.identity.kyc.age_gte(min_age)
```

**Arguments:**

| Argument  | Type     | Description                                                      |
|-----------|----------|------------------------------------------------------------------|
| `min_age` | number   | The min age in years for the birthdate in the identity_data      |

**Returns:**

| Type   | Description                                   |
|--------|-----------------------------------------------|
| bool   | true if the age is sufficient otherwise false |

**Example:**

```rego
package example

import future.keywords.if

# Verify the identity data matches birthdate requirements
authorized if {
    newton.identity.kyc.age_gte(21)
}
```

### newton.identity.kyc.not_expired

Requires identity_data.expiration_date to be after the current time with respect to the reference date.

**Signature:**

```rego
result := newton.identity.kyc.not_expired()
```

**Returns:**

| Type   | Description                                                                                              |
|--------|----------------------------------------------------------------------------------------------------------|
| bool   | true if the document expiration date is in the future with respect to the reference date otherwise false |

**Example:**

```rego
package example

import future.keywords.if

# Verify the identity document isn't expired
authorized if {
    newton.identity.kyc.not_expired()
}
```

### newton.identity.kyc.valid_for

Requires identity_data.expiration_date to be at least the required number of days in the future with respect to the reference date.

**Signature:**

```rego
result := newton.identity.kyc.valid_for(min_days)
```

**Arguments:**

| Argument   | Type     | Description                                                        |
|------------|----------|--------------------------------------------------------------------|
| `min_days` | number   | The number of days after now that the document should be valid for |

**Returns:**

| Type   | Description                                         |
|--------|-----------------------------------------------------|
| bool   | true if the document would be valid otherwise false |

**Example:**

```rego
package example

import future.keywords.if

# Verify the identity data matches document requirements
authorized if {
    newton.identity.kyc.valid_for(365)
}
```

### newton.identity.kyc.issued_since

Requires identity_data.issue_date to be at least the required number of days in the past with respect to the reference date.

**Signature:**

```rego
result := newton.identity.kyc.issued_since(min_days)
```

**Arguments:**

| Argument   | Type     | Description                                                      |
|------------|----------|------------------------------------------------------------------|
| `min_days` | number   | The number of days before now that the document have been issued |

**Returns:**

| Type   | Description                                          |
|--------|------------------------------------------------------|
| bool   | true if the document was issued then otherwise false |

**Example:**

```rego
package example

import future.keywords.if

# Verify the identity data matches document requirements
authorized if {
    newton.identity.kyc.issued_since(90)
}
```

### newton.identity.get

Generic field accessor that works across any identity domain. Returns the raw field value by name from the current domain's `to_field_map()`.

**Signature:**

```rego
result := newton.identity.get(field_name)
```

**Arguments:**

| Argument     | Type   | Description                        |
|--------------|--------|------------------------------------|
| `field_name` | string | The field name to look up          |

**Returns:**

| Type      | Description                                                    |
|-----------|----------------------------------------------------------------|
| any/undef | The field value, or undefined if the field does not exist      |

**Example:**

```rego
package example

import future.keywords.if

# Use generic accessor for ad-hoc field checks
authorized if {
    newton.identity.get("status") == "approved"
    newton.identity.get("address_country_code") == "US"
}
```

## Error Handling

Address functions return an error (and the rule evaluates to undefined) when provided an empty array or provided with full names instead of ISO 3166 country and state codes. Date functions will error if given negative numbers.

## Technical Details

### Dependencies

The newton-identity feature adds the following dependencies:

| Crate            | Version | Purpose                      |
|------------------|---------|------------------------------|
| chrono           | 0.4.40  | Datetime calculation         |
