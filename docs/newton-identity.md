# Newton Identity Extensions

Newton-specific Rego built-in functions for checking identity data within the rego environment, enabled via the `newton-identity` feature flag.

## Overview

The Newton crypto extensions provide Rego built-in functions for checking user age, location, and approval status. These functions require passed in data from the environment initializing the engine. The intent is to allow policy writers to check against data that they know the policy evaluator can source without having direct access to it in a personally identifying way.

## Feature Flag

Enable newton-identity extensions in your `Cargo.toml`:

```toml
regorus = { version = "0.5", features = ["newton-identity"] }
```

Register the extensions with your engine:

```rust
use regorus::Engine;

let mut engine = Engine::new();
engine.with_newton_identity_extensions(identity_data)?;
```

## Data Type

The identity data input data type has the following structure:

```rust
struct IdentityData {
    /// either created, pending, completed, approved, failed, expired, declined, or needs review
    status: String,
    /// the country code selected by the user during the process
    selected_country_code: String,
    /// the state from the document address
    address_subdivision: String,
    /// the country from the document address
    address_country_code: String,
    /// the birthdate as a YYYY-MM-DD string
    birthdate: String,
    /// the expiration date of the document
    expiration_date: String,
    /// the issuing date of the document
    issue_date: String,
    /// the country or state that issued the document
    issuing_authority: String,
}
```

## Built-in Functions

| Builtin                                  | Description                                                                         |
|------------------------------------------|-------------------------------------------------------------------------------------|
| newton.identity.check_approved           | Check the status to ensure the data passed all approval checks before submitting    |
| newton.identity.address_in_countryies    | Check that the country on the submitted document is included in a list of countries |
| newton.identity.address_in_states        | Check that the address on the submitted document is included in a list of states    |
| newton.identity.address_not_in_states    | Check that the address on the submitted document is not within a list of states     |
| newton.identity.age_gte                  | Check that the birthdate in the data implies an age greater or equal to the input   |
| newton.identity.not_expired              | Check that the document expiration date has not passed                              |
| newton.identity.valid_for                | Check that the document expiration date is valid for subsequent inputted duration   |
| newton.identity.issued_since             | Check that the document issuing data was at least the specified time ago            |

### newton.identity.check_approved

Requires identity_data.status to equal "approved"

**Signature:**

```rego
result := newton.identity.check_approved()
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
    newton.identity.check_approved()
}
```

### newton.identity.address_in_countries

Requires identity_data.address_country_code to be found within the inputted list of country codes.

**Signature:**

```rego
result := newton.identity.address_in_countries(country_code_array)
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
    newton.identity.address_in_countries(["US","DE","CA"])
}
```

### newton.identity.address_in_states

Requires identity_data.address_country_code to equal "US" and identity_data.address_subdivision to be found within the inputted list of states.

**Signature:**

```rego
result := newton.identity.address_in_states(state_code_array)
```

**Arguments:**

| Argument           | Type     | Description                                                      |
|--------------------|----------|------------------------------------------------------------------|
| `state_code_array` | string[] | Array of 2 letter US state codes to match with the identity data |

**Returns:**

| Type   | Description                                                  |
|--------|--------------------------------------------------------------|
| bool   | true if the address state is within the list otherwise false |

**Example:**

```rego
package example

import future.keywords.if

# Verify the identity data matches address requirements
authorized if {
    newton.identity.address_in_states(["CA","OR","WA"])
}
```

### newton.identity.address_not_in_states

Requires identity_data.address_subdivision to not be included in the inputted list of states.

**Signature:**

```rego
result := newton.identity.address_not_in_states(state_code_array)
```

**Arguments:**

| Argument           | Type     | Description                                                      |
|--------------------|----------|------------------------------------------------------------------|
| `state_code_array` | string[] | Array of 2 letter US state codes to match with the identity data |

**Returns:**

| Type   | Description                                                  |
|--------|--------------------------------------------------------------|
| bool   | false if the address state is within the list otherwise true |

**Example:**

```rego
package example

import future.keywords.if

# Verify the identity data matches address requirements
authorized if {
    newton.identity.address_not_in_states(["NY","NC","HI"])
}
```

### newton.identity.age_gte

Requires identity_data.birthdate to be at least the required number of years ago at time of policy evaluation.

**Signature:**

```rego
result := newton.identity.age_gte(min_age)
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

# Verify the identity data matches birtdate requirements
authorized if {
    newton.identity.age_gte(21)
}
```

### newton.identity.not_expired

Requires identity_data.expiration_date to be after the current time at time of policy evaluation.

**Signature:**

```rego
result := newton.identity.not_expired()
```

**Returns:**

| Type   | Description                                                                                 |
|--------|---------------------------------------------------------------------------------------------|
| bool   | true if the document expiration date is in the future at time of evaluation otherwise false |

**Example:**

```rego
package example

import future.keywords.if

# Verify the identity document isn't expired
authorized if {
    newton.identity.not_expired()
}
```

### newton.identity.valid_for

Requires identity_data.expiration_date to be at least the required number of days in the future at time of policy evaluation.

**Signature:**

```rego
result := newton.identity.valid_for(min_days)
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
    newton.identity.valid_for(365)
}
```

### newton.identity.issued_since

Requires identity_data.issue_date to be at least the required number of days in the past at time of policy evaluation.

**Signature:**

```rego
result := newton.identity.issued_since(min_days)
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
    newton.identity.issued_since(90)
}
```

## Error Handling

Address functions return an error (and the rule evaluates to undefined) when provided an empty array or provided with full names instead of ISO 3166 country and state codes. Date functions will error if given negative numbers.

## Technical Details

### Dependencies

The newton-identity feature adds the following dependencies:

| Crate            | Version | Purpose                      |
|------------------|---------|------------------------------|
| alloy-primitives | 0.8     | Ethereum types               |

This is so that when imported, the IdentityData struct can be signed via EIP712 to verify it was sent by the correct user.
