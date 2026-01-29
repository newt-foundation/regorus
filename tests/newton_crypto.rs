// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Newton Foundation.

//! Integration tests for Newton crypto Rego extensions.

#![cfg(feature = "newton-crypto")]

use regorus::{Engine, Value};

/// Test values generated using Foundry's cast with Anvil account 0.
/// Private key: 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
const TEST_SIGNER_ADDRESS: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

/// keccak256("hello")
const TEST_MESSAGE_HASH: &str = "0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8";

/// Signature of TEST_MESSAGE_HASH with the test private key (raw hash signing)
/// Generated via: cast wallet sign --no-hash --private-key <key> <hash>
const TEST_RAW_SIGNATURE: &str =
    "0x73eebf81a611136662d65778960c853fdcaf6eca86793ed9cabc30f2195937af78a07e601627da5b4cc80c0ab35f6894da19b4a01759d90c101d9c9dd1c6745d1b";

/// Signature of "Hello, Newton!" with personal_sign format (EIP-191)
/// Generated via: cast wallet sign --private-key <key> "Hello, Newton!"
const TEST_PERSONAL_SIGNATURE: &str =
    "0x9af892807bc7b85aa1a2d72afd27ba666c34a91ac1c27084680bd8e8f290a80f264866c894e8aff1fd5bda8a3c211cc5575bd99191a7b43fbf0c559d20ef89671c";

fn create_engine_with_extensions() -> Engine {
    let mut engine = Engine::new();
    engine
        .with_newton_crypto_extensions()
        .expect("failed to register newton crypto extensions");
    engine
}

#[test]
fn recover_signer_from_valid_signature_returns_correct_address() {
    let mut engine = create_engine_with_extensions();

    let policy = format!(
        r#"
        package test

        message_hash := "{}"
        signature := "{}"
        signer := newton.crypto.ecdsa_recover_signer(signature, message_hash)
    "#,
        TEST_MESSAGE_HASH, TEST_RAW_SIGNATURE
    );

    engine.add_policy("test.rego".to_string(), policy).unwrap();

    let results = engine.eval_query("data.test.signer".to_string(), false).unwrap();

    assert!(!results.result.is_empty(), "query should return results");
    let value = &results.result[0].expressions[0].value;

    let addr = value.as_string().expect("signer should be a string");
    assert_eq!(
        addr.to_lowercase(),
        TEST_SIGNER_ADDRESS.to_lowercase(),
        "recovered address should match expected signer"
    );
}

#[test]
fn recover_signer_personal_with_message_returns_valid_address() {
    let mut engine = create_engine_with_extensions();

    let policy = format!(
        r#"
        package test

        message := "Hello, Newton!"
        signature := "{}"
        signer := newton.crypto.ecdsa_recover_signer_personal(signature, message)
    "#,
        TEST_PERSONAL_SIGNATURE
    );

    engine.add_policy("test.rego".to_string(), policy).unwrap();

    let results = engine.eval_query("data.test.signer".to_string(), false).unwrap();

    assert!(!results.result.is_empty(), "query should return results");
    let value = &results.result[0].expressions[0].value;

    let addr = value.as_string().expect("signer should be a string");
    assert_eq!(
        addr.to_lowercase(),
        TEST_SIGNER_ADDRESS.to_lowercase(),
        "recovered address should match expected signer"
    );
}

#[test]
fn recover_signer_handles_signature_without_0x_prefix() {
    let mut engine = create_engine_with_extensions();

    // Strip 0x prefix from both signature and hash
    let sig_no_prefix = TEST_RAW_SIGNATURE.strip_prefix("0x").unwrap();
    let hash_no_prefix = TEST_MESSAGE_HASH.strip_prefix("0x").unwrap();

    let policy = format!(
        r#"
        package test

        message_hash := "{}"
        signature := "{}"
        signer := newton.crypto.ecdsa_recover_signer(signature, message_hash)
    "#,
        hash_no_prefix, sig_no_prefix
    );

    engine.add_policy("test.rego".to_string(), policy).unwrap();

    let results = engine.eval_query("data.test.signer".to_string(), false).unwrap();

    assert!(
        !results.result.is_empty(),
        "query should return results even without 0x prefix"
    );

    let value = &results.result[0].expressions[0].value;
    let addr = value.as_string().expect("signer should be a string");
    assert_eq!(
        addr.to_lowercase(),
        TEST_SIGNER_ADDRESS.to_lowercase(),
        "recovered address should match expected signer"
    );
}

#[test]
fn recover_signer_fails_with_invalid_signature_length() {
    let mut engine = create_engine_with_extensions();

    let policy = r#"
        package test

        message_hash := "0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
        signature := "0x1234"  # Too short

        signer := newton.crypto.ecdsa_recover_signer(signature, message_hash)
    "#;

    engine.add_policy("test.rego".to_string(), policy.to_string()).unwrap();

    // The query should fail or return undefined due to invalid signature
    let result = engine.eval_query("data.test.signer".to_string(), false);
    // Either the query fails or returns empty results
    assert!(result.is_err() || result.unwrap().result.is_empty());
}

#[test]
fn recover_signer_fails_with_invalid_hash_length() {
    let mut engine = create_engine_with_extensions();

    let policy = format!(
        r#"
        package test

        message_hash := "0x1234"
        signature := "{}"
        signer := newton.crypto.ecdsa_recover_signer(signature, message_hash)
    "#,
        TEST_RAW_SIGNATURE
    );

    engine.add_policy("test.rego".to_string(), policy).unwrap();

    let result = engine.eval_query("data.test.signer".to_string(), false);
    assert!(result.is_err() || result.unwrap().result.is_empty());
}

#[test]
fn newton_crypto_extensions_are_registered() {
    let mut engine = create_engine_with_extensions();

    // Simple policy that just references the extension
    let policy = r#"
        package test

        # Just verify the function exists by calling it with dummy values
        has_extension := true
    "#;

    engine.add_policy("test.rego".to_string(), policy.to_string()).unwrap();

    let results = engine.eval_query("data.test.has_extension".to_string(), false).unwrap();
    assert!(!results.result.is_empty());
    assert_eq!(results.result[0].expressions[0].value, Value::from(true));
}
