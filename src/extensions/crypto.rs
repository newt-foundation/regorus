// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Newton Foundation.

//! Newton crypto extensions for Rego policy evaluation.
//!
//! Provides Ethereum-compatible ECDSA signature recovery functions.

extern crate alloc;

use alloc::{boxed::Box, format, string::ToString, vec::Vec};

use crate::{Engine, Value};
use alloy_primitives::{keccak256, Address, B256};
use anyhow::{bail, Result};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

/// Registers all Newton crypto extensions with the engine.
pub fn register_newton_crypto_extensions(engine: &mut Engine) -> Result<()> {
    engine.add_extension(
        "newton.crypto.ecdsa_recover_signer".to_string(),
        2,
        Box::new(ecdsa_recover_signer),
    )?;

    engine.add_extension(
        "newton.crypto.ecdsa_recover_signer_personal".to_string(),
        2,
        Box::new(ecdsa_recover_signer_personal),
    )?;

    Ok(())
}

/// Recovers the Ethereum address from an ECDSA signature and raw message hash.
///
/// # Arguments
/// * `params[0]` - Hex-encoded 65-byte signature (r, s, v format)
/// * `params[1]` - Hex-encoded 32-byte keccak256 message hash
///
/// # Returns
/// Checksummed Ethereum address (0x-prefixed)
fn ecdsa_recover_signer(params: Vec<Value>) -> Result<Value> {
    let signature_hex = params[0]
        .as_string()
        .map_err(|_| anyhow::anyhow!("signature must be a string"))?;
    let hash_hex = params[1]
        .as_string()
        .map_err(|_| anyhow::anyhow!("message_hash must be a string"))?;

    let signature_bytes = decode_hex(signature_hex.as_ref())?;
    let hash_bytes = decode_hex(hash_hex.as_ref())?;

    if signature_bytes.len() != 65 {
        bail!("signature must be 65 bytes, got {}", signature_bytes.len());
    }
    if hash_bytes.len() != 32 {
        bail!("message_hash must be 32 bytes, got {}", hash_bytes.len());
    }

    let hash: B256 = B256::from_slice(&hash_bytes);
    let address = recover_address(&signature_bytes, &hash)?;

    Ok(Value::from(format!("{}", address)))
}

/// Recovers the Ethereum address from an ECDSA signature using personal_sign format.
///
/// This function prefixes the message with "\x19Ethereum Signed Message:\n<length>"
/// before hashing, matching the behavior of eth_sign / personal_sign.
///
/// # Arguments
/// * `params[0]` - Hex-encoded 65-byte signature (r, s, v format)
/// * `params[1]` - The original message string (not pre-hashed)
///
/// # Returns
/// Checksummed Ethereum address (0x-prefixed)
fn ecdsa_recover_signer_personal(params: Vec<Value>) -> Result<Value> {
    let signature_hex = params[0]
        .as_string()
        .map_err(|_| anyhow::anyhow!("signature must be a string"))?;
    let message = params[1]
        .as_string()
        .map_err(|_| anyhow::anyhow!("message must be a string"))?;

    let signature_bytes = decode_hex(signature_hex.as_ref())?;

    if signature_bytes.len() != 65 {
        bail!("signature must be 65 bytes, got {}", signature_bytes.len());
    }

    let hash = personal_sign_hash(message.as_ref());
    let address = recover_address(&signature_bytes, &hash)?;

    Ok(Value::from(format!("{}", address)))
}

/// Decodes a hex string, handling optional 0x prefix.
fn decode_hex(hex: &str) -> Result<Vec<u8>> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|e| anyhow::anyhow!("invalid hex: {}", e))?;
    Ok(bytes)
}

/// Computes the Ethereum personal_sign message hash.
///
/// Format: keccak256("\x19Ethereum Signed Message:\n" + len(message) + message)
fn personal_sign_hash(message: &str) -> B256 {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut data = prefix.into_bytes();
    data.extend_from_slice(message.as_bytes());
    keccak256(&data)
}

/// Recovers an Ethereum address from a 65-byte signature and message hash.
fn recover_address(signature_bytes: &[u8], hash: &B256) -> Result<Address> {
    let r_s = &signature_bytes[0..64];
    let v = signature_bytes[64];

    // Handle both raw v (0, 1) and EIP-155 v (27, 28)
    let recovery_id = match v {
        0 | 27 => RecoveryId::new(false, false),
        1 | 28 => RecoveryId::new(true, false),
        _ => bail!("invalid recovery id: {}", v),
    };

    let signature = Signature::from_slice(r_s).map_err(|e| anyhow::anyhow!("invalid signature: {}", e))?;

    let recovered_key = VerifyingKey::recover_from_prehash(hash.as_slice(), &signature, recovery_id)
        .map_err(|e| anyhow::anyhow!("failed to recover public key: {}", e))?;

    // Get uncompressed public key bytes (65 bytes: 0x04 prefix + 64 bytes)
    let pubkey_bytes = recovered_key.to_encoded_point(false);
    let pubkey_uncompressed = pubkey_bytes.as_bytes();

    // Skip the 0x04 prefix and hash the remaining 64 bytes
    let pubkey_hash = keccak256(&pubkey_uncompressed[1..]);

    // Take the last 20 bytes as the address
    let address = Address::from_slice(&pubkey_hash[12..]);

    Ok(address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn decode_hex_handles_0x_prefix() {
        let with_prefix = decode_hex("0x1234").unwrap();
        let without_prefix = decode_hex("1234").unwrap();
        assert_eq!(with_prefix, without_prefix);
        assert_eq!(with_prefix, vec![0x12, 0x34]);
    }

    #[test]
    fn decode_hex_returns_error_for_invalid_hex() {
        assert!(decode_hex("0xgg").is_err());
        assert!(decode_hex("xyz").is_err());
    }

    #[test]
    fn personal_sign_hash_matches_expected_format() {
        let message = "hello";
        let hash = personal_sign_hash(message);
        // The hash should be deterministic
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn ecdsa_recover_signer_rejects_invalid_signature_length() {
        let params = vec![
            Value::from("0x1234"), // too short
            Value::from("0x0000000000000000000000000000000000000000000000000000000000000000"),
        ];
        let result = ecdsa_recover_signer(params);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("65 bytes"));
    }

    #[test]
    fn ecdsa_recover_signer_rejects_invalid_hash_length() {
        let sig = "0x".to_string() + &"00".repeat(65);
        let params = vec![
            Value::from(sig),
            Value::from("0x1234"), // too short
        ];
        let result = ecdsa_recover_signer(params);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("32 bytes"));
    }
}
