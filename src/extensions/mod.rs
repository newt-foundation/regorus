// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Newton Foundation.

//! Newton-specific Rego extensions.
//!
//! This module provides custom Rego built-in functions for Newton Protocol,
//! including Ethereum cryptography operations and Identity check operations.

extern crate alloc;

use alloc::{collections::BTreeMap, string::String};

// ---------------------------------------------------------------------------
// Unified domain trait
// ---------------------------------------------------------------------------

/// Unified trait for all policy domain data (identity and confidential).
///
/// Each domain (KYC, blacklist, allowlist, etc.) implements this trait to provide:
/// - A domain name for Rego namespace routing (e.g., "kyc", "blacklist")
/// - A Rego prefix determining the data namespace ("identity" or "privacy")
/// - A flat field map for the generic `newton.{prefix}.get()` accessor
pub trait PolicyDomainData: Send + Sync + std::fmt::Debug {
    /// Domain name for Rego namespace routing (e.g., "kyc", "blacklist", "allowlist").
    fn domain_name(&self) -> &str;

    /// Rego prefix: "identity" maps to `data.identity.*`, "confidential" maps to `data.confidential.*`.
    fn rego_prefix(&self) -> &str;

    /// Returns all fields as a flat string to Value map for the generic accessor.
    fn to_field_map(&self) -> BTreeMap<String, crate::Value>;
}

#[cfg(feature = "newton-crypto")]
pub mod crypto;

#[cfg(feature = "newton-crypto")]
pub use crypto::register_newton_crypto_extensions;

#[cfg(feature = "newton-identity")]
pub mod identity;

#[cfg(feature = "newton-identity")]
pub use identity::{
    register_generic_identity_extensions, register_kyc_identity_extensions,
    KycIdentityData, SharedIdentityFields,
};

#[cfg(feature = "newton-tlsn")]
pub mod tlsn;

#[cfg(feature = "newton-tlsn")]
pub use tlsn::register_newton_tlsn_extensions;

#[cfg(feature = "newton-confidential")]
pub mod confidential;

#[cfg(feature = "newton-confidential")]
pub use confidential::{
    register_blacklist_extensions, register_allowlist_extensions,
    register_generic_confidential_extensions,
    BlacklistData, AllowlistData, SharedConfidentialFields,
};

#[cfg(feature = "newton-time")]
pub mod time;

#[cfg(feature = "newton-time")]
pub use time::register_newton_time_extensions;
