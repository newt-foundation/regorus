// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Newton Foundation.

//! Newton-specific Rego extensions.
//!
//! This module provides custom Rego built-in functions for Newton Protocol,
//! including Ethereum cryptography operations and Identity check operations.

#[cfg(feature = "newton-crypto")]
pub mod crypto;

#[cfg(feature = "newton-crypto")]
pub use crypto::register_newton_crypto_extensions;

#[cfg(feature = "newton-identity")]
pub mod identity;

#[cfg(feature = "newton-identity")]
pub use identity::{
    register_generic_identity_extensions, register_kyc_identity_extensions, IdentityDomainData,
    KycIdentityData, SharedIdentityFields,
};

#[cfg(feature = "newton-tlsn")]
pub mod tlsn;

#[cfg(feature = "newton-tlsn")]
pub use tlsn::register_newton_tlsn_extensions;

#[cfg(feature = "newton-privacy")]
pub mod privacy;

#[cfg(feature = "newton-privacy")]
pub use privacy::{
    register_blacklist_extensions, register_allowlist_extensions,
    register_generic_privacy_extensions, ConfidentialDomainData,
    BlacklistData, AllowlistData, SharedPrivacyFields,
};

#[cfg(feature = "newton-time")]
pub mod time;

#[cfg(feature = "newton-time")]
pub use time::register_newton_time_extensions;
