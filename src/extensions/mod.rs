// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Newton Foundation.

//! Newton-specific Rego extensions.
//!
//! This module provides custom Rego built-in functions for Newton Protocol,
//! including Ethereum cryptography operations and privacy check operations.

#[cfg(feature = "newton-crypto")]
pub mod crypto;

#[cfg(feature = "newton-crypto")]
pub use crypto::register_newton_crypto_extensions;

#[cfg(feature = "newton-privacy")]
pub mod privacy;

#[cfg(feature = "newton-privacy")]
pub use privacy::{
    register_generic_privacy_extensions, register_kyc_privacy_extensions, KycPrivacyData,
    PrivacyDomainData, SharedPrivacyFields,
};

#[cfg(feature = "newton-tlsn")]
pub mod tlsn;

#[cfg(feature = "newton-tlsn")]
pub use tlsn::register_newton_tlsn_extensions;
