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
pub use identity::register_newton_identity_extensions;
