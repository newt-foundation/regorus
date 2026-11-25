# Newton Crypto Extensions

Newton-specific Rego built-in functions for Ethereum cryptography, enabled via the `newton-crypto` feature flag.

## Overview

The Newton crypto extensions provide Rego built-in functions for Ethereum signature verification and address recovery. These functions are designed for policy evaluation in blockchain contexts where transaction or message signatures need to be validated.

## Feature Flag

Enable newton-crypto extensions in your `Cargo.toml`:

```toml
regorus = { version = "0.5", features = ["newton-crypto"] }
```

Register the extensions with your engine:

```rust
use regorus::Engine;

let mut engine = Engine::new();
engine.with_newton_crypto_extensions()?;
```

## Built-in Functions

| Builtin                                     | Description                                         |
|---------------------------------------------|-----------------------------------------------------|
| newton.crypto.ecdsa_recover_signer          | Recover signer address from signature and hash      |
| newton.crypto.ecdsa_recover_signer_personal | Recover signer from personal_sign formatted message |

### newton.crypto.ecdsa_recover_signer

Recovers the Ethereum address from an ECDSA signature and message hash.

**Signature:**

```rego
result := newton.crypto.ecdsa_recover_signer(signature, message_hash)
```

**Arguments:**

| Argument       | Type   | Description                                    |
|----------------|--------|------------------------------------------------|
| `signature`    | string | Hex-encoded 65-byte signature (r, s, v format) |
| `message_hash` | string | Hex-encoded 32-byte keccak256 hash             |

**Returns:**

| Type   | Description                                               |
|--------|-----------------------------------------------------------|
| string | Checksummed Ethereum address (0x-prefixed, 42 characters) |

**Input Format:**

Both the signature and message hash can be provided with or without the `0x` prefix. The function handles both formats gracefully.

The signature must be in the Ethereum standard format:

- 32 bytes: `r` component
- 32 bytes: `s` component  
- 1 byte: `v` component (0, 1, 27, or 28)

**Example:**

```rego
package example

import future.keywords.if

# Recover the signer from a transaction signature
signer := newton.crypto.ecdsa_recover_signer(input.signature, input.tx_hash)

# Verify the signer is authorized
authorized if {
    signer == "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
}
```

### newton.crypto.ecdsa_recover_signer_personal

Recovers the Ethereum address from an ECDSA signature using the Ethereum personal_sign format.

This function automatically prefixes the message with `"\x19Ethereum Signed Message:\n<length>"` before hashing, matching the behavior of `eth_sign` and `personal_sign` RPC methods.

**Signature:**

```rego
result := newton.crypto.ecdsa_recover_signer_personal(signature, message)
```

**Arguments:**

| Argument    | Type   | Description                                    |
|-------------|--------|------------------------------------------------|
| `signature` | string | Hex-encoded 65-byte signature (r, s, v format) |
| `message`   | string | The original message string (not pre-hashed)   |

**Returns:**

| Type   | Description                                               |
|--------|-----------------------------------------------------------|
| string | Checksummed Ethereum address (0x-prefixed, 42 characters) |

**Example:**

```rego
package example

import future.keywords.if

# Recover signer from a signed message (e.g., SIWE authentication)
message := "Sign in to Newton Protocol\nNonce: abc123"
signer := newton.crypto.ecdsa_recover_signer_personal(input.signature, message)

# Verify the signer matches the claimed identity
valid_signer if {
    signer == input.claimed_address
}
```

## Error Handling

Both functions return an error (and the rule evaluates to undefined) when:

- The signature is not 65 bytes
- The message hash is not 32 bytes (for `ecdsa_recover_signer`)
- The hex encoding is invalid
- The signature recovery fails (invalid signature)

In Rego policies, you can handle these cases using default values:

```rego
package example

default signer := "0x0000000000000000000000000000000000000000"

signer := addr if {
    addr := newton.crypto.ecdsa_recover_signer(input.sig, input.hash)
}
```

## Use Cases

**Transaction Authorization:**

```rego
package tx_auth

import future.keywords.if

# Verify that a transaction was signed by an authorized operator
authorized if {
    signer := newton.crypto.ecdsa_recover_signer(input.signature, input.tx_hash)
    signer == data.operators[_].address
}
```

**Message Signature Verification:**

```rego
package message_auth

import future.keywords.if

# Verify a signed message for authentication (e.g., SIWE)
authenticated if {
    signer := newton.crypto.ecdsa_recover_signer_personal(
        input.signature, 
        input.message
    )
    signer == input.wallet_address
}
```

**Multi-Sig Verification:**

```rego
package multisig

import future.keywords.if

# Count valid signatures from authorized signers
valid_signers[signer] if {
    sig := input.signatures[_]
    signer := newton.crypto.ecdsa_recover_signer(sig, input.tx_hash)
    data.authorized_signers[signer]
}

# Require minimum threshold of signatures
has_quorum if {
    count(valid_signers) >= data.threshold
}
```

## Technical Details

### Address Derivation

The address is derived following the standard Ethereum process:

1. Recover the public key from the signature and message hash using ECDSA recovery
2. Take the uncompressed public key (64 bytes, without the 0x04 prefix)
3. Compute keccak256 hash of the public key bytes
4. Take the last 20 bytes of the hash as the address

### Dependencies

The newton-crypto feature adds the following dependencies:

| Crate            | Version | Purpose                      |
|------------------|---------|------------------------------|
| alloy-primitives | 0.8     | Ethereum types and keccak256 |
| k256             | 0.13    | ECDSA signature recovery     |
