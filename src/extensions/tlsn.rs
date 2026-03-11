// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Newton Foundation.

//! Newton TLSNotary extensions for Rego policy evaluation.
//!
//! Provides verification and extraction helpers for serialized TLSNotary
//! presentations.

extern crate alloc;

use alloc::{
    boxed::Box,
    collections::BTreeMap,
    string::{String, ToString as _},
    vec,
    vec::Vec,
};
use anyhow::{anyhow, bail, Result};
use bincode::{config::standard, serde::decode_from_slice};
use data_encoding::{BASE64, BASE64_NOPAD};
use p256::ecdsa::{signature::Verifier as _, Signature, VerifyingKey};
use rs_merkle::MerkleProof;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use tiny_keccak::Hasher as _;

use crate::{Engine, Value};

/// Maximum presentation / transcript size we are willing to allocate (16 MiB).
///
/// Checked before base64-decoded presentation deserialization *and* before
/// transcript expansion to prevent memory-exhaustion DoS from malicious
/// presentations.
const MAX_TRANSCRIPT_BYTES: usize = 16 * 1024 * 1024;

/// Registers all Newton TLSNotary extensions with the engine.
pub fn register_newton_tlsn_extensions(engine: &mut Engine) -> Result<()> {
    engine.add_extension(
        "newton.crypto.tlsn_verify".to_string(),
        2,
        Box::new(tlsn_verify),
    )?;

    Ok(())
}

/// Verifies a TLSNotary presentation and extracts disclosed HTTP fields.
///
/// # Arguments
/// * `params[0]` - Base64-encoded TLSNotary presentation bytes
/// * `params[1]` - Hex-encoded SEC1 P-256 notary public key
///
/// # Returns
/// A JSON object containing:
/// * `verified` - Whether the presentation and disclosed fields verify
/// * `server_name` - The authenticated HTTP Host header
/// * `response_body` - The authenticated HTTP response body
/// * `request_target` - The authenticated HTTP request target
fn tlsn_verify(params: Vec<Value>) -> Result<Value> {
    let presentation_b64 = params
        .first()
        .ok_or_else(|| anyhow!("presentation is missing"))?
        .as_string()
        .map_err(|_| anyhow!("presentation must be a string"))?;
    let notary_pubkey_hex = params
        .get(1)
        .ok_or_else(|| anyhow!("notary public key is missing"))?
        .as_string()
        .map_err(|_| anyhow!("notary public key must be a string"))?;

    let presentation_bytes = decode_base64(presentation_b64.as_ref())?;
    // Guard against oversized presentations before expensive deserialization.
    // base64 decodes to ~75% of input size, so MAX_TRANSCRIPT_BYTES covers this.
    if presentation_bytes.len() > MAX_TRANSCRIPT_BYTES {
        bail!(
            "presentation size ({}) exceeds maximum ({MAX_TRANSCRIPT_BYTES})",
            presentation_bytes.len()
        );
    }
    let trusted_notary_pubkey = decode_hex(notary_pubkey_hex.as_ref())?;
    let presentation = decode_presentation(&presentation_bytes)?;

    let VerificationStatus::Verified(verified_presentation) =
        verify_presentation(&presentation, &trusted_notary_pubkey)?
    else {
        return Ok(build_result(
            false,
            String::new(),
            String::new(),
            String::new(),
            false,
        ));
    };

    let server_name = match extract_server_name(
        &verified_presentation.transcript.sent,
        &verified_presentation.transcript.sent_authed,
    ) {
        Ok(server_name) => server_name,
        Err(_) => {
            return Ok(build_result(
                false,
                String::new(),
                String::new(),
                String::new(),
                false,
            ))
        }
    };
    // `identity_name` originates from `IdentityProofEnvelope.name`.  The
    // `verify_identity_commitment` call in `verify_presentation` proves that
    // `identity.opening` matches the attested certificate commitment, but the
    // `name` field itself is metadata not directly covered by the commitment
    // hash.  When `identity` is absent, `server_name` comes solely from the
    // prover-authored HTTP Host header.  We expose `identity_verified` in the
    // result so Rego policies can decide whether to trust `server_name`.
    let identity_verified = if let Some(identity_name) = verified_presentation.identity_name {
        let normalized_identity = normalize_host(&identity_name);
        let normalized_host = normalize_host(&server_name);
        if !normalized_identity.eq_ignore_ascii_case(&normalized_host) {
            return Ok(build_result(
                false,
                String::new(),
                String::new(),
                String::new(),
                false,
            ));
        }
        true
    } else {
        false
    };

    let request_target = match extract_request_target(
        &verified_presentation.transcript.sent,
        &verified_presentation.transcript.sent_authed,
    ) {
        Ok(request_target) => request_target,
        Err(_) => {
            return Ok(build_result(
                false,
                String::new(),
                String::new(),
                String::new(),
                false,
            ))
        }
    };
    let response_body = match extract_response_body(
        &verified_presentation.transcript.received,
        &verified_presentation.transcript.received_authed,
    ) {
        Ok(response_body) => response_body,
        Err(_) => {
            return Ok(build_result(
                false,
                String::new(),
                String::new(),
                String::new(),
                false,
            ))
        }
    };

    Ok(build_result(
        true,
        server_name,
        response_body,
        request_target,
        identity_verified,
    ))
}

enum VerificationStatus {
    Invalid,
    Verified(VerifiedPresentation),
}

struct VerifiedPresentation {
    transcript: PartialTranscriptData,
    identity_name: Option<String>,
}

fn verify_presentation(
    presentation: &PresentationEnvelope,
    trusted_notary_pubkey: &[u8],
) -> Result<VerificationStatus> {
    let Some(body) = verify_attestation(&presentation.attestation, trusted_notary_pubkey)? else {
        return Ok(VerificationStatus::Invalid);
    };

    if let Some(identity) = presentation.identity.as_ref() {
        if !verify_identity_commitment(identity, &body.cert_commitment.data)? {
            return Ok(VerificationStatus::Invalid);
        }
    }

    let Some(transcript_proof) = presentation.transcript.as_ref() else {
        return Ok(VerificationStatus::Invalid);
    };
    let Some(transcript) = verify_transcript_proof(
        transcript_proof,
        &body.connection_info.data.transcript_length,
        &body.transcript_commitments,
    )?
    else {
        return Ok(VerificationStatus::Invalid);
    };

    Ok(VerificationStatus::Verified(VerifiedPresentation {
        transcript,
        identity_name: presentation
            .identity
            .as_ref()
            .map(|identity| identity.name.as_str().to_string()),
    }))
}

fn verify_attestation<'a>(
    attestation: &'a AttestationProofEnvelope,
    trusted_notary_pubkey: &[u8],
) -> Result<Option<&'a BodyEnvelope>> {
    if attestation.signature.alg != SignatureAlgId::SECP256R1 {
        return Ok(None);
    }

    if !verify_body_proof(&attestation.header, &attestation.body)? {
        return Ok(None);
    }

    let body = &attestation.body.body;
    if body.verifying_key.data.alg != KeyAlgIdEnvelope::P256 {
        return Ok(None);
    }
    if body.verifying_key.data.data.as_slice() != trusted_notary_pubkey {
        return Ok(None);
    }

    let key = VerifyingKey::from_sec1_bytes(trusted_notary_pubkey)
        .map_err(|e| anyhow!("invalid P-256 notary public key: {e}"))?;
    let signature = Signature::from_slice(&attestation.signature.data)
        .map_err(|e| anyhow!("invalid P-256 signature: {e}"))?;
    let message =
        bcs::to_bytes(&attestation.header).map_err(|e| anyhow!("BCS serialization failed: {e}"))?;

    Ok(key.verify(&message, &signature).is_ok().then_some(body))
}

fn verify_body_proof(header: &HeaderEnvelope, body_proof: &BodyProofEnvelope) -> Result<bool> {
    if body_proof.proof.alg != header.root.alg {
        return Ok(false);
    }

    let field_hashes = body_field_hashes(&body_proof.body, header.root.alg)?;
    let (indices, leaves): (Vec<_>, Vec<_>) = field_hashes.into_iter().unzip();

    verify_merkle_proof(
        body_proof.proof.alg,
        &header.root.value,
        &indices,
        &leaves,
        &body_proof.proof.proof.proof_hashes,
        body_proof.proof.leaf_count,
    )
}

fn body_field_hashes(body: &BodyEnvelope, root_alg: HashAlgId) -> Result<Vec<(usize, [u8; 32])>> {
    let mut fields = vec![
        (
            usize::try_from(body.verifying_key.id.0)
                .map_err(|_| anyhow!("field id overflow for verifying key"))?,
            field_hash(root_alg, "VerifyingKey", &body.verifying_key.data)?,
        ),
        (
            usize::try_from(body.connection_info.id.0)
                .map_err(|_| anyhow!("field id overflow for connection info"))?,
            field_hash(
                root_alg,
                "tlsn_core::connection::ConnectionInfo",
                &body.connection_info.data,
            )?,
        ),
        (
            usize::try_from(body.server_ephemeral_key.id.0)
                .map_err(|_| anyhow!("field id overflow for server ephemeral key"))?,
            field_hash(
                root_alg,
                "tlsn_core::connection::ServerEphemKey",
                &body.server_ephemeral_key.data,
            )?,
        ),
        (
            usize::try_from(body.cert_commitment.id.0)
                .map_err(|_| anyhow!("field id overflow for certificate commitment"))?,
            field_hash(root_alg, "ServerCertCommitment", &body.cert_commitment.data)?,
        ),
    ];

    for extension in &body.extensions {
        fields.push((
            usize::try_from(extension.id.0)
                .map_err(|_| anyhow!("field id overflow for extension"))?,
            field_hash(root_alg, "Extension", &extension.data)?,
        ));
    }

    for commitment in &body.transcript_commitments {
        fields.push((
            usize::try_from(commitment.id.0)
                .map_err(|_| anyhow!("field id overflow for transcript commitment"))?,
            field_hash(
                root_alg,
                "tlsn_core::transcript::TranscriptCommitment",
                &commitment.data,
            )?,
        ));
    }

    fields.sort_unstable_by_key(|field| field.0);
    Ok(fields)
}

fn verify_identity_commitment(
    identity: &IdentityProofEnvelope,
    cert_commitment: &ServerCertCommitmentEnvelope,
) -> Result<bool> {
    let expected_commitment = field_hash(
        cert_commitment.0.alg,
        "ServerCertOpening",
        &identity.opening,
    )?;

    Ok(cert_commitment.0.value.as_slice() == expected_commitment)
}

fn verify_transcript_proof(
    transcript_proof: &TranscriptProofEnvelope,
    transcript_length: &TranscriptLengthEnvelope,
    transcript_commitments: &[FieldEnvelope<TranscriptCommitmentEnvelope>],
) -> Result<Option<PartialTranscriptData>> {
    let transcript = decompress_partial_transcript(&transcript_proof.transcript)?;

    if transcript.sent.len() != usize::try_from(transcript_length.sent).unwrap_or(usize::MAX)
        || transcript.received.len()
            != usize::try_from(transcript_length.received).unwrap_or(usize::MAX)
    {
        return Ok(None);
    }

    let mut authenticated_sent_ranges = Vec::new();
    let mut authenticated_received_ranges = Vec::new();

    for hash_secret in &transcript_proof.hash_secrets {
        let plaintext = match hash_secret.direction {
            DirectionEnvelope::Sent => {
                authenticated_sent_ranges.extend(hash_secret.idx.iter().cloned());
                collect_ranges_bytes(&transcript.sent, &hash_secret.idx)?
            }
            DirectionEnvelope::Received => {
                authenticated_received_ranges.extend(hash_secret.idx.iter().cloned());
                collect_ranges_bytes(&transcript.received, &hash_secret.idx)?
            }
        };

        let expected = TranscriptCommitmentEnvelope::Hash(PlaintextHashEnvelope {
            direction: hash_secret.direction.clone(),
            idx: hash_secret.idx.clone(),
            hash: hash_plaintext(hash_secret.alg, &plaintext, hash_secret.blinder.as_bytes())?,
        });

        if !transcript_commitments
            .iter()
            .any(|commitment| commitment.data == expected)
        {
            return Ok(None);
        }
    }

    let authenticated_sent = RangeSetEnvelope::from(authenticated_sent_ranges);
    let authenticated_received = RangeSetEnvelope::from(authenticated_received_ranges);
    if authenticated_sent != transcript.sent_authed
        || authenticated_received != transcript.received_authed
    {
        return Ok(None);
    }

    Ok(Some(transcript))
}

/// TLSNotary prover presentations are bincode-encoded as a whole, while the
/// nested attestation header is signed over its BCS encoding.
///
/// Verification therefore has to handle two serialization formats in the same
/// pipeline.
fn decode_presentation(bytes: &[u8]) -> Result<PresentationEnvelope> {
    let (presentation, consumed) = decode_from_slice::<PresentationEnvelope, _>(bytes, standard())
        .map_err(|e| anyhow!("invalid TLSNotary presentation encoding: {e}"))?;

    if consumed != bytes.len() {
        bail!("TLSNotary presentation has trailing bytes");
    }

    Ok(presentation)
}

fn decode_base64(encoded: &str) -> Result<Vec<u8>> {
    let trimmed = encoded.trim();

    BASE64
        .decode(trimmed.as_bytes())
        .or_else(|_| BASE64_NOPAD.decode(trimmed.as_bytes()))
        .map_err(|e| anyhow!("invalid base64 presentation: {e}"))
}

#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
fn decode_hex(hex: &str) -> Result<Vec<u8>> {
    let trimmed = hex.trim();
    let trimmed = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if !trimmed.len().is_multiple_of(2) {
        bail!("invalid hex length: {}", trimmed.len());
    }

    (0..trimmed.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&trimmed[index..index + 2], 16))
        .collect::<core::result::Result<Vec<u8>, _>>()
        .map_err(|e| anyhow!("invalid hex: {e}"))
}

fn build_result(
    verified: bool,
    server_name: String,
    response_body: String,
    request_target: String,
    identity_verified: bool,
) -> Value {
    let mut map = BTreeMap::new();
    map.insert(Value::from("verified"), Value::from(verified));
    map.insert(Value::from("server_name"), Value::from(server_name));
    map.insert(Value::from("response_body"), Value::from(response_body));
    map.insert(Value::from("request_target"), Value::from(request_target));
    // `identity_verified` is true when the presentation includes a certificate
    // identity proof whose opening matches the attested cert commitment AND
    // whose name matches the HTTP Host header.  When false, `server_name`
    // comes solely from the (prover-authored) HTTP Host header.  Rego policies
    // that need server-identity assurance MUST check `identity_verified == true`.
    map.insert(
        Value::from("identity_verified"),
        Value::from(identity_verified),
    );
    Value::from_map(map)
}

fn field_hash<T: Serialize>(alg: HashAlgId, domain_name: &str, value: &T) -> Result<[u8; 32]> {
    let canonical = bcs::to_bytes(value).map_err(|e| anyhow!("BCS serialization failed: {e}"))?;
    let domain = domain_separator(domain_name);
    digest_prefixed(alg, &domain, &canonical)
}

fn domain_separator(name: &str) -> [u8; 16] {
    let digest = blake3::hash(name.as_bytes());
    let mut separator = [0_u8; 16];
    separator.copy_from_slice(&digest.as_bytes()[..16]);
    separator
}

fn hash_plaintext(alg: HashAlgId, msg: &[u8], blinder: &[u8]) -> Result<TypedHashEnvelope> {
    Ok(TypedHashEnvelope {
        alg,
        value: digest_prefixed(alg, msg, blinder)?.to_vec(),
    })
}

fn digest_prefixed(alg: HashAlgId, prefix: &[u8], data: &[u8]) -> Result<[u8; 32]> {
    match alg.as_u8() {
        1 => {
            let mut hasher = sha2::Sha256::new();
            hasher.update(prefix);
            hasher.update(data);
            let digest = hasher.finalize();
            let mut output = [0_u8; 32];
            output.copy_from_slice(&digest);
            Ok(output)
        }
        2 => {
            let mut hasher = blake3::Hasher::new();
            hasher.update(prefix);
            hasher.update(data);
            Ok(*hasher.finalize().as_bytes())
        }
        3 => {
            let mut hasher = tiny_keccak::Keccak::v256();
            hasher.update(prefix);
            hasher.update(data);
            let mut output = [0_u8; 32];
            hasher.finalize(&mut output);
            Ok(output)
        }
        _ => bail!("unsupported TLSNotary hash algorithm: {}", alg.as_u8()),
    }
}

/// `leaf_count` comes from untrusted presentation data, but `rs_merkle`
/// rejects proofs whose declared leaf count does not match the proof-implied
/// tree structure.
fn verify_merkle_proof(
    alg: HashAlgId,
    root: &[u8],
    indices: &[usize],
    leaves: &[[u8; 32]],
    proof_hashes: &[Vec<u8>],
    leaf_count: usize,
) -> Result<bool> {
    let Some(root) = decode_fixed_hash(root) else {
        return Ok(false);
    };

    match alg.as_u8() {
        1 => {
            let proof = MerkleProof::<Sha256Merkle>::new(collect_fixed_hashes(proof_hashes)?);
            Ok(proof.verify(root, indices, leaves, leaf_count))
        }
        2 => {
            let proof = MerkleProof::<Blake3Merkle>::new(collect_fixed_hashes(proof_hashes)?);
            Ok(proof.verify(root, indices, leaves, leaf_count))
        }
        3 => {
            let proof = MerkleProof::<KeccakMerkle>::new(collect_fixed_hashes(proof_hashes)?);
            Ok(proof.verify(root, indices, leaves, leaf_count))
        }
        _ => bail!(
            "unsupported TLSNotary merkle hash algorithm: {}",
            alg.as_u8()
        ),
    }
}

fn collect_fixed_hashes(hashes: &[Vec<u8>]) -> Result<Vec<[u8; 32]>> {
    hashes
        .iter()
        .map(|hash| {
            decode_fixed_hash(hash).ok_or_else(|| anyhow!("invalid merkle proof hash length"))
        })
        .collect()
}

const fn decode_fixed_hash(hash: &[u8]) -> Option<[u8; 32]> {
    if hash.len() != 32 {
        return None;
    }

    let mut output = [0_u8; 32];
    output.copy_from_slice(hash);
    Some(output)
}

#[derive(Clone)]
struct Sha256Merkle;
#[derive(Clone)]
struct Blake3Merkle;
#[derive(Clone)]
struct KeccakMerkle;

impl rs_merkle::Hasher for Sha256Merkle {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> Self::Hash {
        let mut hasher = sha2::Sha256::new();
        hasher.update(data);
        let digest = hasher.finalize();
        let mut output = [0_u8; 32];
        output.copy_from_slice(&digest);
        output
    }
}

impl rs_merkle::Hasher for Blake3Merkle {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> Self::Hash {
        *blake3::hash(data).as_bytes()
    }
}

impl rs_merkle::Hasher for KeccakMerkle {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> Self::Hash {
        let mut hasher = tiny_keccak::Keccak::v256();
        hasher.update(data);
        let mut output = [0_u8; 32];
        hasher.finalize(&mut output);
        output
    }
}

fn decompress_partial_transcript(
    transcript: &CompressedPartialTranscriptEnvelope,
) -> Result<PartialTranscriptData> {
    Ok(PartialTranscriptData {
        sent: expand_ranges(
            &transcript.sent_authed,
            &transcript.sent_idx,
            transcript.sent_total,
            "sent",
        )?,
        received: expand_ranges(
            &transcript.received_authed,
            &transcript.recv_idx,
            transcript.recv_total,
            "received",
        )?,
        sent_authed: transcript.sent_idx.clone(),
        received_authed: transcript.recv_idx.clone(),
    })
}

#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
fn expand_ranges(
    authenticated: &[u8],
    indices: &RangeSetEnvelope,
    total_len: usize,
    label: &str,
) -> Result<Vec<u8>> {
    if total_len > MAX_TRANSCRIPT_BYTES {
        bail!("{label} transcript length ({total_len}) exceeds maximum ({MAX_TRANSCRIPT_BYTES})");
    }
    let mut expanded = vec![0; total_len];
    let mut offset = 0_usize;

    for range in indices.iter() {
        if range.end > total_len {
            bail!("{label} transcript range is out of bounds");
        }

        let range_len = range
            .end
            .checked_sub(range.start)
            .ok_or_else(|| anyhow!("{label} transcript range underflow"))?;
        let next_offset = offset
            .checked_add(range_len)
            .ok_or_else(|| anyhow!("{label} transcript offset overflow"))?;
        if next_offset > authenticated.len() {
            bail!("{label} transcript authenticated bytes do not match ranges");
        }

        expanded[range.clone()].copy_from_slice(&authenticated[offset..next_offset]);
        offset = next_offset;
    }

    if offset != authenticated.len() {
        bail!("{label} transcript authenticated bytes do not match ranges");
    }

    Ok(expanded)
}

#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
fn collect_ranges_bytes(data: &[u8], indices: &RangeSetEnvelope) -> Result<Vec<u8>> {
    let mut output = Vec::new();

    for range in indices.iter() {
        if range.end > data.len() {
            bail!("range is out of bounds for authenticated transcript data");
        }

        output.extend_from_slice(&data[range.clone()]);
    }

    Ok(output)
}

#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
fn extract_request_target(request: &[u8], authed: &RangeSetEnvelope) -> Result<String> {
    let line_end = find_subsequence(request, b"\r\n")
        .ok_or_else(|| anyhow!("HTTP request line is missing a CRLF terminator"))?;
    ensure_authenticated_range(authed, 0..line_end + 2, "HTTP request line")?;
    let line = &request[..line_end];
    let first_space = line
        .iter()
        .position(|byte| *byte == b' ')
        .ok_or_else(|| anyhow!("HTTP request line is missing a method separator"))?;
    let rest = &line[first_space + 1..];
    let second_space = rest
        .iter()
        .position(|byte| *byte == b' ')
        .ok_or_else(|| anyhow!("HTTP request line is missing a protocol separator"))?;
    let target = core::str::from_utf8(&rest[..second_space])
        .map_err(|e| anyhow!("request target is not valid UTF-8: {e}"))?;

    if target.is_empty() {
        bail!("HTTP request target is empty");
    }

    Ok(target.to_string())
}

#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
fn extract_server_name(request: &[u8], authed: &RangeSetEnvelope) -> Result<String> {
    let (host_range, host) = header_value_with_range(request, "host")?
        .ok_or_else(|| anyhow!("HTTP request is missing a Host header"))?;
    ensure_authenticated_range(authed, host_range, "HTTP Host header")?;
    let server_name = normalize_host(host);
    if server_name.is_empty() {
        bail!("HTTP Host header is empty");
    }

    Ok(server_name)
}

fn normalize_host(host: &str) -> String {
    let trimmed = host.trim();
    if let Some(stripped) = trimmed.strip_prefix('[') {
        if let Some(end) = stripped.find(']') {
            return stripped[..end].to_string();
        }
    }

    trimmed
        .split(':')
        .next()
        .unwrap_or(trimmed)
        .trim()
        .to_string()
}

#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
fn extract_response_body(response: &[u8], authed: &RangeSetEnvelope) -> Result<String> {
    let header_end = find_subsequence(response, b"\r\n\r\n")
        .ok_or_else(|| anyhow!("HTTP response headers are incomplete"))?;
    ensure_authenticated_range(authed, 0..header_end + 4, "HTTP response headers")?;
    let headers = &response[..header_end + 2];
    let body_start = header_end + 4;
    let body = &response[body_start..];

    let body = if let Some(transfer_encoding) = header_value(headers, "transfer-encoding")? {
        if transfer_encoding
            .split(',')
            .any(|value| value.trim().eq_ignore_ascii_case("chunked"))
        {
            decode_chunked_body(body, body_start, authed)?
        } else {
            ensure_authenticated_range(authed, body_start..response.len(), "HTTP response body")?;
            body.to_vec()
        }
    } else if let Some(content_length) = header_value(headers, "content-length")? {
        let content_length = content_length
            .parse::<usize>()
            .map_err(|e| anyhow!("invalid content-length header: {e}"))?;
        let body_end = body_start
            .checked_add(content_length)
            .ok_or_else(|| anyhow!("HTTP response body length overflow"))?;
        if response.len() < body_end {
            bail!("HTTP response body is shorter than content-length");
        }
        ensure_authenticated_range(authed, body_start..body_end, "HTTP response body")?;
        response[body_start..body_end].to_vec()
    } else {
        ensure_authenticated_range(authed, body_start..response.len(), "HTTP response body")?;
        body.to_vec()
    };

    Ok(String::from_utf8_lossy(&body).into_owned())
}

fn ensure_authenticated_range(
    authed: &RangeSetEnvelope,
    range: core::ops::Range<usize>,
    label: &str,
) -> Result<()> {
    if contains_range(authed, range) {
        Ok(())
    } else {
        bail!("{label} is not fully authenticated")
    }
}

fn contains_range(authed: &RangeSetEnvelope, range: core::ops::Range<usize>) -> bool {
    if range.start == range.end {
        return true;
    }

    authed
        .iter()
        .any(|authenticated| authenticated.start <= range.start && range.end <= authenticated.end)
}

fn header_value<'a>(headers: &'a [u8], name: &str) -> Result<Option<&'a str>> {
    Ok(header_value_with_range(headers, name)?.map(|(_, value)| value))
}

#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
fn header_value_with_range<'a>(
    headers: &'a [u8],
    name: &str,
) -> Result<Option<(core::ops::Range<usize>, &'a str)>> {
    let first_line_end = find_subsequence(headers, b"\r\n")
        .ok_or_else(|| anyhow!("HTTP message is missing a start-line terminator"))?;
    let mut line_start = first_line_end + 2;

    while line_start < headers.len() {
        let line_end = find_subsequence(&headers[line_start..], b"\r\n")
            .ok_or_else(|| anyhow!("HTTP header line is missing a CRLF terminator"))?;
        let absolute_line_end = line_start + line_end;
        let line = &headers[line_start..absolute_line_end];

        if line.is_empty() {
            break;
        }

        if let Some(colon) = line.iter().position(|byte| *byte == b':') {
            let header_name = core::str::from_utf8(&line[..colon])
                .map_err(|e| anyhow!("header name is not valid UTF-8: {e}"))?;
            if header_name.eq_ignore_ascii_case(name) {
                let value = core::str::from_utf8(&line[colon + 1..])
                    .map_err(|e| anyhow!("header value is not valid UTF-8: {e}"))?;
                return Ok(Some((line_start..absolute_line_end + 2, value.trim())));
            }
        }

        line_start = absolute_line_end + 2;
    }

    Ok(None)
}

#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
fn decode_chunked_body(
    body: &[u8],
    body_offset: usize,
    authed: &RangeSetEnvelope,
) -> Result<Vec<u8>> {
    let mut decoded = Vec::new();
    let mut offset = 0_usize;

    loop {
        let line_end = find_subsequence(&body[offset..], b"\r\n")
            .ok_or_else(|| anyhow!("chunked response is missing a size line terminator"))?;
        let absolute_line_end = offset + line_end;
        ensure_authenticated_range(
            authed,
            body_offset + offset..body_offset + absolute_line_end + 2,
            "chunked response size line",
        )?;
        let size_line = &body[offset..absolute_line_end];
        let size_token = size_line
            .splitn(2, |byte| *byte == b';')
            .next()
            .ok_or_else(|| anyhow!("chunked response is missing a size token"))?;
        let size = usize::from_str_radix(
            core::str::from_utf8(size_token)
                .map_err(|e| anyhow!("chunk size is not valid UTF-8: {e}"))?
                .trim(),
            16,
        )
        .map_err(|e| anyhow!("invalid chunk size: {e}"))?;

        offset = absolute_line_end + 2;

        if size == 0 {
            verify_chunked_trailers(&body[offset..], body_offset + offset, authed)?;
            return Ok(decoded);
        }

        let chunk_end = offset
            .checked_add(size)
            .ok_or_else(|| anyhow!("chunked response length overflow"))?;
        let chunk_crlf_end = chunk_end
            .checked_add(2)
            .ok_or_else(|| anyhow!("chunked response length overflow"))?;
        if body.len() < chunk_crlf_end {
            bail!("chunked response ended before the declared chunk size");
        }
        if &body[chunk_end..chunk_crlf_end] != b"\r\n" {
            bail!("chunked response chunk is missing a trailing CRLF");
        }
        ensure_authenticated_range(
            authed,
            body_offset + offset..body_offset + chunk_crlf_end,
            "chunked response chunk",
        )?;

        decoded.extend_from_slice(&body[offset..chunk_end]);
        offset = chunk_crlf_end;
    }
}

#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
fn verify_chunked_trailers(
    mut body: &[u8],
    mut absolute_offset: usize,
    authed: &RangeSetEnvelope,
) -> Result<()> {
    loop {
        let line_end = find_subsequence(body, b"\r\n")
            .ok_or_else(|| anyhow!("chunked response trailers are incomplete"))?;
        ensure_authenticated_range(
            authed,
            absolute_offset..absolute_offset + line_end + 2,
            "chunked response trailer",
        )?;
        if line_end == 0 {
            return Ok(());
        }

        absolute_offset += line_end + 2;
        body = &body[line_end + 2..];
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }

    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PresentationEnvelope {
    attestation: AttestationProofEnvelope,
    identity: Option<IdentityProofEnvelope>,
    transcript: Option<TranscriptProofEnvelope>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AttestationProofEnvelope {
    signature: SignatureEnvelope,
    header: HeaderEnvelope,
    body: BodyProofEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BodyProofEnvelope {
    body: BodyEnvelope,
    proof: MerkleProofEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BodyEnvelope {
    verifying_key: FieldEnvelope<PresentationVerifyingKeyEnvelope>,
    connection_info: FieldEnvelope<ConnectionInfoEnvelope>,
    server_ephemeral_key: FieldEnvelope<ServerEphemeralKeyEnvelope>,
    cert_commitment: FieldEnvelope<ServerCertCommitmentEnvelope>,
    extensions: Vec<FieldEnvelope<ExtensionEnvelope>>,
    transcript_commitments: Vec<FieldEnvelope<TranscriptCommitmentEnvelope>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FieldEnvelope<T> {
    id: FieldIdEnvelope,
    data: T,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct FieldIdEnvelope(u32);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SignatureEnvelope {
    alg: SignatureAlgId,
    data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct HeaderEnvelope {
    id: Uid,
    version: Version,
    root: TypedHashEnvelope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Uid([u8; 16]);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Version(u32);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TypedHashEnvelope {
    alg: HashAlgId,
    value: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct HashAlgId(u8);

#[allow(dead_code)]
impl HashAlgId {
    const SHA256: Self = Self(1);
    const BLAKE3: Self = Self(2);
    const KECCAK256: Self = Self(3);

    const fn as_u8(self) -> u8 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct SignatureAlgId(u8);

impl SignatureAlgId {
    const SECP256R1: Self = Self(2);
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PresentationVerifyingKeyEnvelope {
    alg: KeyAlgIdEnvelope,
    data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct KeyAlgIdEnvelope(u8);

impl KeyAlgIdEnvelope {
    const P256: Self = Self(2);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConnectionInfoEnvelope {
    time: u64,
    version: TlsVersionEnvelope,
    transcript_length: TranscriptLengthEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum TlsVersionEnvelope {
    #[serde(rename = "v1_2")]
    V1_2,
    #[serde(rename = "v1_3")]
    V1_3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TranscriptLengthEnvelope {
    sent: u32,
    received: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ServerEphemeralKeyEnvelope {
    #[serde(rename = "type")]
    typ: KeyTypeEnvelope,
    key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum KeyTypeEnvelope {
    #[serde(rename = "secp256r1")]
    Secp256r1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ServerCertCommitmentEnvelope(TypedHashEnvelope);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExtensionEnvelope {
    id: Vec<u8>,
    value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum TranscriptCommitmentEnvelope {
    Hash(PlaintextHashEnvelope),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PlaintextHashEnvelope {
    direction: DirectionEnvelope,
    idx: RangeSetEnvelope,
    hash: TypedHashEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MerkleProofEnvelope {
    alg: HashAlgId,
    leaf_count: usize,
    proof: RsMerkleProofEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RsMerkleProofEnvelope {
    proof_hashes: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IdentityProofEnvelope {
    name: ServerNameEnvelope,
    opening: ServerCertOpeningEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum ServerNameEnvelope {
    Dns(String),
}

impl ServerNameEnvelope {
    #[allow(clippy::pattern_type_mismatch)]
    const fn as_str(&self) -> &str {
        match self {
            Self::Dns(name) => name.as_str(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ServerCertOpeningEnvelope(BlindedEnvelope<HandshakeDataEnvelope>);

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BlindedEnvelope<T> {
    data: T,
    blinder: BlinderEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HandshakeDataEnvelope {
    certs: Vec<Vec<u8>>,
    sig: ServerSignatureEnvelope,
    binding: CertBindingEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ServerSignatureEnvelope {
    alg: SignatureAlgorithmEnvelope,
    sig: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum CertBindingEnvelope {
    #[serde(rename = "v1_2")]
    V1_2(CertBindingV12Envelope),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CertBindingV12Envelope {
    client_random: [u8; 32],
    server_random: [u8; 32],
    server_ephemeral_key: ServerEphemeralKeyEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum SignatureAlgorithmEnvelope {
    EcdsaNistp256Sha256,
    EcdsaNistp256Sha384,
    EcdsaNistp384Sha256,
    EcdsaNistp384Sha384,
    Ed25519,
    RsaPkcs1_2048_8192Sha256,
    RsaPkcs1_2048_8192Sha384,
    RsaPkcs1_2048_8192Sha512,
    RsaPss2048_8192Sha256LegacyKey,
    RsaPss2048_8192Sha384LegacyKey,
    RsaPss2048_8192Sha512LegacyKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TranscriptProofEnvelope {
    transcript: CompressedPartialTranscriptEnvelope,
    hash_secrets: Vec<PlaintextHashSecretEnvelope>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PlaintextHashSecretEnvelope {
    direction: DirectionEnvelope,
    idx: RangeSetEnvelope,
    alg: HashAlgId,
    blinder: BlinderEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BlinderEnvelope([u8; 16]);

impl BlinderEnvelope {
    const fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum DirectionEnvelope {
    Sent,
    Received,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompressedPartialTranscriptEnvelope {
    sent_authed: Vec<u8>,
    received_authed: Vec<u8>,
    sent_idx: RangeSetEnvelope,
    recv_idx: RangeSetEnvelope,
    sent_total: usize,
    recv_total: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    from = "Vec<core::ops::Range<usize>>",
    into = "Vec<core::ops::Range<usize>>"
)]
struct RangeSetEnvelope {
    ranges: Vec<core::ops::Range<usize>>,
}

impl RangeSetEnvelope {
    fn iter(&self) -> impl Iterator<Item = &core::ops::Range<usize>> {
        self.ranges.iter()
    }
}

impl From<core::ops::Range<usize>> for RangeSetEnvelope {
    fn from(range: core::ops::Range<usize>) -> Self {
        Self {
            ranges: vec![range],
        }
    }
}

impl From<Vec<core::ops::Range<usize>>> for RangeSetEnvelope {
    fn from(mut ranges: Vec<core::ops::Range<usize>>) -> Self {
        ranges.retain(|range| range.start < range.end);
        ranges.sort_unstable_by(|left, right| match left.start.cmp(&right.start) {
            core::cmp::Ordering::Equal => left.end.cmp(&right.end),
            ordering => ordering,
        });

        let mut merged: Vec<core::ops::Range<usize>> = Vec::with_capacity(ranges.len());
        for range in ranges {
            if let Some(last) = merged.last_mut() {
                if range.start <= last.end {
                    if range.end > last.end {
                        last.end = range.end;
                    }
                    continue;
                }
            }

            merged.push(range);
        }

        Self { ranges: merged }
    }
}

impl From<RangeSetEnvelope> for Vec<core::ops::Range<usize>> {
    fn from(value: RangeSetEnvelope) -> Self {
        value.ranges
    }
}

struct PartialTranscriptData {
    sent: Vec<u8>,
    received: Vec<u8>,
    sent_authed: RangeSetEnvelope,
    received_authed: RangeSetEnvelope,
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::as_conversions,
        clippy::assertions_on_result_states,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::unwrap_used
    )]

    use super::*;
    use alloc::format;
    use bincode::serde::encode_to_vec;
    use p256::ecdsa::{signature::Signer as _, Signature as P256Signature, SigningKey};
    use rs_merkle::MerkleTree;

    const DEFAULT_REQUEST: &str = "GET /v1/resource?foo=bar HTTP/1.1\r\nHost: example.com\r\n\r\n";

    fn hex_encode(bytes: &[u8]) -> String {
        let mut encoded = String::from("0x");
        for byte in bytes {
            encoded.push_str(&format!("{byte:02x}"));
        }
        encoded
    }

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_slice(&[seed; 32]).expect("valid signing key")
    }

    fn build_fixture_presentation(seed: u8, response: &str) -> (PresentationEnvelope, Vec<u8>) {
        build_fixture_presentation_with_ranges(
            seed,
            DEFAULT_REQUEST,
            response,
            RangeSetEnvelope::from(0..DEFAULT_REQUEST.len()),
            RangeSetEnvelope::from(0..response.len()),
        )
    }

    fn build_fixture_presentation_with_ranges(
        seed: u8,
        request: &str,
        response: &str,
        sent_idx: RangeSetEnvelope,
        recv_idx: RangeSetEnvelope,
    ) -> (PresentationEnvelope, Vec<u8>) {
        let signing_key = signing_key(seed);
        let trusted_key = signing_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        let sent_authed =
            collect_ranges_bytes(request.as_bytes(), &sent_idx).expect("sent transcript ranges");
        let received_authed = collect_ranges_bytes(response.as_bytes(), &recv_idx)
            .expect("received transcript ranges");

        let sent_secret = PlaintextHashSecretEnvelope {
            direction: DirectionEnvelope::Sent,
            idx: sent_idx.clone(),
            alg: HashAlgId::SHA256,
            blinder: BlinderEnvelope([1; 16]),
        };
        let received_secret = PlaintextHashSecretEnvelope {
            direction: DirectionEnvelope::Received,
            idx: recv_idx.clone(),
            alg: HashAlgId::SHA256,
            blinder: BlinderEnvelope([2; 16]),
        };

        let identity_opening = ServerCertOpeningEnvelope(BlindedEnvelope {
            data: HandshakeDataEnvelope {
                certs: vec![vec![0x30, 0x82, 0x01, 0x00]],
                sig: ServerSignatureEnvelope {
                    alg: SignatureAlgorithmEnvelope::EcdsaNistp256Sha256,
                    sig: vec![0xaa, 0xbb],
                },
                binding: CertBindingEnvelope::V1_2(CertBindingV12Envelope {
                    client_random: [3; 32],
                    server_random: [4; 32],
                    server_ephemeral_key: ServerEphemeralKeyEnvelope {
                        typ: KeyTypeEnvelope::Secp256r1,
                        key: vec![9; 65],
                    },
                }),
            },
            blinder: BlinderEnvelope([5; 16]),
        });

        let cert_commitment = ServerCertCommitmentEnvelope(TypedHashEnvelope {
            alg: HashAlgId::SHA256,
            value: field_hash(HashAlgId::SHA256, "ServerCertOpening", &identity_opening)
                .expect("identity opening hashes")
                .to_vec(),
        });

        let sent_commitment = TranscriptCommitmentEnvelope::Hash(PlaintextHashEnvelope {
            direction: DirectionEnvelope::Sent,
            idx: sent_secret.idx.clone(),
            hash: hash_plaintext(
                HashAlgId::SHA256,
                &sent_authed,
                sent_secret.blinder.as_bytes(),
            )
            .expect("sent hash commitment"),
        });
        let received_commitment = TranscriptCommitmentEnvelope::Hash(PlaintextHashEnvelope {
            direction: DirectionEnvelope::Received,
            idx: received_secret.idx.clone(),
            hash: hash_plaintext(
                HashAlgId::SHA256,
                &received_authed,
                received_secret.blinder.as_bytes(),
            )
            .expect("received hash commitment"),
        });

        let body = BodyEnvelope {
            verifying_key: FieldEnvelope {
                id: FieldIdEnvelope(0),
                data: PresentationVerifyingKeyEnvelope {
                    alg: KeyAlgIdEnvelope::P256,
                    data: trusted_key.clone(),
                },
            },
            connection_info: FieldEnvelope {
                id: FieldIdEnvelope(1),
                data: ConnectionInfoEnvelope {
                    time: 1,
                    version: TlsVersionEnvelope::V1_2,
                    transcript_length: TranscriptLengthEnvelope {
                        sent: request.len() as u32,
                        received: response.len() as u32,
                    },
                },
            },
            server_ephemeral_key: FieldEnvelope {
                id: FieldIdEnvelope(2),
                data: ServerEphemeralKeyEnvelope {
                    typ: KeyTypeEnvelope::Secp256r1,
                    key: vec![9; 65],
                },
            },
            cert_commitment: FieldEnvelope {
                id: FieldIdEnvelope(3),
                data: cert_commitment,
            },
            extensions: Vec::new(),
            transcript_commitments: vec![
                FieldEnvelope {
                    id: FieldIdEnvelope(4),
                    data: sent_commitment,
                },
                FieldEnvelope {
                    id: FieldIdEnvelope(5),
                    data: received_commitment,
                },
            ],
        };

        let body_hashes = body_field_hashes(&body, HashAlgId::SHA256).expect("body hashes");
        let (indices, leaves): (Vec<_>, Vec<_>) = body_hashes.into_iter().unzip();
        let tree = MerkleTree::<Sha256Merkle>::from_leaves(&leaves);
        let proof = tree.proof(&indices);
        let root = tree.root().expect("tree root");

        let header = HeaderEnvelope {
            id: Uid([7; 16]),
            version: Version(0),
            root: TypedHashEnvelope {
                alg: HashAlgId::SHA256,
                value: root.to_vec(),
            },
        };
        let message = bcs::to_bytes(&header).expect("header serialization");
        let signature: P256Signature = signing_key.sign(&message);

        let presentation = PresentationEnvelope {
            attestation: AttestationProofEnvelope {
                signature: SignatureEnvelope {
                    alg: SignatureAlgId::SECP256R1,
                    data: signature.to_bytes().to_vec(),
                },
                header,
                body: BodyProofEnvelope {
                    body,
                    proof: MerkleProofEnvelope {
                        alg: HashAlgId::SHA256,
                        leaf_count: leaves.len(),
                        proof: RsMerkleProofEnvelope {
                            proof_hashes: proof
                                .proof_hashes()
                                .iter()
                                .map(|hash| hash.to_vec())
                                .collect(),
                        },
                    },
                },
            },
            identity: Some(IdentityProofEnvelope {
                name: ServerNameEnvelope::Dns("example.com".to_string()),
                opening: identity_opening,
            }),
            transcript: Some(TranscriptProofEnvelope {
                transcript: CompressedPartialTranscriptEnvelope {
                    sent_authed,
                    received_authed,
                    sent_idx,
                    recv_idx,
                    sent_total: request.len(),
                    recv_total: response.len(),
                },
                hash_secrets: vec![sent_secret, received_secret],
            }),
        };

        (presentation, trusted_key)
    }

    fn encode_fixture(presentation: &PresentationEnvelope, trusted_key: &[u8]) -> (String, String) {
        let bytes = encode_to_vec(presentation, standard()).expect("fixture should encode");
        (BASE64.encode(&bytes), hex_encode(trusted_key))
    }

    #[test]
    fn tlsn_verify_returns_verified_payload() {
        let response = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\n{\"ok\":true}\n\n";
        let (presentation, trusted_key) = build_fixture_presentation(3, response);
        let (presentation_b64, trusted_key_hex) = encode_fixture(&presentation, &trusted_key);

        let result = tlsn_verify(vec![
            Value::from(presentation_b64),
            Value::from(trusted_key_hex),
        ])
        .expect("tlsn_verify should succeed");

        assert_eq!(result["verified"], Value::from(true));
        assert_eq!(result["server_name"], Value::from("example.com"));
        assert_eq!(
            result["request_target"],
            Value::from("/v1/resource?foo=bar")
        );
        assert_eq!(result["response_body"], Value::from("{\"ok\":true}\n\n"));
    }

    #[test]
    fn tlsn_verify_returns_false_for_signature_mismatch() {
        let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let (presentation, trusted_key) = build_fixture_presentation(5, response);
        let wrong_key = signing_key(9);
        let wrong_key_hex = hex_encode(wrong_key.verifying_key().to_encoded_point(true).as_bytes());
        let (presentation_b64, _) = encode_fixture(&presentation, &trusted_key);

        let result = tlsn_verify(vec![
            Value::from(presentation_b64),
            Value::from(wrong_key_hex),
        ])
        .expect("tlsn_verify should return a verification result");

        assert_eq!(result["verified"], Value::from(false));
        assert_eq!(result["server_name"], Value::from(""));
        assert_eq!(result["request_target"], Value::from(""));
        assert_eq!(result["response_body"], Value::from(""));
    }

    #[test]
    fn tlsn_verify_rejects_tampered_transcript() {
        let response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let (mut presentation, trusted_key) = build_fixture_presentation(7, response);
        presentation
            .transcript
            .as_mut()
            .unwrap()
            .transcript
            .received_authed = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nworld".to_vec();
        let (presentation_b64, trusted_key_hex) = encode_fixture(&presentation, &trusted_key);

        let result = tlsn_verify(vec![
            Value::from(presentation_b64),
            Value::from(trusted_key_hex),
        ])
        .expect("tampered presentations should return verified=false");

        assert_eq!(result["verified"], Value::from(false));
    }

    #[test]
    fn tlsn_verify_rejects_tampered_attested_body() {
        let response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let (mut presentation, trusted_key) = build_fixture_presentation(11, response);
        presentation.attestation.body.body.connection_info.data.time = 99;
        let (presentation_b64, trusted_key_hex) = encode_fixture(&presentation, &trusted_key);

        let result = tlsn_verify(vec![
            Value::from(presentation_b64),
            Value::from(trusted_key_hex),
        ])
        .expect("tampered body proofs should return verified=false");

        assert_eq!(result["verified"], Value::from(false));
    }

    #[test]
    fn tlsn_verify_rejects_gapped_request_target_disclosure() {
        let response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let gap_index = DEFAULT_REQUEST.find("resource").unwrap() + 2;
        let sent_idx =
            RangeSetEnvelope::from(vec![0..gap_index, gap_index + 1..DEFAULT_REQUEST.len()]);
        let (presentation, trusted_key) = build_fixture_presentation_with_ranges(
            17,
            DEFAULT_REQUEST,
            response,
            sent_idx,
            RangeSetEnvelope::from(0..response.len()),
        );
        let (presentation_b64, trusted_key_hex) = encode_fixture(&presentation, &trusted_key);

        let result = tlsn_verify(vec![
            Value::from(presentation_b64),
            Value::from(trusted_key_hex),
        ])
        .expect("gapped request target should return verified=false");

        assert_eq!(result["verified"], Value::from(false));
        assert_eq!(result["request_target"], Value::from(""));
    }

    #[test]
    fn tlsn_verify_rejects_gapped_host_disclosure() {
        let response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let gap_index = DEFAULT_REQUEST.find("example.com").unwrap() + 3;
        let sent_idx =
            RangeSetEnvelope::from(vec![0..gap_index, gap_index + 1..DEFAULT_REQUEST.len()]);
        let (presentation, trusted_key) = build_fixture_presentation_with_ranges(
            18,
            DEFAULT_REQUEST,
            response,
            sent_idx,
            RangeSetEnvelope::from(0..response.len()),
        );
        let (presentation_b64, trusted_key_hex) = encode_fixture(&presentation, &trusted_key);

        let result = tlsn_verify(vec![
            Value::from(presentation_b64),
            Value::from(trusted_key_hex),
        ])
        .expect("gapped Host header should return verified=false");

        assert_eq!(result["verified"], Value::from(false));
        assert_eq!(result["server_name"], Value::from(""));
    }

    #[test]
    fn tlsn_verify_rejects_gapped_response_body_disclosure() {
        let response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let body_start = response.find("\r\n\r\n").unwrap() + 4;
        let gap_index = body_start + 1;
        let recv_idx = RangeSetEnvelope::from(vec![0..gap_index, gap_index + 1..response.len()]);
        let (presentation, trusted_key) = build_fixture_presentation_with_ranges(
            19,
            DEFAULT_REQUEST,
            response,
            RangeSetEnvelope::from(0..DEFAULT_REQUEST.len()),
            recv_idx,
        );
        let (presentation_b64, trusted_key_hex) = encode_fixture(&presentation, &trusted_key);

        let result = tlsn_verify(vec![
            Value::from(presentation_b64),
            Value::from(trusted_key_hex),
        ])
        .expect("gapped response body should return verified=false");

        assert_eq!(result["verified"], Value::from(false));
        assert_eq!(result["response_body"], Value::from(""));
    }

    #[test]
    fn tlsn_extension_registers_and_executes_in_engine() {
        let response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let (presentation, trusted_key) = build_fixture_presentation(13, response);
        let (presentation_b64, trusted_key_hex) = encode_fixture(&presentation, &trusted_key);
        let mut engine = Engine::new();
        engine.with_newton_tlsn_extensions().unwrap();
        engine.set_input(
            Value::from_json_str(&format!(
                r#"{{"presentation":"{}","notary_key":"{}"}}"#,
                presentation_b64, trusted_key_hex
            ))
            .unwrap(),
        );
        let policy = r#"
            package test

            result := newton.crypto.tlsn_verify(input.presentation, input.notary_key)
        "#;
        engine
            .add_policy("test.rego".to_string(), policy.to_string())
            .unwrap();
        let results = engine
            .eval_query("data.test.result.response_body".to_string(), false)
            .unwrap();
        assert_eq!(results.result[0].expressions[0].value, Value::from("hello"));
    }

    #[test]
    fn extract_response_body_decodes_chunked_payloads() {
        let response = concat!(
            "HTTP/1.1 200 OK\r\n",
            "Transfer-Encoding: chunked\r\n",
            "\r\n",
            "4\r\nWiki\r\n",
            "5\r\npedia\r\n",
            "0\r\n\r\n"
        );

        let body = extract_response_body(
            response.as_bytes(),
            &RangeSetEnvelope::from(0..response.len()),
        )
        .expect("response body should decode");
        assert_eq!(body, "Wikipedia");
    }

    #[test]
    fn decode_hex_rejects_odd_lengths() {
        assert!(decode_hex("abc").is_err());
    }

    #[test]
    fn tlsn_golden_fixture_placeholder_documents_expected_format() {
        // TODO: Replace this placeholder with a real TLSNotary prover
        // presentation fixture. The golden input should stay as base64-wrapped
        // bincode bytes for `PresentationEnvelope`.
        const PLACEHOLDER_PRESENTATION_B64: &str = "AA==";

        let bytes = decode_base64(PLACEHOLDER_PRESENTATION_B64)
            .expect("placeholder fixture should stay valid base64");
        let err = decode_presentation(&bytes)
            .expect_err("placeholder fixture is not yet a real TLSNotary presentation");

        assert!(err
            .to_string()
            .contains("invalid TLSNotary presentation encoding"));
    }
}
