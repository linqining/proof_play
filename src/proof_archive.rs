//! Durable wire format for one verified Texas method proof.
//!
//! The archive stores only the Stwo proof and its structural metadata.  The
//! corresponding [`crate::prove_task::ProveTask`] remains the verifier-owned
//! statement: archive verification reconstructs the AIR, trusted trace row and
//! public inputs from that task instead of trusting proof-carried metadata.

use bincode::Options;
use borsh::{BorshDeserialize, BorshSerialize};
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::poseidon252_merkle::Poseidon252MerkleHasher;

use crate::error::{TexasAirError, TexasAirResult};
use crate::method_kind::MethodKind;

/// Current durable method-proof archive schema.
///
/// v5（2026-09-11，展示名出共识）：移除 `name_commitment_v2_bytes` 附件——
/// 展示名非共识，`create_table` 不再证明/随附名字承诺（#22⑤ 消费侧机制
/// 整体下线）。v4 及更早归档 fail-closed 拒绝。
pub const METHOD_PROOF_ARCHIVE_VERSION: u8 = 5;

/// Maximum accepted serialized Stwo proof size.
pub const MAX_ARCHIVED_STARK_PROOF_BYTES: usize = 16 * 1024 * 1024;

/// A restart-safe serialized method proof.
///
/// This value is not sufficient by itself: verification also requires the
/// exact canonical [`crate::prove_task::ProveTask`] that produced it.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedMethodProof {
    version: u8,
    method_kind: MethodKind,
    log_size: u32,
    num_columns: u32,
    stark_proof_bytes: Vec<u8>,
    root_binding_bytes: Vec<u8>,
}

impl ArchivedMethodProof {
    /// Encode a proved Stwo object into the durable archive format.
    pub(crate) fn from_stark(
        method_kind: MethodKind,
        log_size: u32,
        num_columns: usize,
        stark_proof: &StarkProof<Poseidon252MerkleHasher>,
        root_binding: &crate::state_root_binding::ArchivedStateRootBindingProof,
    ) -> TexasAirResult<Self> {
        let num_columns = u32::try_from(num_columns).map_err(|_| {
            TexasAirError::SerializationError("method proof column count exceeds u32".into())
        })?;
        let stark_proof_bytes = bincode_options().serialize(stark_proof).map_err(|error| {
            TexasAirError::SerializationError(format!(
                "Stwo method proof serialization failed: {error}"
            ))
        })?;
        let root_binding_bytes = borsh::to_vec(root_binding).map_err(|error| {
            TexasAirError::SerializationError(format!(
                "state-root binding serialization failed: {error}"
            ))
        })?;
        let archive = Self {
            version: METHOD_PROOF_ARCHIVE_VERSION,
            method_kind,
            log_size,
            num_columns,
            stark_proof_bytes,
            root_binding_bytes,
        };
        archive.validate()?;
        Ok(archive)
    }

    /// Decode a complete Borsh archive with strict trailing-byte rejection.
    pub fn from_bytes(bytes: &[u8]) -> TexasAirResult<Self> {
        if bytes.is_empty() || bytes.len() > MAX_ARCHIVED_STARK_PROOF_BYTES + 64 * 1024 {
            return Err(TexasAirError::SerializationError(
                "invalid archived method proof length".into(),
            ));
        }
        let archive = Self::try_from_slice(bytes).map_err(|error| {
            TexasAirError::SerializationError(format!(
                "archived method proof Borsh decoding failed: {error}"
            ))
        })?;
        archive.validate()?;
        Ok(archive)
    }

    /// Encode this archive as canonical Borsh bytes.
    pub fn to_bytes(&self) -> TexasAirResult<Vec<u8>> {
        self.validate()?;
        borsh::to_vec(self).map_err(|error| {
            TexasAirError::SerializationError(format!(
                "archived method proof Borsh encoding failed: {error}"
            ))
        })
    }

    /// Method selector family committed by this proof.
    #[must_use]
    pub const fn method_kind(&self) -> MethodKind {
        self.method_kind
    }

    /// Trace logarithmic size committed by the original prover.
    #[must_use]
    pub const fn log_size(&self) -> u32 {
        self.log_size
    }

    /// Trace column count committed by the original prover.
    pub fn num_columns(&self) -> TexasAirResult<usize> {
        usize::try_from(self.num_columns).map_err(|_| {
            TexasAirError::SerializationError(
                "archived method proof column count does not fit usize".into(),
            )
        })
    }

    /// Deserialize the proven state-root binding carried alongside the
    /// method proof.
    pub(crate) fn decode_root_binding(
        &self,
    ) -> TexasAirResult<crate::state_root_binding::ArchivedStateRootBindingProof> {
        self.validate()?;
        borsh::from_slice(&self.root_binding_bytes).map_err(|error| {
            TexasAirError::SerializationError(format!(
                "archived state-root binding decoding failed: {error}"
            ))
        })
    }

    /// Deserialize the bounded Stwo proof for native verification.
    pub(crate) fn decode_stark(&self) -> TexasAirResult<StarkProof<Poseidon252MerkleHasher>> {
        self.validate()?;
        bincode_options()
            .reject_trailing_bytes()
            .deserialize(&self.stark_proof_bytes)
            .map_err(|error| {
                TexasAirError::SerializationError(format!(
                    "archived Stwo method proof decoding failed: {error}"
                ))
            })
    }

    /// Validate the archive envelope and bounded proof payload without decoding Stwo internals.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported version, invalid trace shape, or
    /// empty/oversized proof payload.
    pub fn validate(&self) -> TexasAirResult<()> {
        if self.version != METHOD_PROOF_ARCHIVE_VERSION {
            return Err(TexasAirError::SerializationError(format!(
                "unsupported method proof archive version {}",
                self.version
            )));
        }
        if self.log_size == 0 || self.log_size >= usize::BITS {
            return Err(TexasAirError::SerializationError(format!(
                "invalid archived method proof log_size {}",
                self.log_size
            )));
        }
        if self.num_columns == 0 {
            return Err(TexasAirError::SerializationError(
                "archived method proof has zero columns".into(),
            ));
        }
        if self.stark_proof_bytes.is_empty()
            || self.stark_proof_bytes.len() > MAX_ARCHIVED_STARK_PROOF_BYTES
        {
            return Err(TexasAirError::SerializationError(
                "invalid archived Stwo method proof length".into(),
            ));
        }
        Ok(())
    }
}

fn bincode_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_ARCHIVED_STARK_PROOF_BYTES as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_archive(proof_bytes: Vec<u8>) -> ArchivedMethodProof {
        ArchivedMethodProof {
            version: METHOD_PROOF_ARCHIVE_VERSION,
            method_kind: MethodKind::CreateTable,
            log_size: 10,
            num_columns: 1,
            stark_proof_bytes: proof_bytes,
            root_binding_bytes: Vec::new(),
        }
    }

    #[test]
    fn borsh_archive_rejects_trailing_bytes() {
        let archive = synthetic_archive(vec![1, 2, 3]);
        let mut bytes = archive.to_bytes().unwrap();
        bytes.push(0);
        assert!(ArchivedMethodProof::from_bytes(&bytes).is_err());
    }

    #[test]
    fn archive_rejects_empty_and_oversized_proof_payloads() {
        assert!(synthetic_archive(Vec::new()).to_bytes().is_err());
        assert!(
            synthetic_archive(vec![0; MAX_ARCHIVED_STARK_PROOF_BYTES + 1])
                .to_bytes()
                .is_err()
        );
    }

    #[test]
    fn archive_rejects_unsupported_version_and_invalid_shape() {
        let mut archive = synthetic_archive(vec![1]);
        archive.version = METHOD_PROOF_ARCHIVE_VERSION + 1;
        assert!(archive.to_bytes().is_err());

        let mut archive = synthetic_archive(vec![1]);
        archive.log_size = 0;
        assert!(archive.to_bytes().is_err());

        let mut archive = synthetic_archive(vec![1]);
        archive.num_columns = 0;
        assert!(archive.to_bytes().is_err());
    }
}
